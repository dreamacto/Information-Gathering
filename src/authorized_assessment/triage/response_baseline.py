"""response_baseline.py —— 固定路径响应基线比较与降噪（实施规格 4.1）。

固定路径（config/git/openapi/actuator/druid 等字典路径）命中 200 时不得直接作为候选：
必须先与目标基线、登录页、统一错误页、CDN/WAF 页比较，默认输出（规格 1082-1091 行）：

    signal_type=fixed_path / confidence=low / promotion_status=not_promoted /
    baseline_similarity / body_semantic_match / known_false_positive_pattern

只有规格 1093-1100 行的六条升级证据全部满足才升为 candidate：

  1. stable_baseline_difference    与基线有稳定差异（相似度 <= STABLE_DIFF_MAX 且内容非同哈希）；
  2. content_type_matches_resource Content-Type 与资源类型一致（配置/JSON 类路径返回 HTML 视为不一致）；
  3. mutually_supporting_signals   标题、响应头（Content-Type）、body 关键词、路径家族相互支持（>=2 路）；
  4. not_known_false_positive_page 不是登录页、统一错误页、WAF 页或 CDN 页；
  5. low_budget_reproducible       可低预算复现（调用方显式声明，模块无法自证，fail-closed 默认 False）；
  6. explicit_impact_hypothesis    有明确影响假设（调用方显式提供）。

纯离线模块：所有函数只消费已抓取的响应记录（dict），零网络、零文件系统写入
（load_baseline_profiles 只读文件）。相似度为行集 Jaccard + 标题/状态归一化的确定性实现，
不引入外部依赖；无基线时 fail-closed（baseline_available=False，一律 not_promoted）。
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable, Mapping

SIGNAL_TYPE = "fixed_path"

CONFIDENCE_LEVELS = ("low", "medium")
PROMOTION_STATUSES = ("not_promoted", "promoted_candidate")

BASELINE_KINDS = (
    "target_baseline",
    "login_page",
    "generic_error_page",
    "cdn_waf_page",
)

KNOWN_FALSE_POSITIVE_PATTERNS = (
    "generic_200_error_page",
    "login_page",
    "waf_block_page",
    "cdn_challenge_page",
    "empty_success_page",
)

PROMOTION_CRITERIA = (
    "stable_baseline_difference",
    "content_type_matches_resource",
    "mutually_supporting_signals",
    "not_known_false_positive_page",
    "low_budget_reproducible",
    "explicit_impact_hypothesis",
)

# 与基线相似度 <= 该值视为"稳定差异"（规格未给数值，实现侧保守取值并固化为常量）。
STABLE_DIFF_MAX = 0.80

MAX_PROFILE_LINES = 200

_WAF_MARKERS = re.compile(
    r"(request blocked|access denied|防火墙|安全狗|safedog|imperva|radware|waf\b|拦截)",
    re.I,
)
_CDN_CHALLENGE_MARKERS = re.compile(
    r"(just a moment|cf-chl|checking your browser|ddos-guard|captcha|验证码|浏览器安全检查)",
    re.I,
)
_LOGIN_TITLE_MARKERS = re.compile(r"(login|sign in|登录)", re.I)
_LOGIN_BODY_MARKERS = re.compile(
    r"(password|密码|username|用户名|<form[^>]*action)",
    re.I,
)
_GENERIC_ERROR_MARKERS = re.compile(
    r"(404|not found|page not found|error|找不到|不存在|exception|aspxerrorpath)",
    re.I,
)

_HTML_CONTENT_TYPE = re.compile(r"text/html", re.I)

_FAMILY_MARKERS = {
    "env": re.compile(r"(?i)^\s*[A-Z_][A-Z0-9_]*\s*="),
    "git": re.compile(r"(?m)^(ref:|\[remote|\[core)|(tree |parent )"),
    "openapi": re.compile(r"(?i)(swagger|openapi|\"paths\"|api-docs)"),
    "actuator": re.compile(r"(?i)(propertySources|activeProfiles|_links|measurements|systemProperties)"),
    "druid": re.compile(r"(?i)(druid monitor|druid stat|sql stat|web session stat)"),
    "config": re.compile(
        r"(?i)(<configuration|<\?xml|appsettings|spring\.datasource|jdbc:|datasource"
        r"|server:|DB_HOST|APP_KEY|<beans|connectionstring)",
    ),
}

_FAMILY_BY_PATH = (
    ("env", ("/.env",)),
    ("git", ("/.git",)),
    ("openapi", ("api-docs", "swagger", "openapi")),
    ("actuator", ("/actuator",)),
    ("druid", ("/druid",)),
    ("config", ("web.config", "appsettings", "config.php", "config.inc.php", "database.php",
                "application.properties", "application.yml", "bootstrap.yml", "bootstrap.properties",
                "jdbc", "db.properties", "web.xml")),
)

_FORBIDDEN_KEY_FRAGMENTS = (
    "cookie",
    "token",
    "password",
    "passwd",
    "secret",
    "authorization",
    "session_id",
    "credential",
)


def summarize_body(text: str, max_lines: int = MAX_PROFILE_LINES) -> list[str]:
    """规范化 body 行集：小写、去首尾空白、去空行、去重、截断；确定性。"""
    lines: list[str] = []
    seen: set[str] = set()
    for raw_line in (text or "").splitlines():
        line = raw_line.strip().lower()
        if not line or line in seen:
            continue
        seen.add(line)
        lines.append(line)
        if len(lines) >= max_lines:
            break
    return lines


def origin_of(url: str) -> str:
    """origin = scheme://host[:non-default-port]；无 scheme 时按 host 处理。"""
    text = (url or "").strip()
    if "://" not in text:
        return text.rstrip("/").lower()
    scheme, rest = text.split("://", 1)
    authority = rest.split("/", 1)[0].rstrip("/")
    return f"{scheme.lower()}://{authority.lower()}"


def detect_path_family(url_or_path: str, *, family_hint: str = "") -> str:
    """路径家族识别（env/git/openapi/actuator/druid/config/other）；family_hint 可显式指定。"""
    if family_hint in _FAMILY_MARKERS:
        return family_hint
    path = (url_or_path or "").lower()
    for family, needles in _FAMILY_BY_PATH:
        if any(needle in path for needle in needles):
            return family
    return "other"


def detect_known_false_positive_pattern(
    record: Mapping[str, Any], body_lines: Iterable[str] | None = None
) -> str | None:
    """已知误报模式识别（规格 4.1：登录页/统一错误页/WAF/CDN 页；规格 13.2 负例来源）。

    优先序：WAF（状态码或标记）> CDN 挑战 > 登录页 > 通用 200 错误页 > 空 200 页。
    """
    status = record.get("status")
    text = record.get("text") or ""
    title = str(record.get("title") or "")
    lines = list(body_lines) if body_lines is not None else summarize_body(text)
    joined = "\n".join(lines[:200])

    if status in (403, 426, 429) or _WAF_MARKERS.search(joined) or _WAF_MARKERS.search(title):
        return "waf_block_page"
    if _CDN_CHALLENGE_MARKERS.search(joined) or _CDN_CHALLENGE_MARKERS.search(title):
        return "cdn_challenge_page"
    if _LOGIN_TITLE_MARKERS.search(title) or ("<form" in joined and _LOGIN_BODY_MARKERS.search(joined)):
        return "login_page"
    if status == 200 and _GENERIC_ERROR_MARKERS.search(joined[:4096]):
        return "generic_200_error_page"
    if status == 200 and not lines:
        return "empty_success_page"
    return None


def body_semantic_match_for_family(family: str, text: str, body_lines: Iterable[str] | None = None) -> bool:
    """body 是否携带与路径家族一致的语义标记（规格 body_semantic_match 字段）。

    other 家族保守返回 False（无标记可依 → 不支持升级）。
    """
    marker = _FAMILY_MARKERS.get(family)
    if marker is None:
        return False
    if body_lines is not None:
        lines = list(body_lines)
        sample = "\n".join(lines[:200])
        if family == "env":
            return any(marker.search(line) for line in lines[:200])
        return bool(marker.search(sample))
    return bool(marker.search(text or ""))


def build_baseline_profile(
    record: Mapping[str, Any], *, kind: str, body_lines: Iterable[str] | None = None
) -> dict[str, Any]:
    """从已抓取响应记录构建基线画像；kind ∈ BASELINE_KINDS。"""
    if kind not in BASELINE_KINDS:
        raise ValueError(f"unknown baseline kind: {kind!r}")
    text = record.get("text") or ""
    lines = list(body_lines) if body_lines is not None else summarize_body(text)
    url = str(record.get("final_url") or record.get("url") or "")
    return {
        "baseline_kind": kind,
        "origin": str(record.get("origin") or origin_of(url)),
        "status": record.get("status"),
        "content_type": str(record.get("content_type") or ""),
        "title": str(record.get("title") or ""),
        "sample_sha256": str(record.get("sample_sha256") or ""),
        "body_lines": lines,
    }


def response_similarity(profile_a: Mapping[str, Any], profile_b: Mapping[str, Any]) -> float:
    """行集 Jaccard 相似度 [0,1]；两侧均无 body 行时退化为标题/状态/Content-Type 一致性。"""
    lines_a = set(profile_a.get("body_lines") or [])
    lines_b = set(profile_b.get("body_lines") or [])
    if lines_a or lines_b:
        union = lines_a | lines_b
        intersection = lines_a & lines_b
        return round(len(intersection) / len(union), 4) if union else 0.0
    same_meta = (
        str(profile_a.get("title") or "").lower() == str(profile_b.get("title") or "").lower()
        and profile_a.get("status") == profile_b.get("status")
        and str(profile_a.get("content_type") or "").lower()
        == str(profile_b.get("content_type") or "").lower()
    )
    return 1.0 if same_meta else 0.0


def load_baseline_profiles(path: str | Path) -> list[dict[str, Any]]:
    """读取基线记录 JSONL（--baseline-file 离线入口）；kind 非法行直接拒绝。"""
    profiles: list[dict[str, Any]] = []
    file_path = Path(path)
    for line in file_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if not isinstance(row, dict):
            raise ValueError("baseline record must be a JSON object")
        kind = row.get("baseline_kind")
        if kind not in BASELINE_KINDS:
            raise ValueError(f"unknown baseline kind: {kind!r}")
        profiles.append(dict(row))
    return profiles


def compare_fixed_path(
    record: Mapping[str, Any],
    baselines: Iterable[Mapping[str, Any]],
    *,
    body_lines: Iterable[str] | None = None,
) -> dict[str, Any]:
    """固定路径响应 vs 基线集比较；返回规格 1082-1091 行默认输出字段全集。

    无基线时 fail-closed：baseline_similarity=0.0、baseline_available=False，
    升级判定必然不通过（见 evaluate_promotion）。
    """
    text = record.get("text") or ""
    lines = list(body_lines) if body_lines is not None else summarize_body(text)
    baseline_list = [dict(b) for b in baselines]

    similarities = [response_similarity(
        {"body_lines": lines, "title": record.get("title") or "", "status": record.get("status"),
         "content_type": record.get("content_type") or ""},
        baseline,
    ) for baseline in baseline_list]
    max_similarity = round(max(similarities), 4) if similarities else 0.0

    return {
        "signal_type": SIGNAL_TYPE,
        "confidence": "low",
        "promotion_status": "not_promoted",
        "baseline_similarity": max_similarity,
        "body_semantic_match": body_semantic_match_for_family(
            detect_path_family(
                str(record.get("path") or record.get("url") or record.get("final_url") or ""),
                family_hint=str(record.get("family") or ""),
            ),
            text,
            lines,
        ),
        "known_false_positive_pattern": detect_known_false_positive_pattern(record, lines),
        "baseline_available": bool(baseline_list),
        "compared_against": [str(b.get("baseline_kind")) for b in baseline_list],
    }


def evaluate_promotion(
    record: Mapping[str, Any],
    comparison: Mapping[str, Any],
    *,
    reproducible: bool = False,
    impact_hypothesis: str = "",
) -> dict[str, Any]:
    """规格 1093-1100 行六条升级证据逐条判定；六条全过才 promoted，任缺一即 blocker。"""
    text = record.get("text") or ""
    lines = list(comparison.get("body_lines") or summarize_body(text))
    sha = str(record.get("sample_sha256") or "")

    family = detect_path_family(
        str(record.get("path") or record.get("url") or record.get("final_url") or ""),
        family_hint=str(record.get("family") or ""),
    )
    content_type = str(record.get("content_type") or "")
    path_lower = str(record.get("path") or record.get("url") or record.get("final_url") or "").lower()

    if not comparison.get("baseline_available"):
        criterion_1 = (False, "no_baseline_records")
    else:
        sha_matches_baseline = any(
            sha and str(b.get("sample_sha256") or "") == sha
            for b in (comparison.get("baselines") or [])
        )
        if sha_matches_baseline:
            criterion_1 = (False, "content_identical_to_baseline")
        elif float(comparison.get("baseline_similarity") or 0.0) <= STABLE_DIFF_MAX:
            criterion_1 = (True, "stable_difference_from_baseline")
        else:
            criterion_1 = (False, f"similarity_above_{STABLE_DIFF_MAX:.2f}")

    html_claimed = bool(_HTML_CONTENT_TYPE.search(content_type))
    html_path = path_lower.endswith(".html") or path_lower.endswith(".htm")
    if not content_type:
        criterion_2 = (False, "content_type_missing")
    elif html_claimed and not html_path:
        criterion_2 = (False, "html_response_for_non_html_path")
    else:
        criterion_2 = (True, "content_type_consistent_with_path")

    signals: list[str] = []
    if comparison.get("body_semantic_match"):
        signals.append("body_semantic_match")
    title = str(record.get("title") or "")
    title_marker = _FAMILY_MARKERS.get(family)
    if title and family != "other" and (
        family in title.lower() or (title_marker and title_marker.search(title))
    ):
        signals.append("title_family_match")
    if content_type and not html_claimed and family != "other":
        signals.append("content_type_family_match")
    if family != "other":
        signals.append("specific_path_family")
    if len(signals) >= 2:
        criterion_3 = (True, "signals:" + "+".join(sorted(signals)))
    else:
        criterion_3 = (False, "insufficient_supporting_signals")

    if comparison.get("known_false_positive_pattern"):
        criterion_4 = (False, f"known_false_positive:{comparison['known_false_positive_pattern']}")
    else:
        criterion_4 = (True, "no_known_false_positive_pattern")

    criterion_5 = (bool(reproducible), "declared_reproducible" if reproducible else "not_declared_reproducible")
    criterion_6 = (
        bool(str(impact_hypothesis).strip()),
        "impact_hypothesis_present" if str(impact_hypothesis).strip() else "impact_hypothesis_missing",
    )

    results = [
        ("stable_baseline_difference", criterion_1),
        ("content_type_matches_resource", criterion_2),
        ("mutually_supporting_signals", criterion_3),
        ("not_known_false_positive_page", criterion_4),
        ("low_budget_reproducible", criterion_5),
        ("explicit_impact_hypothesis", criterion_6),
    ]
    criteria = [
        {"criterion": name, "satisfied": bool(ok), "reason": reason}
        for name, (ok, reason) in results
    ]
    blockers = [item["criterion"] for item in criteria if not item["satisfied"]]
    promoted = not blockers
    return {
        "promoted": promoted,
        "criteria": criteria,
        "remaining_blockers": blockers,
    }


def classify_fixed_path(
    record: Mapping[str, Any],
    baselines: Iterable[Mapping[str, Any]],
    *,
    body_lines: Iterable[str] | None = None,
    reproducible: bool = False,
    impact_hypothesis: str = "",
) -> dict[str, Any]:
    """固定路径判定总入口：规格默认输出 + 升级判定明细（fixed_path_assessment 全量结构）。"""
    text = record.get("text") or ""
    lines = list(body_lines) if body_lines is not None else summarize_body(text)
    baseline_list = [dict(b) for b in baselines]

    comparison = compare_fixed_path(record, baseline_list, body_lines=lines)
    comparison["body_lines"] = lines
    comparison["baselines"] = baseline_list
    promotion = evaluate_promotion(
        record, comparison, reproducible=reproducible, impact_hypothesis=impact_hypothesis
    )

    assessment = {key: comparison[key] for key in (
        "signal_type",
        "confidence",
        "promotion_status",
        "baseline_similarity",
        "body_semantic_match",
        "known_false_positive_pattern",
        "baseline_available",
        "compared_against",
    )}
    assessment["path_family"] = detect_path_family(
        str(record.get("path") or record.get("url") or record.get("final_url") or ""),
        family_hint=str(record.get("family") or ""),
    )
    if promotion["promoted"]:
        assessment["promotion_status"] = "promoted_candidate"
        assessment["confidence"] = "medium"
    assessment["promotion"] = promotion
    return assessment


def assess_response_record(
    record: Mapping[str, Any],
    baselines: Iterable[Mapping[str, Any]],
    *,
    body_lines: Iterable[str] | None = None,
) -> dict[str, Any]:
    """CLI 集成入口：默认不声明可复现与影响假设（人工环节未发生 → fail-closed not_promoted）。"""
    return classify_fixed_path(record, baselines, body_lines=body_lines)


def _credential_scan(node: Any, prefix: str) -> list[str]:
    errors: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            key_text = str(key).lower()
            path = f"{prefix}.{key}" if prefix else str(key)
            if any(fragment in key_text for fragment in _FORBIDDEN_KEY_FRAGMENTS):
                errors.append(f"credential-like key is forbidden in fixed path assessment: {path}")
            errors.extend(_credential_scan(value, path))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            errors.extend(_credential_scan(value, f"{prefix}[{index}]"))
    return errors


def _is_plain_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


REQUIRED_ASSESSMENT_FIELDS = (
    "signal_type",
    "confidence",
    "promotion_status",
    "baseline_similarity",
    "body_semantic_match",
    "known_false_positive_pattern",
    "baseline_available",
    "path_family",
    "compared_against",
    "promotion",
)


def validate_fixed_path_result(result: Any) -> list[str]:
    """依赖-free 契约校验；返回错误列表（空 = 通过）。

    拒绝：缺必需字段、confidence/promotion_status 不在枚举、相似度越界 [0,1]、
    已知误报模式不在枚举、promotion 明细与顶层状态不一致、凭证类键。
    """
    errors: list[str] = []
    if not isinstance(result, dict):
        return ["fixed path assessment must be a dict"]

    for field in REQUIRED_ASSESSMENT_FIELDS:
        if field not in result:
            errors.append(f"missing required field: {field}")
    if errors:
        return errors

    if result["signal_type"] != SIGNAL_TYPE:
        errors.append(f"signal_type must be {SIGNAL_TYPE!r}")
    if result["confidence"] not in CONFIDENCE_LEVELS:
        errors.append(f"confidence not in enum: {result['confidence']!r}")
    if result["promotion_status"] not in PROMOTION_STATUSES:
        errors.append(f"promotion_status not in enum: {result['promotion_status']!r}")

    similarity = result["baseline_similarity"]
    if not isinstance(similarity, (int, float)) or isinstance(similarity, bool):
        errors.append("baseline_similarity must be a number")
    elif not 0.0 <= float(similarity) <= 1.0:
        errors.append(f"baseline_similarity must be in [0,1], got {similarity}")

    if not isinstance(result["body_semantic_match"], bool):
        errors.append("body_semantic_match must be a boolean")
    if not isinstance(result["baseline_available"], bool):
        errors.append("baseline_available must be a boolean")

    fp = result["known_false_positive_pattern"]
    if fp is not None and fp not in KNOWN_FALSE_POSITIVE_PATTERNS:
        errors.append(f"known_false_positive_pattern not in enum: {fp!r}")

    compared = result["compared_against"]
    if not isinstance(compared, list) or not all(isinstance(item, str) for item in compared):
        errors.append("compared_against must be a list of strings")

    promotion = result["promotion"]
    if not isinstance(promotion, dict):
        errors.append("promotion must be a dict")
    else:
        criteria = promotion.get("criteria")
        if not isinstance(criteria, list) or len(criteria) != len(PROMOTION_CRITERIA):
            errors.append(f"promotion.criteria must contain exactly {len(PROMOTION_CRITERIA)} entries")
        else:
            names = [item.get("criterion") for item in criteria if isinstance(item, dict)]
            if names != list(PROMOTION_CRITERIA):
                errors.append("promotion.criteria names must match PROMOTION_CRITERIA order")
            all_satisfied = all(
                isinstance(item, dict) and item.get("satisfied") is True for item in criteria
            )
            if promotion.get("promoted") is True and not all_satisfied:
                errors.append("promoted=True requires all six promotion criteria satisfied")
            if result["promotion_status"] == "promoted_candidate" and promotion.get("promoted") is not True:
                errors.append("promotion_status=promoted_candidate requires promotion.promoted=True")
            if result["promotion_status"] == "not_promoted" and promotion.get("promoted") is True:
                errors.append("promotion_status=not_promoted contradicts promotion.promoted=True")
            blockers = promotion.get("remaining_blockers")
            if not isinstance(blockers, list):
                errors.append("promotion.remaining_blockers must be a list")

    errors.extend(_credential_scan(result, ""))
    return errors
