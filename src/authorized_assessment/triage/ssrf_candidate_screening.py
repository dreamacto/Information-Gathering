"""SSRF 候选筛选（实施规格 5.4：ssrf_candidate_screening 子阶段）。

只读离线：默认只分析 URL/callback/webhook/image/import/remote file 类参数、协议与
重定向限制、已有响应证据、内部地址/云元数据可能性与 OOB token 队列；不默认自动对
POST 写入探测值，不使用公共 OAST，不访问内网或云元数据。OOB、内部地址和任何写入
验证均为审批门（由现有 approval_gated_phases 控制，本模块只校验 manifest 的
approval_ref 完整性，不造第二套审批规则）。

与根目录 ssrf_triage.py（主动探测脚本，OOB/时间盲）的关系：本模块是筛选层，复用
同一词表 wordlists/ssrf_params.txt（单一事实源），不重复实现探测器。候选分级与升级
规则判定复用 injection_candidates.rule_satisfied（单一引擎，batch6_2）。
"""
from __future__ import annotations

from pathlib import Path

from authorized_assessment.triage import injection_candidates as ic

SSRF_CATEGORY = "ssrf"

# 词表缺失时的内置回退（fail-soft：词表是筛选入口不是安全边界；禁止联网下载）。
# 内容与 wordlists/ssrf_params.txt 保持一致（batch6_2 对齐，避免双表漂移）。
DEFAULT_SSRF_PARAMS: tuple[str, ...] = (
    "url",
    "src",
    "source",
    "redirect",
    "link",
    "avatar",
    "cover",
    "webhook",
    "callback",
    "next",
    "return",
    "dest",
    "destination",
    "target",
    "file",
    "load",
    "page",
    "fetch",
    "proxy",
    "img",
    "image",
    "domain",
    "host",
    "site",
    "path",
    "reference",
    "ref",
    "continue",
    "goto",
    "gotourl",
    "jump",
    "url_path",
    "weburl",
    "back",
    "out",
    "api",
    "feed",
    "share",
    "open",
    "window",
    "data",
    "remote",
    "connect",
    "callback_url",
    "return_url",
    "redirect_url",
    "next_url",
    "jump_url",
)


def load_param_wordlist(path: str | Path | None = None) -> tuple[str, ...]:
    """加载 SSRF 参数词表：默认与根目录 ssrf_triage.py 同源 wordlists/ssrf_params.txt。

    缺失/不可读时回退 DEFAULT_SSRF_PARAMS，不抛异常、不下载。
    """
    if path is None:
        # src/authorized_assessment/triage/ → 项目根为 parents[3]
        root = Path(__file__).resolve().parents[3]
        path = root / "wordlists" / "ssrf_params.txt"
    try:
        words = tuple(
            w
            for w in Path(path).read_text(encoding="utf-8", errors="replace").split()
            if w.strip()
        )
    except OSError:
        return DEFAULT_SSRF_PARAMS
    return words or DEFAULT_SSRF_PARAMS


SSRF_EVIDENCE_KINDS: tuple[str, ...] = (
    "oob_callback_hit",
    "timing_differential",
    "response_content_injection",
    "server_fetch_evidence",
    "redirect_followed",
    "error_leaks_internal",
    "protocol_blocked",
    "param_name_match",
    "post_form_static_only",
)

# 这些形态"不算漏洞"：仅参数名命中、POST 表单只做静态候选（规格 5.4 + 13.2）。
SSRF_INSUFFICIENT_KINDS: tuple[str, ...] = ("param_name_match", "post_form_static_only")

# 升级规则：OOB 回调命中；或 时间差分+服务端发起证据；或 响应内容注入+服务端发起证据。
SSRF_UPGRADE_RULE: dict[str, tuple[tuple[str, ...], ...]] = {
    "required_any_branches": (
        ("oob_callback_hit",),
        ("timing_differential", "server_fetch_evidence"),
        ("response_content_injection", "server_fetch_evidence"),
    ),
}

# v1 观察键 → 证据形态（复核会话从 run 产物/代理记录提炼，模块不做启发式推断）。
SSRF_OBSERVATION_EVIDENCE_MAP: dict[str, str] = {
    "oob_callback_hit_confirmed": "oob_callback_hit",
    "timing_differential_observed": "timing_differential",
    "response_content_injection_observed": "response_content_injection",
    "server_fetch_evidence_observed": "server_fetch_evidence",
    "redirect_followed_observed": "redirect_followed",
    "error_leaks_internal_observed": "error_leaks_internal",
    "protocol_blocked_observed": "protocol_blocked",
    "param_name_matched": "param_name_match",
    "post_form_static_only": "post_form_static_only",
}

SSRF_TOKEN_STATUSES: tuple[str, ...] = ("issued", "hit", "expired", "revoked")

# 公共 OAST 域（规格红线：不使用公共 OAST；回调只允许自有监听器/登记的自有 VPS）。
PUBLIC_OAST_HOSTS: tuple[str, ...] = (
    "burpcollaborator.net",
    "oast.pro",
    "oast.fun",
    "oast.live",
    "oast.site",
    "oast.online",
    "oast.me",
    "interaction.sh",
    "canarytokens.org",
    "webhook.site",
    "requestbin.com",
    "requestbin.net",
    "pipedream.net",
)


def derive_ssrf_evidence_kinds(evidence: dict) -> list[str]:
    """观察键 → SSRF 证据形态（按 SSRF_EVIDENCE_KINDS 顺序，确定性）。"""
    return [kind for key, kind in SSRF_OBSERVATION_EVIDENCE_MAP.items() if evidence.get(key)]


def grade_ssrf_observation(evidence_kinds: list[str], status_hint: str | None = None) -> str:
    """SSRF 候选分级：升级规则满足 → candidate；否则 signal。status_hint 尊重人工判定。"""
    if status_hint in ic.CANDIDATE_STATUS_VALUES:
        return status_hint
    satisfied, _ = ic.rule_satisfied(
        SSRF_UPGRADE_RULE, evidence_kinds, SSRF_EVIDENCE_KINDS, SSRF_INSUFFICIENT_KINDS
    )
    return "candidate" if satisfied else "signal"


def screen_ssrf_observations(
    observations: list[dict],
    label: str = "ssrf_screening",
    wordlist_path: str | Path | None = None,
) -> tuple[list[dict], dict, list[str]]:
    """SSRF 候选筛选 → (候选行, ssrf 单类别汇总行, 违例)。

    默认只分析 URL/callback/webhook/image/import/remote file 类参数（词表命中）；
    参数不在分析面且没有任何非"不算漏洞"证据的观察不产候选（不是 SSRF 分析对象）。
    POST 表单参数只做静态候选（post_form_static_only 永不升级，不自动发探测值）。
    """
    wordlist = {p.lower() for p in load_param_wordlist(wordlist_path)}
    rows: list[dict] = []
    violations: list[str] = []
    na_count = 0
    na_reasons: list[str] = []
    applicable_count = 0
    unknown_count = 0
    for index, observation in enumerate(observations, start=1):
        if not isinstance(observation, dict):
            violations.append(f"{label}: 第 {index} 条观察必须是键值映射")
            continue
        obs_version = observation.get("observation_schema_version")
        if obs_version is not None and str(obs_version) != ic.OBSERVATION_SCHEMA_VERSION:
            violations.append(
                f"{label}: 第 {index} 条观察 observation_schema_version={obs_version!r} "
                f"与当前版本 {ic.OBSERVATION_SCHEMA_VERSION!r} 不符"
            )
        applicability = str(observation.get("applicability") or "unknown")
        if applicability not in ic.APPLICABLE_VALUES:
            violations.append(
                f"{label}: 第 {index} 条观察 applicability 非法 {applicability!r}"
                f"（允许值 {list(ic.APPLICABLE_VALUES)}）"
            )
            continue
        reason = str(observation.get("reason") or "").strip()
        if applicability == "not_applicable":
            na_count += 1
            if reason:
                na_reasons.append(reason)
            continue
        if applicability == "applicable":
            applicable_count += 1
        else:
            unknown_count += 1
        kinds = derive_ssrf_evidence_kinds(observation.get("evidence") or {})
        param = str(observation.get("parameter_name") or "").strip()
        if param.lower() in wordlist and "param_name_match" not in kinds:
            kinds.append("param_name_match")
        strong = [k for k in kinds if k not in SSRF_INSUFFICIENT_KINDS]
        if param.lower() not in wordlist and not strong:
            # 不在 SSRF 分析面且无更强证据：不属于默认分析对象，不产候选。
            continue
        method = str(observation.get("http_method") or "").strip().upper()
        if method == "POST" and "post_form_static_only" not in kinds:
            kinds.append("post_form_static_only")
        status = grade_ssrf_observation(kinds, str(observation.get("status_hint") or "") or None)
        source = str(observation.get("source") or "").strip()
        if not source:
            endpoint = str(observation.get("endpoint") or "").strip()
            source = f"{endpoint} {method} {param}".strip()
        if not source:
            violations.append(
                f"{label}: 第 {index} 条观察缺少来源（source 或 endpoint/parameter_name 均为空，"
                "契约 observation_schema.source_required）"
            )
        row = {
            "candidate_id": f"ssrf-{index:04d}",
            "status": status,
            "evidence_kinds": kinds,
            "parameter_name": param,
            "source": source,
            "evidence_ref": str(observation.get("evidence_ref") or ""),
            "precondition": str(observation.get("precondition") or ""),
            "reason": reason,
        }
        rows.append(row)
        violations += validate_ssrf_candidate(row, label=f"{label}[{row['candidate_id']}]")

    status_counts = {s: 0 for s in ic.CANDIDATE_STATUS_VALUES}
    for r in rows:
        status_counts[r["status"]] += 1
    tested_count = sum(status_counts[s] for s in ic.DEFINITIVE_RESULT_STATUSES)
    category_status = ic.aggregate_category_status(
        [r["status"] for r in rows], na_count > 0
    )
    reasons = [str(r.get("reason") or "") for r in rows if r.get("reason")] + na_reasons
    summary = {
        "category": SSRF_CATEGORY,
        "category_status": category_status,
        "applicability_counts": {
            "applicable": applicable_count,
            "not_applicable": na_count,
            "unknown": unknown_count,
        },
        "status_counts": status_counts,
        "tested_count": tested_count,
        "reason": reasons[0] if reasons else "本次筛选无 SSRF 升级观察",
        "source": next((str(r["source"]) for r in rows if r.get("source")), ""),
        "precondition": next((str(r["precondition"]) for r in rows if r.get("precondition")), ""),
    }
    violations += ic.validate_category_summary(summary, label=f"{label}.summary", categories=(SSRF_CATEGORY,))
    return rows, summary, violations


def validate_ssrf_candidate(candidate: dict, label: str = "ssrf_candidate") -> list[str]:
    """SSRF 候选行校验：8 状态 + 证据形态 + 升级规则（复用 injection_candidates 引擎）。"""
    violations: list[str] = []
    if not isinstance(candidate, dict):
        return [f"{label}: 候选必须是键值映射"]
    for field in ("candidate_id", "status", "evidence_kinds", "source"):
        if field not in candidate:
            violations.append(f"{label}: 缺少必需字段 {field}")
    status = str(candidate.get("status") or "")
    if status and status not in ic.CANDIDATE_STATUS_VALUES:
        violations.append(f"{label}.status 非法: {status!r}（允许值 {list(ic.CANDIDATE_STATUS_VALUES)}）")
    kinds = candidate.get("evidence_kinds")
    if kinds is not None:
        if not isinstance(kinds, (list, tuple)):
            violations.append(f"{label}.evidence_kinds 必须为列表")
        else:
            kind_list = [str(k) for k in kinds]
            if not kind_list:
                violations.append(f"{label}.evidence_kinds 不能为空")
            unknown = sorted({k for k in kind_list if k not in SSRF_EVIDENCE_KINDS})
            if unknown:
                violations.append(f"{label}.evidence_kinds 未知形态: {unknown}")
            if status in ("candidate", "confirmed"):
                satisfied, why = ic.rule_satisfied(
                    SSRF_UPGRADE_RULE, kind_list, SSRF_EVIDENCE_KINDS, SSRF_INSUFFICIENT_KINDS
                )
                if not satisfied:
                    violations.append(f"{label}: status={status} 但升级证据不满足——{why}")
    if status in ("candidate", "confirmed", "needs_manual_validation") and not str(
        candidate.get("evidence_ref") or ""
    ).strip():
        violations.append(f"{label}: status={status} 但 evidence_ref 为空（候选必须可证明）")
    return violations


def build_oob_token_entry(
    token: str,
    callback_host: str,
    issued_at: str,
    approval_ref: str = "",
    target: str = "",
    status: str = "issued",
) -> tuple[dict, list[str]]:
    """构建 OOB token manifest 条目（数据结构函数；不签发、不探测）。

    违例：公共 OAST 域回调、status=hit 但缺 approval_ref（OOB 验证审批门）。
    """
    violations: list[str] = []
    entry = {
        "token": str(token or "").strip(),
        "callback_host": str(callback_host or "").strip().lower(),
        "issued_at": str(issued_at or "").strip(),
        "status": str(status or "issued").strip(),
        "target": str(target or "").strip(),
        "approval_ref": str(approval_ref or "").strip(),
    }
    if not entry["token"]:
        violations.append("oob_token: token 不能为空")
    if not entry["callback_host"]:
        violations.append("oob_token: callback_host 不能为空")
    elif any(host in entry["callback_host"] for host in PUBLIC_OAST_HOSTS):
        violations.append(
            f"oob_token: 禁止使用公共 OAST 回调 {entry['callback_host']!r}（规格 5.4 红线，只用自有监听器/登记自有 VPS）"
        )
    if entry["status"] not in SSRF_TOKEN_STATUSES:
        violations.append(
            f"oob_token: status 非法 {entry['status']!r}（允许值 {list(SSRF_TOKEN_STATUSES)}）"
        )
    if entry["status"] == "hit" and not entry["approval_ref"]:
        violations.append("oob_token: status=hit 但 approval_ref 为空（OOB 验证是审批门动作，必须可追溯）")
    return entry, violations


def validate_oob_token_manifest(manifest: dict, label: str = "oob_token_manifest") -> list[str]:
    """OOB token manifest 校验：结构 + 每条目红线（公共 OAST / hit 无审批引用 / token 重复）。"""
    violations: list[str] = []
    if not isinstance(manifest, dict):
        return [f"{label}: manifest 必须是键值映射"]
    tokens = manifest.get("tokens")
    if not isinstance(tokens, list):
        return violations + [f"{label}: tokens 必须为列表"]
    seen: set[str] = set()
    for index, entry in enumerate(tokens, start=1):
        entry_violations = build_oob_token_entry(
            token=str((entry or {}).get("token") or ""),
            callback_host=str((entry or {}).get("callback_host") or ""),
            issued_at=str((entry or {}).get("issued_at") or ""),
            approval_ref=str((entry or {}).get("approval_ref") or ""),
            target=str((entry or {}).get("target") or ""),
            status=str((entry or {}).get("status") or "issued"),
        )[1]
        violations += [f"{label}.tokens[{index}]: {v}" for v in entry_violations]
        token = str((entry or {}).get("token") or "")
        if token in seen:
            violations.append(f"{label}.tokens[{index}]: token 重复")
        seen.add(token)
    return violations
