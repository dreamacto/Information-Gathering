"""canonical_keys.py —— 统一去重键与合并键（实施规格 4.2 / 2.7 / 4.3）。

纯离线模块：输入候选/finding dict，输出身份键 dict 与 identity_hash；零网络、零文件系统
（契约读取除外）。contracts/candidate_identity_schema.json 为契约；candidate_dedup.py
（Batch 3 后续子项）为唯一去重消费方。

三套身份键（规格 4.2，字段逐一精确一致）：
  generic: canonical_target/endpoint/http_method/parameter_name/input_location/test_family
  api:     canonical_host/normalized_path/http_method/parameter_names/content_type/source_kind
  miniapp: miniapp_id/backend_host/normalized_path/http_method/parameter_names/package_version

2.7 合并器七键：canonical_target/product_or_component/normalized_endpoint/http_method/
vulnerability_family/root_cause_signature/parameter_scope——sqli 家族强制
parameter_scope=endpoint_all_parameters（同一接口多个参数只计一处）。

跨 run 只保留五字段（规格 4.2）：first_seen/last_seen/seen_count/latest_status/
latest_evidence_ref（CROSS_RUN_RETENTION_FIELDS；合并逻辑属 candidate_dedup）。
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable, Mapping

IDENTITY_SCHEMA_PATH = (
    Path(__file__).resolve().parents[3] / "contracts" / "candidate_identity_schema.json"
)

IDENTITY_KINDS = ("generic", "api", "miniapp")

GENERIC_KEY_FIELDS = (
    "canonical_target",
    "endpoint",
    "http_method",
    "parameter_name",
    "input_location",
    "test_family",
)

API_KEY_FIELDS = (
    "canonical_host",
    "normalized_path",
    "http_method",
    "parameter_names",
    "content_type",
    "source_kind",
)

MINIAPP_KEY_FIELDS = (
    "miniapp_id",
    "backend_host",
    "normalized_path",
    "http_method",
    "parameter_names",
    "package_version",
)

MERGE_KEY_FIELDS = (
    "canonical_target",
    "product_or_component",
    "normalized_endpoint",
    "http_method",
    "vulnerability_family",
    "root_cause_signature",
    "parameter_scope",
)

CROSS_RUN_RETENTION_FIELDS = (
    "first_seen",
    "last_seen",
    "seen_count",
    "latest_status",
    "latest_evidence_ref",
)

HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")

INPUT_LOCATIONS = ("query", "form", "json", "header", "path", "cookie", "body")

SOURCE_KINDS = ("A", "B", "C", "D", "E")

SOURCE_KIND_ELIGIBILITY = {
    "queue_eligible": ("A", "B", "C"),
    "needs_extra_response_evidence": ("D",),
    "low_confidence_signal": ("E",),
}

VULNERABILITY_FAMILIES = (
    "sqli",
    "xss",
    "xxe",
    "ssrf",
    "upload",
    "deserialize",
    "ssti",
    "idor",
    "authz",
    "authn",
    "race",
    "logic",
    "info_disclosure",
    "config_exposure",
    "crypto",
    "rce",
    "redirect",
    "csrf",
    "other",
)

PARAMETER_SCOPES = ("single_parameter", "endpoint_subset", "endpoint_all_parameters")

QUOTA_MAX_PER_SYSTEM_AND_FAMILY = 3

DEFAULT_PORTS = {"http": 80, "https": 443}

_UUID_SEGMENT = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_HEX_SEGMENT = re.compile(r"^[0-9a-fA-F]{16,}$")
_NUMERIC_SEGMENT = re.compile(r"^\d+$")

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


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def canonical_target(url: str) -> str:
    """scheme://host[:port] 小写、默认端口省略、去尾斜杠；无 scheme 时按 host 处理。"""
    text = _text(url).rstrip("/")
    if "://" not in text:
        return text.lower()
    scheme, rest = text.split("://", 1)
    authority = rest.split("/", 1)[0]
    if "@" in authority:
        authority = authority.split("@", 1)[1]
    host = authority.lower()
    if ":" in host:
        hostname, _, port = host.rpartition(":")
        if port.isdigit() and int(port) == DEFAULT_PORTS.get(scheme.lower()):
            host = hostname
    return f"{scheme.lower()}://{host}"


def canonical_host(url_or_host: str) -> str:
    """host[:port] 小写、默认端口省略（API 键用，无 scheme 时无法判定默认端口则保留）。"""
    text = _text(url_or_host).rstrip("/")
    if "://" in text:
        return canonical_target(text).split("://", 1)[1]
    return text.lower()


def normalize_endpoint(url_or_path: str) -> str:
    """端点归一化：小写、去 query/fragment、去尾斜杠（根除外）、连续斜杠折叠、
    纯数字段→{n}、UUID→{uuid}、>=16 位 hex→{hex}。确定性，规格 2.7
    "不得因不同 URL 人为制造多个漏洞"的保守实现。"""
    text = _text(url_or_path)
    if "://" in text:
        text = text.split("://", 1)[1]
        text = text.split("/", 1)[1] if "/" in text else ""
    path = text.split("?", 1)[0].split("#", 1)[0]
    path = re.sub(r"/{2,}", "/", path).lower().rstrip("/").lstrip("/")
    if not path:
        return "/"
    normalized = []
    for segment in path.split("/"):
        if _NUMERIC_SEGMENT.match(segment):
            normalized.append("{n}")
        elif _UUID_SEGMENT.match(segment):
            normalized.append("{uuid}")
        elif _HEX_SEGMENT.match(segment):
            normalized.append("{hex}")
        else:
            normalized.append(segment)
    return "/" + "/".join(normalized)


def normalize_http_method(method: Any) -> str:
    return _text(method).upper()


def normalize_parameter_name(name: Any) -> str:
    return _text(name).lower()


def normalize_parameter_names(names: Iterable[Any] | None) -> list[str]:
    unique = {normalize_parameter_name(n) for n in (names or []) if _text(n)}
    return sorted(unique)


def normalize_content_type(content_type: Any) -> str:
    return _text(content_type).split(";", 1)[0].strip().lower()


def generic_candidate_key(candidate: Mapping[str, Any]) -> dict[str, Any]:
    """通用键（规格 4.2 第一套，六字段逐一精确一致）。"""
    return {
        "canonical_target": canonical_target(_text(candidate.get("target") or candidate.get("url"))),
        "endpoint": normalize_endpoint(_text(candidate.get("endpoint") or candidate.get("url"))),
        "http_method": normalize_http_method(candidate.get("http_method") or "GET"),
        "parameter_name": normalize_parameter_name(candidate.get("parameter_name")),
        "input_location": _text(candidate.get("input_location")).lower(),
        "test_family": _text(candidate.get("test_family") or candidate.get("vulnerability_family")).lower(),
    }


def api_candidate_key(candidate: Mapping[str, Any]) -> dict[str, Any]:
    """API 键（规格 4.2 第二套，六字段逐一精确一致）。"""
    return {
        "canonical_host": canonical_host(_text(candidate.get("host") or candidate.get("url"))),
        "normalized_path": normalize_endpoint(_text(candidate.get("path") or candidate.get("url"))),
        "http_method": normalize_http_method(candidate.get("http_method") or "GET"),
        "parameter_names": normalize_parameter_names(candidate.get("parameter_names")),
        "content_type": normalize_content_type(candidate.get("content_type")),
        "source_kind": _text(candidate.get("source_kind")).upper(),
    }


def miniapp_candidate_key(candidate: Mapping[str, Any]) -> dict[str, Any]:
    """小程序键（规格 4.2 第三套，六字段逐一精确一致）。"""
    return {
        "miniapp_id": _text(candidate.get("miniapp_id")).lower(),
        "backend_host": canonical_host(_text(candidate.get("backend_host") or candidate.get("url"))),
        "normalized_path": normalize_endpoint(_text(candidate.get("path") or candidate.get("url"))),
        "http_method": normalize_http_method(candidate.get("http_method") or "GET"),
        "parameter_names": normalize_parameter_names(candidate.get("parameter_names")),
        "package_version": _text(candidate.get("package_version")),
    }


def merge_key(finding: Mapping[str, Any]) -> dict[str, Any]:
    """2.7 合并器七键；sqli 家族强制 parameter_scope=endpoint_all_parameters
    （同一接口多个参数只计一处），其余家族保留调用方声明的 parameter_scope。"""
    family = _text(finding.get("vulnerability_family")).lower()
    scope = _text(finding.get("parameter_scope")).lower() or "single_parameter"
    if family == "sqli":
        scope = "endpoint_all_parameters"
    return {
        "canonical_target": canonical_target(
            _text(finding.get("canonical_target") or finding.get("target") or finding.get("url"))
        ),
        "product_or_component": _text(finding.get("product_or_component")).lower(),
        "normalized_endpoint": normalize_endpoint(
            _text(finding.get("normalized_endpoint") or finding.get("endpoint") or finding.get("url"))
        ),
        "http_method": normalize_http_method(finding.get("http_method") or "GET"),
        "vulnerability_family": family,
        "root_cause_signature": _text(finding.get("root_cause_signature")).lower(),
        "parameter_scope": scope,
    }


def identity_hash(key: Mapping[str, Any]) -> str:
    """键的 canonical JSON（sort_keys、紧凑分隔符）sha256；同键同哈希。"""
    canonical = json.dumps(key, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_candidate_identity(candidate: Mapping[str, Any]) -> dict[str, Any]:
    """按 identity_kind 分派产出身份记录（契约 required 三字段）。"""
    kind = _text(candidate.get("identity_kind") or candidate.get("kind")).lower()
    builders = {"generic": generic_candidate_key, "api": api_candidate_key,
                "miniapp": miniapp_candidate_key}
    if kind not in builders:
        raise ValueError(f"unknown identity_kind: {kind!r}")
    key = builders[kind](candidate)
    return {"identity_kind": kind, "key": key, "identity_hash": identity_hash(key)}


def load_identity_schema() -> dict[str, Any]:
    if not IDENTITY_SCHEMA_PATH.is_file():
        return {}
    try:
        return json.loads(IDENTITY_SCHEMA_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def _credential_scan(node: Any, prefix: str) -> list[str]:
    errors: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            key_text = str(key).lower()
            path = f"{prefix}.{key}" if prefix else str(key)
            if any(fragment in key_text for fragment in _FORBIDDEN_KEY_FRAGMENTS):
                errors.append(f"credential-like key is forbidden in candidate identity: {path}")
            errors.extend(_credential_scan(value, path))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            errors.extend(_credential_scan(value, f"{prefix}[{index}]"))
    return errors


def _is_plain_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


_KEY_FIELDS_BY_KIND = {
    "generic": GENERIC_KEY_FIELDS,
    "api": API_KEY_FIELDS,
    "miniapp": MINIAPP_KEY_FIELDS,
}


def validate_candidate_identity(identity: Any) -> list[str]:
    """依赖-free 契约校验；返回错误列表（空 = 通过）。

    拒绝：缺必需字段、identity_kind 不在枚举、键字段集与契约漂移（缺失/多余/顺序外字段）、
    method/input_location/source_kind 不在枚举、parameter_names 未排序或含重复、
    identity_hash 与键不匹配、凭证类键。
    """
    errors: list[str] = []
    if not isinstance(identity, dict):
        return ["candidate identity must be a dict"]

    for field in ("identity_kind", "key", "identity_hash"):
        if field not in identity:
            errors.append(f"missing required field: {field}")
    if errors:
        # 凭证扫描在提前返回前执行（fail-closed：结构错误不豁免凭证纪律）
        errors.extend(_credential_scan(identity, ""))
        return errors

    kind = identity["identity_kind"]
    if kind not in IDENTITY_KINDS:
        errors.append(f"identity_kind not in enum: {kind!r}")
        errors.extend(_credential_scan(identity, ""))
        return errors

    key = identity["key"]
    if not isinstance(key, dict):
        errors.append("key must be a dict")
        errors.extend(_credential_scan(identity, ""))
        return errors

    expected_fields = list(_KEY_FIELDS_BY_KIND[kind])
    for field in expected_fields:
        if field not in key:
            errors.append(f"missing key field: {field}")
    for field in key:
        if field not in expected_fields:
            errors.append(f"unexpected key field for {kind} identity: {field}")
    if any(e.startswith("missing key field") for e in errors):
        errors.extend(_credential_scan(identity, ""))
        return errors

    if key["http_method"] not in HTTP_METHODS:
        errors.append(f"http_method not in enum: {key['http_method']!r}")

    if kind == "generic":
        if key["input_location"] not in INPUT_LOCATIONS:
            errors.append(f"input_location not in enum: {key['input_location']!r}")
        if not key["test_family"]:
            errors.append("test_family must be non-empty")
        elif key["test_family"] not in VULNERABILITY_FAMILIES:
            errors.append(f"test_family not in enum: {key['test_family']!r}")
        if not key["parameter_name"]:
            errors.append("parameter_name must be non-empty")
    else:
        names = key["parameter_names"]
        if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
            errors.append("parameter_names must be a list of strings")
        elif names != sorted(set(names)):
            errors.append("parameter_names must be sorted and deduplicated")
        if kind == "api":
            if key["source_kind"] not in SOURCE_KINDS:
                errors.append(f"source_kind not in enum: {key['source_kind']!r}")
        else:
            if not key["miniapp_id"]:
                errors.append("miniapp_id must be non-empty")

    expected_hash = identity_hash({f: key[f] for f in expected_fields})
    if identity["identity_hash"] != expected_hash:
        errors.append("identity_hash does not match key (expected canonical sha256)")

    errors.extend(_credential_scan(identity, ""))
    return errors


def validate_merge_key(merge: Any) -> list[str]:
    """2.7 合并键校验；拒绝缺键/多余键/坏枚举/凭证类键。"""
    errors: list[str] = []
    if not isinstance(merge, dict):
        return ["merge key must be a dict"]
    for field in MERGE_KEY_FIELDS:
        if field not in merge:
            errors.append(f"missing merge key field: {field}")
    for field in merge:
        if field not in MERGE_KEY_FIELDS:
            errors.append(f"unexpected merge key field: {field}")
    if any(e.startswith("missing merge key field") for e in errors):
        # 凭证扫描在提前返回前执行（fail-closed：结构错误不豁免凭证纪律）
        errors.extend(_credential_scan(merge, ""))
        return errors

    if merge["http_method"] not in HTTP_METHODS:
        errors.append(f"http_method not in enum: {merge['http_method']!r}")
    if merge["vulnerability_family"] not in VULNERABILITY_FAMILIES:
        errors.append(f"vulnerability_family not in enum: {merge['vulnerability_family']!r}")
    if merge["parameter_scope"] not in PARAMETER_SCOPES:
        errors.append(f"parameter_scope not in enum: {merge['parameter_scope']!r}")
    if merge["vulnerability_family"] == "sqli" and merge["parameter_scope"] != "endpoint_all_parameters":
        errors.append("sqli merge key must use parameter_scope=endpoint_all_parameters")
    if not merge["root_cause_signature"]:
        errors.append("root_cause_signature must be non-empty")
    if not merge["product_or_component"]:
        errors.append("product_or_component must be non-empty")
    # 凭证扫描在所有提前返回路径之后统一执行（fail-closed：结构错误不豁免凭证纪律）
    errors.extend(_credential_scan(merge, ""))
    return errors
