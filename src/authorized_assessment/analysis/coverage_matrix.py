"""测试维度与覆盖子状态（实施规格 10.1/10.2/10.3 + 5.2）。

test-dimensions.csv 行契约与聚合阶段子状态的唯一实现。纯 stdlib、零网络、只读幂等：
  - TEST_DIMENSION_FIELDS：规格 10.1 十六字段；
  - COVERAGE_SUBSTATUSES：规格 10.2 六状态；
  - APPLICATION_MAP_ROW_FIELDS：规格 5.2 application-map 行最小输出字段；
  - validate_test_dimensions_row / validate_application_map_row：行级校验；
  - coverage_ratio：钳制 [0,1] 的聚合覆盖率（tested > 总行数必须拒绝）；
  - aggregate_substatuses：聚合阶段子状态映射校验。
"""
from __future__ import annotations

import hashlib
import re
from typing import Mapping

TEST_DIMENSION_FIELDS = (
    "role",
    "account_ref_hash",
    "tenant",
    "object_ref_hash",
    "api_version",
    "client_version",
    "device",
    "workflow_state",
    "http_method",
    "content_type",
    "feature_flag",
    "authentication_state",
    "branch",
    "status",
    "reason",
    "evidence_ref",
)

COVERAGE_SUBSTATUSES = (
    "tested",
    "not_applicable",
    "blocked",
    "approval_required",
    "needs_manual_validation",
    "inconclusive",
)

# 规格 5.2：application_mapping 五个子阶段每行至少输出这 7 个字段。
APPLICATION_MAP_ROW_FIELDS = (
    "applicable",
    "status",
    "source",
    "asset",
    "endpoint_or_surface",
    "reason",
    "evidence_ref",
)

APPLICATION_MAP_SUBPHASES = (
    "graphql_mapping",
    "websocket_mapping",
    "file_surface_mapping",
    "auth_surface_mapping",
    "webhook_mapping",
)

APPLICABLE_VALUES = ("applicable", "not_applicable", "unknown")

_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")

# 哈希字段禁止携带的明文形态（凭证/敏感对象原文）：形如 key=value 或含凭证前缀的值。
_PLAINTEXT_SECRET_MARKERS = ("password=", "passwd=", "token=", "cookie:", "authorization:", "bearer ")


def ref_hash(value: str) -> str:
    """生成不可逆引用哈希（sha256 小写十六进制）；调用方在写入 hash 字段前使用。"""
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def _require_nonempty(row: Mapping[str, object], field: str, label: str, violations: list[str]) -> None:
    value = row.get(field)
    if value is None or not str(value).strip():
        violations.append(f"{label}: 字段 {field} 必须非空")


def _check_hash_field(row: Mapping[str, object], field: str, label: str, violations: list[str]) -> None:
    value = str(row.get(field) or "")
    if not value:
        return
    if not _SHA256_HEX.match(value):
        violations.append(f"{label}.{field}: 必须为 sha256 十六进制不可逆引用或空串，禁止明文")
        return
    lowered = value.lower()
    if any(marker in lowered for marker in _PLAINTEXT_SECRET_MARKERS):
        violations.append(f"{label}.{field}: 疑似携带明文凭证/敏感对象原文，禁止")


def validate_test_dimensions_row(row: Mapping[str, object], label: str = "test_dimensions") -> list[str]:
    """test-dimensions.csv 单行校验（规格 10.1 + 13.2 负例）。"""
    violations: list[str] = []
    if not isinstance(row, Mapping):
        return [f"{label}: 行必须是键值映射"]
    for field in TEST_DIMENSION_FIELDS:
        if field not in row:
            violations.append(f"{label}: 缺少必需字段 {field}")
    unknown = sorted(set(row) - set(TEST_DIMENSION_FIELDS))
    if unknown:
        violations.append(f"{label}: 未知字段 {unknown}（维度矩阵保持 10.1 最小集）")
    for field in ("account_ref_hash", "object_ref_hash"):
        _check_hash_field(row, field, label, violations)
    status = str(row.get("status") or "")
    if status and status not in COVERAGE_SUBSTATUSES:
        violations.append(f"{label}.status 非法: {status!r}（允许值 {list(COVERAGE_SUBSTATUSES)}）")
    if status == "not_applicable":
        reason = str(row.get("reason") or "").strip()
        if not reason:
            violations.append(f"{label}: status=not_applicable 但 reason 为空（规格 10.2：不能空填）")
    if status == "tested":
        evidence = str(row.get("evidence_ref") or "").strip()
        if not evidence:
            violations.append(f"{label}: status=tested 但 evidence_ref 为空（完成必须可证明）")
    if status in ("blocked", "approval_required", "needs_manual_validation", "inconclusive"):
        reason = str(row.get("reason") or "").strip()
        if not reason:
            violations.append(f"{label}: status={status} 必须 reason 说明下一步")
    return violations


def validate_application_map_row(row: Mapping[str, object], label: str = "application_map") -> list[str]:
    """application-map 产物单行最小字段校验（规格 5.2 + 10.3）。"""
    violations: list[str] = []
    if not isinstance(row, Mapping):
        return [f"{label}: 行必须是键值映射"]
    for field in APPLICATION_MAP_ROW_FIELDS:
        if field not in row:
            violations.append(f"{label}: 缺少最小字段 {field}（规格 5.2）")
    applicable = str(row.get("applicable") or "")
    if applicable and applicable not in APPLICABLE_VALUES:
        violations.append(f"{label}.applicable 非法: {applicable!r}（允许值 {list(APPLICABLE_VALUES)}）")
    status = str(row.get("status") or "")
    if status and status not in COVERAGE_SUBSTATUSES:
        violations.append(f"{label}.status 非法: {status!r}（允许值 {list(COVERAGE_SUBSTATUSES)}）")
    if status == "not_applicable":
        if not str(row.get("reason") or "").strip():
            violations.append(f"{label}: status=not_applicable 但 reason 为空（规格 10.2）")
        if applicable != "not_applicable":
            violations.append(
                f"{label}: status=not_applicable 必须 applicable=not_applicable"
                "（未做适用性判定不得宣称不适用，规格 10.3）"
            )
    if status == "tested" and not str(row.get("evidence_ref") or "").strip():
        violations.append(f"{label}: status=tested 但 evidence_ref 为空")
    return violations


def coverage_ratio(tested: int, total: int) -> float:
    """聚合覆盖率 = tested / total，钳制 [0,1]（规格 13.2：coverage > 1 必须拒绝）。

    tested/total 为负或 tested > total 时抛 ValueError（行数矛盾不得静默钳制）；
    total=0 返回 0.0。
    """
    if tested < 0 or total < 0:
        raise ValueError(f"coverage counts must be non-negative: tested={tested}, total={total}")
    if tested > total:
        raise ValueError(f"coverage inconsistent: tested({tested}) > total({total})")
    return round(min(tested / total, 1.0), 4) if total else 0.0


def aggregate_substatuses(
    mapping: Mapping[str, str], label: str = "coverage"
) -> tuple[dict[str, str], list[str]]:
    """校验并返回聚合阶段子状态映射（规格 10.2）。返回 (normalized, violations)。"""
    violations: list[str] = []
    normalized: dict[str, str] = {}
    if not isinstance(mapping, Mapping):
        return normalized, [f"{label}: 子状态映射必须是键值对象"]
    for subphase, status in mapping.items():
        name = str(subphase).strip()
        value = str(status).strip()
        if not name:
            violations.append(f"{label}: 子分支名不能为空")
            continue
        if value not in COVERAGE_SUBSTATUSES:
            violations.append(
                f"{label}.{name}: 子状态非法 {value!r}（允许值 {list(COVERAGE_SUBSTATUSES)}）"
            )
            continue
        normalized[name] = value
    return normalized, violations
