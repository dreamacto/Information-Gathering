"""WebSocket 面离线盘点（实施规格 5.2 websocket_mapping 子阶段 + 3.1 模块清单）。

只读离线：从复核会话提炼的结构化盘点观察确定性识别 WebSocket/SSE/realtime 面
（ws://、wss:// scheme 与端点/正文形态标记），校验盘点行并汇总 manifest 形状；
不发任何请求、不建立任何连接。盘点行字段为规格 5.2 七字段（复用
coverage_matrix.validate_application_map_row 单一实现）+ surface_kind + scheme。

盘点只证明"面存在"，不证明"已测试"：观察未显式给出行 status 时按适用性派生
（applicable → inconclusive），declared status=tested 必须带 evidence_ref。
"""
from __future__ import annotations

from typing import Iterable, Mapping

from authorized_assessment.analysis.coverage_matrix import (
    APPLICABLE_VALUES,
    COVERAGE_SUBSTATUSES,
    validate_application_map_row,
)

# 发现来源（规格 5.2：JS / 流量 / 文档三途径 + SSE 流）。
WEBSOCKET_SURFACE_KINDS: tuple[str, ...] = (
    "captured_traffic",
    "js_reference",
    "api_doc_reference",
    "sse_stream",
)

# ws/wss 传输 scheme（盘点行 scheme 字段枚举；unknown = 途径未给出 scheme）。
WEBSOCKET_SCHEMES: tuple[str, ...] = ("ws", "wss", "unknown")

# 规格 5.2 七字段 + surface_kind + scheme（实现扩展字段）。
INVENTORY_ROW_FIELDS: tuple[str, ...] = (
    "applicable",
    "status",
    "source",
    "asset",
    "endpoint_or_surface",
    "reason",
    "evidence_ref",
    "surface_kind",
    "scheme",
)

MANIFEST_VERSION = "1.0"

# URL scheme 标记（确定性前缀匹配）。
URL_SCHEME_MARKERS: tuple[str, ...] = ("ws://", "wss://")

# 端点路径标记（确定性子串匹配，小写比较）。
ENDPOINT_MARKERS: tuple[str, ...] = (
    "websocket",
    "/ws",
    "socket.io",
    "sockjs",
    "primus",
    "realtime",
    "eventsource",
    "text/event-stream",
    "/sse",
    "stomp",
)

# 正文/JS 形态标记（复核会话从 JS/响应样本提炼的形态线索，非原始正文）。
BODY_MARKERS: tuple[str, ...] = (
    "new websocket",
    "websocket(",
    "socket.io",
    "eventsource",
    "text/event-stream",
    "sockjs",
    "stomp",
    "onmessage",
    "onopen",
)


def looks_like_websocket(endpoint: str = "", body_markers: Iterable[str] = ()) -> bool:
    """从端点路径与正文形态标记确定性判断是否 WebSocket/SSE 面（不做启发式猜测）。"""
    lowered_ep = (endpoint or "").lower()
    if any(lowered_ep.startswith(scheme) for scheme in URL_SCHEME_MARKERS):
        return True
    if any(marker in lowered_ep for marker in ENDPOINT_MARKERS):
        return True
    lowered_markers = [str(m).lower() for m in body_markers]
    return any(marker in m for m in lowered_markers for marker in BODY_MARKERS)


def detect_scheme(endpoint: str = "") -> str:
    """从端点确定性提取传输 scheme（ws/wss）；无法判定为 unknown。"""
    lowered = (endpoint or "").strip().lower()
    if lowered.startswith("wss://"):
        return "wss"
    if lowered.startswith("ws://"):
        return "ws"
    return "unknown"


def validate_inventory_row(row: Mapping[str, object], label: str = "websocket_inventory") -> list[str]:
    """盘点行校验：规格 5.2 七字段复用 validate_application_map_row + surface_kind/scheme 扩展。"""
    violations = validate_application_map_row(row, label=label)
    surface_kind = str(row.get("surface_kind") or "")
    if surface_kind and surface_kind not in WEBSOCKET_SURFACE_KINDS:
        violations.append(
            f"{label}.surface_kind 非法: {surface_kind!r}（允许值 {list(WEBSOCKET_SURFACE_KINDS)}）"
        )
    scheme = str(row.get("scheme") or "")
    if scheme and scheme not in WEBSOCKET_SCHEMES:
        violations.append(f"{label}.scheme 非法: {scheme!r}（允许值 {list(WEBSOCKET_SCHEMES)}）")
    return violations


def _derive_status(applicability: str, declared: str) -> str:
    if declared in COVERAGE_SUBSTATUSES:
        return declared
    if applicability == "not_applicable":
        return "not_applicable"
    return "inconclusive"


def build_websocket_inventory(
    observations: Iterable[Mapping[str, object]],
    label: str = "websocket_inventory",
) -> dict:
    """盘点观察 → manifest 形状（离线数据变换，不落盘）。

    观察必需键：endpoint（或 endpoint_or_surface）；可选：asset/surface_kind/scheme/
    source/evidence_ref/applicability/status/reason/body_markers。endpoint_or_surface
    缺省由 endpoint 派生；scheme 缺省由端点前缀确定性提取；applicability 缺省按
    looks_like_websocket 命中派生。
    返回 {"manifest_version", "surfaces", "summary", "violations"}。
    """
    surfaces: list[dict] = []
    violations: list[str] = []
    by_kind: dict[str, int] = {kind: 0 for kind in WEBSOCKET_SURFACE_KINDS}
    by_status: dict[str, int] = {status: 0 for status in COVERAGE_SUBSTATUSES}
    by_applicability: dict[str, int] = {key: 0 for key in APPLICABLE_VALUES}
    by_scheme: dict[str, int] = {scheme: 0 for scheme in WEBSOCKET_SCHEMES}
    for index, observation in enumerate(observations, start=1):
        if not isinstance(observation, Mapping):
            violations.append(f"{label}: 第 {index} 条盘点观察必须是键值映射")
            continue
        endpoint = str(observation.get("endpoint") or "").strip()
        endpoint_or_surface = str(observation.get("endpoint_or_surface") or "").strip() or endpoint
        body_markers = [str(m) for m in (observation.get("body_markers") or [])]
        declared_applicability = str(observation.get("applicability") or "").strip()
        if declared_applicability and declared_applicability not in APPLICABLE_VALUES:
            violations.append(
                f"{label}: 第 {index} 条观察 applicability 非法 {declared_applicability!r}"
                f"（允许值 {list(APPLICABLE_VALUES)}）"
            )
            continue
        if not endpoint_or_surface and not body_markers:
            violations.append(f"{label}: 第 {index} 条观察缺少 endpoint_or_surface（盘点行必须可定位）")
            continue
        if declared_applicability:
            applicability = declared_applicability
        elif looks_like_websocket(endpoint, body_markers):
            applicability = "applicable"
        else:
            applicability = "unknown"
        status = _derive_status(applicability, str(observation.get("status") or "").strip())
        surface_kind = str(observation.get("surface_kind") or "").strip()
        if not surface_kind and applicability == "applicable":
            surface_kind = "captured_traffic"
        declared_scheme = str(observation.get("scheme") or "").strip().lower()
        if declared_scheme and declared_scheme not in WEBSOCKET_SCHEMES:
            violations.append(
                f"{label}: 第 {index} 条观察 scheme 非法 {declared_scheme!r}"
                f"（允许值 {list(WEBSOCKET_SCHEMES)}）"
            )
            declared_scheme = ""
        scheme = declared_scheme or detect_scheme(endpoint)
        row = {
            "applicable": applicability,
            "status": status,
            "source": str(observation.get("source") or "").strip(),
            "asset": str(observation.get("asset") or "").strip(),
            "endpoint_or_surface": endpoint_or_surface,
            "reason": str(observation.get("reason") or "").strip(),
            "evidence_ref": str(observation.get("evidence_ref") or "").strip(),
            "surface_kind": surface_kind,
            "scheme": scheme if scheme in WEBSOCKET_SCHEMES else "unknown",
        }
        surfaces.append(row)
        if surface_kind:
            by_kind[surface_kind] = by_kind.get(surface_kind, 0) + 1
        by_status[status] = by_status.get(status, 0) + 1
        by_applicability[applicability] = by_applicability.get(applicability, 0) + 1
        by_scheme[row["scheme"]] = by_scheme.get(row["scheme"], 0) + 1
        row_violations = validate_inventory_row(row, label=f"{label}[{index}]")
        if applicability == "applicable" and not row["source"]:
            row_violations.append(
                f"{label}[{index}]: applicable 盘点行 source 为空（发现必须可追溯）"
            )
        violations += row_violations
    return {
        "manifest_version": MANIFEST_VERSION,
        "surfaces": surfaces,
        "summary": {
            "surface_count": len(surfaces),
            "by_surface_kind": by_kind,
            "by_status": by_status,
            "by_applicability": by_applicability,
            "by_scheme": by_scheme,
        },
        "violations": violations,
    }
