"""静态/动态端点对账域（实施规格 6.4 1558-1581 行 + 6.2 拆分 1507-1511 行，
Batch 12）。

只读离线：对账是把静态提取的端点基线与动态映射的端点基线做一次离线比较，产物为
CSV 清单（规格 1564 行：artifacts/miniapp/reconciliation/static-dynamic-endpoints.csv，
契约 miniapp_reconciliation_schema）。不发任何新请求——unreachable/stale 是状态判定
不是测试邀请，禁止通过探测"复核"（红线常量 RECONCILIATION_NO_PROBE_RULE 留痕）。

本域不产出 review JSON/8 状态候选行（规格 6.4 产物只有 CSV，无 rows/summaries）：
对账行是覆盖清单，不是漏洞候选；对账发现的隐藏流程（dynamic_only/feature_gated）
只生成后续 phase 的测试假设，漏洞候选仍经后续 phase 进入标准 review ledger 与
finding 五门。phase 覆盖完成度由 coverage_substatus 六值 substatuses 承载（5 分支，
与 skill init/audit 常量、第 12 契约三方同源，漂移由 tests/test_xcx_cloud_
reconciliation_phase_split.py 与本模块测试锁定）。

十值端点状态（规格 1570-1581 行）是 CSV 行级状态，与 coverage_substatus 六值不同
源（唯一语义交集 needs_manual_validation：同名值分别承载行级判定与 phase 覆盖语义，
互不 substitute）。

确定性分类（实现定义供操作者复核）：classify_endpoint_status 以"判定资格修饰优先
于出现位置"为优先级——needs_manual_validation > unreachable > stale > feature_gated
> version_specific > third_party > platform_shared > both_seen > static_only >
dynamic_only；静态/动态均未出现且无修饰时兜底 needs_manual_validation（无证据的行
不可凭空定状态）。同一输入恒得同一输出。

CSV 编码 utf-8-sig（与 skill 种子一致，Excel 打开不乱码）。
"""
from __future__ import annotations

import csv
import io
from typing import Iterable, Mapping

# 契约标识与版本（miniapp_reconciliation_schema.schema_version/contract 同源）。
MINIAPP_RECONCILIATION_CONTRACT = "miniapp_reconciliation_schema"
MINIAPP_RECONCILIATION_SCHEMA_VERSION = "1.0"

# 对账 phase 与产物路径（规格 6.2 1507-1511 行 + 6.4 产物 1564 行；与 xcx skill
# init/audit 常量、第 12 契约三方同源）。
RECONCILIATION_PHASE = "static_dynamic_reconciliation"
RECONCILIATION_ARTIFACT = "artifacts/miniapp/reconciliation/static-dynamic-endpoints.csv"

# 五分支（契约 phases.static_dynamic_reconciliation.branches 同源；规格 6.4 未给
# 分支清单，按对账活动分解设计，batch12_0 卡片留痕）。
RECONCILIATION_BRANCHES: tuple[str, ...] = (
    "static_endpoint_base",
    "dynamic_endpoint_base",
    "match_status_classification",
    "hidden_flow_identification",
    "stale_entry_disposition",
)

# 十值端点状态（规格 1570-1581 行逐一对应；CSV 行级枚举）。
RECONCILIATION_ENDPOINT_STATES: tuple[str, ...] = (
    "static_only",
    "dynamic_only",
    "both_seen",
    "feature_gated",
    "stale",
    "version_specific",
    "third_party",
    "platform_shared",
    "unreachable",
    "needs_manual_validation",
)

# 判定行状态：这些行必须有非空 reason（过期/不可达不得静默充数，人工验证需留痕）。
RECONCILIATION_JUDGMENT_STATES: tuple[str, ...] = (
    "stale",
    "unreachable",
    "needs_manual_validation",
)

# CSV 列清单（契约 csv_fields 同源；表头精确匹配、顺序敏感）。
RECONCILIATION_CSV_FIELDS: tuple[str, ...] = (
    "endpoint_id",
    "host",
    "method",
    "path",
    "source_material",
    "static_evidence_ref",
    "dynamic_evidence_ref",
    "status",
    "reason",
    "notes",
)

# 红线常量（规格 6.4 + batch12_0 契约 red_lines；写入候选 precondition 语义）。
RECONCILIATION_NO_PROBE_RULE: str = (
    "对账为离线比较既有静态证据与授权动态证据，不发任何新请求；unreachable/stale "
    "不得通过探测'复核'（unreachable 是状态判定不是测试邀请）"
)
PLATFORM_SHARED_ATTRIBUTION_RULE: str = (
    "third_party/platform_shared 行按归属状态记录；平台共享资产不得误报为自有资产漏洞"
)
STALE_NOT_FINDING_RULE: str = (
    "stale/unreachable 条目不得作为活跃问题上报（死代码防误报）；dynamic_only/"
    "feature_gated 行进入隐藏流程发现，只生成后续测试假设"
)

# 确定性分类优先级（实现定义：判定资格修饰优先于出现位置）。
_CLASSIFICATION_PRECEDENCE: tuple[str, ...] = (
    "needs_manual_validation",
    "unreachable",
    "stale",
    "feature_gated",
    "version_specific",
    "third_party",
    "platform_shared",
)

# 证据布尔键 → 状态（分类输入；键名即观察语义）。
_HINT_KEYS: dict[str, str] = {
    "needs_manual_hint": "needs_manual_validation",
    "unreachable_hint": "unreachable",
    "stale_hint": "stale",
    "feature_gated_hint": "feature_gated",
    "version_hint": "version_specific",
    "third_party_hint": "third_party",
    "platform_shared_hint": "platform_shared",
}


def classify_endpoint_status(evidence: Mapping[str, object]) -> str:
    """证据布尔键 → 十值端点状态（确定性；同输入同输出）。

    优先级：判定资格修饰（needs_manual/unreachable/stale/feature_gated/version_
    specific/third_party/platform_shared）覆盖出现位置；两基线均未出现且无修饰时
    兜底 needs_manual_validation（无证据的行不可凭空定状态）。
    """
    for state in _CLASSIFICATION_PRECEDENCE:
        key = next(k for k, v in _HINT_KEYS.items() if v == state)
        if evidence.get(key):
            return state
    static_seen = bool(evidence.get("static_seen"))
    dynamic_seen = bool(evidence.get("dynamic_seen"))
    if static_seen and dynamic_seen:
        return "both_seen"
    if static_seen:
        return "static_only"
    if dynamic_seen:
        return "dynamic_only"
    return "needs_manual_validation"


def build_reconciliation_row(
    endpoint: Mapping[str, object],
    status: str | None = None,
) -> dict[str, str]:
    """端点观察（含分类证据键）→ 对账 CSV 行（列与 RECONCILIATION_CSV_FIELDS
    一致）。status 缺省时由 classify_endpoint_status 确定性推导；显式 status 仅
    接受十值之一（人工判定覆盖）。"""
    evidence = endpoint.get("evidence") if isinstance(endpoint.get("evidence"), Mapping) else endpoint
    row_status = str(status or "").strip() or classify_endpoint_status(evidence)
    return {
        "endpoint_id": str(endpoint.get("endpoint_id") or "").strip(),
        "host": str(endpoint.get("host") or "").strip(),
        "method": str(endpoint.get("method") or "").strip(),
        "path": str(endpoint.get("path") or "").strip(),
        "source_material": str(endpoint.get("source_material") or "").strip(),
        "static_evidence_ref": str(endpoint.get("static_evidence_ref") or "").strip(),
        "dynamic_evidence_ref": str(endpoint.get("dynamic_evidence_ref") or "").strip(),
        "status": row_status,
        "reason": str(endpoint.get("reason") or "").strip(),
        "notes": str(endpoint.get("notes") or "").strip(),
    }


def validate_reconciliation_rows(rows: Iterable[Mapping[str, object]]) -> list[str]:
    """对账行校验：endpoint_id 非空 + status ∈ 十值 + 判定行（judgment_states）
    reason 非空（静默省略禁止）。"""
    violations: list[str] = []
    for index, row in enumerate(rows, start=1):
        if not isinstance(row, Mapping):
            violations.append(f"row {index}: 对账行必须是键值映射")
            continue
        endpoint_id = str(row.get("endpoint_id") or "").strip()
        if not endpoint_id:
            violations.append(f"row {index}: endpoint_id 为空（行标识必需）")
        status = str(row.get("status") or "").strip()
        if not status:
            violations.append(f"row {index}: status 为空")
        elif status not in RECONCILIATION_ENDPOINT_STATES:
            violations.append(
                f"row {index}: status 非法 {status!r}"
                f"（允许值 {list(RECONCILIATION_ENDPOINT_STATES)}）"
            )
        reason = str(row.get("reason") or "").strip()
        if status in RECONCILIATION_JUDGMENT_STATES and not reason:
            violations.append(
                f"row {index}: status {status!r} 需要非空 reason"
                "（过期/不可达不得静默充数，人工验证需留痕）"
            )
    return violations


def render_reconciliation_csv(rows: Iterable[Mapping[str, object]]) -> str:
    """对账行 → CSV 文本（表头精确等于 RECONCILIATION_CSV_FIELDS，顺序敏感；
    调用方负责校验并以 utf-8-sig 落盘）。"""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(RECONCILIATION_CSV_FIELDS))
    writer.writeheader()
    for row in rows:
        writer.writerow({field: str(row.get(field) or "") for field in RECONCILIATION_CSV_FIELDS})
    return buffer.getvalue()


def _cli() -> int:
    """离线 CLI：端点观察 JSON 文件 → 对账 CSV（纯文件到文件；违例 fail-closed
    不落盘）。不发任何网络请求。"""
    import argparse
    import json
    from pathlib import Path

    parser = argparse.ArgumentParser(
        description="Offline static/dynamic endpoint reconciliation (no network; "
        "unreachable/stale rows are judgments, never probe targets)."
    )
    parser.add_argument(
        "--endpoints", required=True,
        help="Endpoint observations JSON file (list or {endpoints: [...]})",
    )
    parser.add_argument("--out", required=True, help="Output CSV path")
    args = parser.parse_args()
    payload = json.loads(Path(args.endpoints).read_text(encoding="utf-8-sig"))
    endpoints = payload.get("endpoints", []) if isinstance(payload, dict) else payload
    if not isinstance(endpoints, list):
        print("ERROR: endpoints must be a list", flush=True)
        return 2
    rows = [
        build_reconciliation_row(item, str(item.get("status") or "") or None)
        if isinstance(item, Mapping)
        else item
        for item in endpoints
    ]
    violations = validate_reconciliation_rows(rows)
    if violations:
        for violation in violations:
            print(f"VIOLATION: {violation}", flush=True)
        print(f"rejected: {len(violations)} violation(s); nothing written", flush=True)
        return 2
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render_reconciliation_csv(rows), encoding="utf-8-sig")
    print(f"rows={len(list(rows))} out={out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
