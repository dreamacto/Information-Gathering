"""第三方边界复核域（实施规格 6.7 1635-1660 行 + 6.2 拆分 1528-1534 行，
Batch 12）。

只读离线：third_party_platform_boundary phase 的产物是第三方边界 CSV 清单（规格
1645 行：artifacts/miniapp/cloud/third-party-boundary.csv，契约 miniapp_cloud_
schema），形状与 review JSON 不同（csv_fields 9 列，无 rows/summaries 结构）。
不发任何请求、不触发真实支付、不产生任何写操作、不批量读取——默认只做材料、
配置、授权流量和最小读验证（规格 1660 行红线，THIRD_PARTY_NO_PAYMENT_RULE 留痕）。

观察输入为复核会话从操作员提供的授权材料、本地流量或第三方 SDK/配置副本提炼的
结构化记录。筛选入口沿用统一筛选模式（观察键→证据形态确定性映射→rule_satisfied
升级判定→8 状态分级）：仅 *_confirmed（既有只读证据的复核判定且可复现）可升级
candidate；"第三方端点存在/SDK 配置标记/归属不一致线索"等形态与支持性观察永不
升级（signal 不是漏洞）。分级与证据推导复用 cloud_function_review 宿主的通用
函数（单一来源），分支汇总经 injection_candidates.aggregate_category_status 单一
引擎聚合；CSV 行形状、行校验与 CSV 渲染为本域实现（形状不同，判定逻辑不复制）。

分支与 CSV 行的关联不落盘（CSV 无 branch 列）：分支汇总仅存在于筛选返回值，
substatuses 由复核会话写入 phase_status.json，审计按 batch12_0 CSV 语义验证
（全分支 proven + tested 需 ≥1 行 + not_applicable 需 phase 行 reason 非空，
契约 csv_phase_completion_invariant）。

两分支（与 contracts/miniapp_cloud_schema.json phases.third_party_platform_boundary.
branches 同源）：
- third_party_service_boundary：地图、支付、推送等第三方服务边界；
- platform_shared_asset_attribution：平台共享资产归属（不得误报为自有资产）。
"""
from __future__ import annotations

import csv
import io
from typing import Iterable, Mapping

from authorized_assessment.miniapp import cloud_function_review as cloud_engine
from authorized_assessment.triage import injection_candidates as ic

# 两分支（契约 phases.third_party_platform_boundary.branches 同源）。
THIRD_PARTY_BRANCHES: tuple[str, ...] = (
    "third_party_service_boundary",
    "platform_shared_asset_attribution",
)

# CSV 列清单（契约 csv_fields 同源；表头精确匹配、顺序敏感；与 xcx skill init/
# audit 常量三方同源，漂移由 tests/test_xcx_cloud_reconciliation_phase_split.py
# 与本模块测试锁定）。
THIRD_PARTY_CSV_FIELDS: tuple[str, ...] = (
    "row_id",
    "service_name",
    "service_type",
    "host",
    "attribution",
    "boundary_status",
    "evidence_ref",
    "reason",
    "notes",
)

# 服务类型（契约 service_types 同源；map/payment/push 为规格点名域，plugin/sdk/
# analytics/other 覆盖"等"字残余域）。
THIRD_PARTY_SERVICE_TYPES: tuple[str, ...] = (
    "map", "payment", "push", "analytics", "plugin", "sdk", "other",
)

# 归属枚举（契约 attribution_values 同源；与 skill audit KNOWN_HOST_STATES 集合
# 相等——单一来源对齐：hosts 分类状态）。
THIRD_PARTY_ATTRIBUTION_VALUES: tuple[str, ...] = (
    "in_scope", "third_party", "platform", "platform_shared",
    "out_of_scope", "invalid", "confirmation_required", "unclassified",
)
# 待确认归属：这些行必须有非空 reason（静默省略禁止，与 audit 行校验一致）。
THIRD_PARTY_PENDING_ATTRIBUTIONS: tuple[str, ...] = ("confirmation_required", "unclassified")

# 证据形态（8：6 形态/支持性永不升级 + 2 确认形态与分支一一对应）。
THIRD_PARTY_EVIDENCE_KINDS: tuple[str, ...] = (
    "third_party_endpoint_observed",
    "third_party_sdk_config_clue_observed",
    "business_data_to_third_party_clue_observed",
    "payment_flow_marker_observed",
    "platform_asset_marker_observed",
    "asset_attribution_mismatch_clue_observed",
    "third_party_unauthorized_data_flow_confirmed",
    "platform_shared_asset_misattributed_confirmed",
)

# "不算漏洞"证据形态：仅形态/支持性观察，未证明边界失效或归属错误。
THIRD_PARTY_INSUFFICIENT_KINDS: tuple[str, ...] = (
    "third_party_endpoint_observed",
    "third_party_sdk_config_clue_observed",
    "business_data_to_third_party_clue_observed",
    "payment_flow_marker_observed",
    "platform_asset_marker_observed",
    "asset_attribution_mismatch_clue_observed",
)

# 升级规则（实现定义，固定语义；确认形态与分支一一对应、不跨分支升级）：
# "确认"语义要求观察来自既有只读证据（授权材料/本地流量/SDK 与配置副本）的复核
# 判定且可复现；禁止为取得确认而触发真实支付、产生写操作或批量读取（规格 1660
# 红线，precondition 必须留痕）。
THIRD_PARTY_UPGRADE_RULES: dict[str, dict[str, tuple[tuple[str, ...], ...]]] = {
    "third_party_service_boundary": {
        "required_any_groups": (("third_party_unauthorized_data_flow_confirmed",),)
    },
    "platform_shared_asset_attribution": {
        "required_any_groups": (("platform_shared_asset_misattributed_confirmed",),)
    },
}

# v1 观察键 → 证据形态（确定性映射；版本化演进同 OBSERVATION_SCHEMA_VERSION）。
THIRD_PARTY_OBSERVATION_EVIDENCE_MAP: dict[str, str] = {
    key: key for key in THIRD_PARTY_EVIDENCE_KINDS
}

THIRD_PARTY_OBSERVATION_FIELD_DOCS: dict[str, str] = {
    "third_party_endpoint_observed": "观察到地图/支付/推送等第三方服务端点（支持性）",
    "third_party_sdk_config_clue_observed": "观察到第三方 SDK 配置/初始化线索（仅形态）",
    "business_data_to_third_party_clue_observed": "观察到业务数据发送给第三方服务线索"
    "（仅形态，不代表超出功能必需或授权范围）",
    "payment_flow_marker_observed": "观察到支付流程调用标记（支持性；观察不改写支付，"
    "任何真实支付必须审批）",
    "platform_asset_marker_observed": "观察到平台共享/分配资产标记（仅形态）",
    "asset_attribution_mismatch_clue_observed": "观察到资产归属记录与平台标记不一致"
    "线索（仅形态）",
    "third_party_unauthorized_data_flow_confirmed": "已确认业务数据流向第三方且超出其"
    "功能必需或授权范围（既有只读证据复核且可复现）",
    "platform_shared_asset_misattributed_confirmed": "已确认平台共享资产被记录为自有"
    "资产（既有只读证据复核且可复现）",
}

# 红线常量（规格 1660 行；写入 artifact 与候选 precondition 语义）。
THIRD_PARTY_NO_PAYMENT_RULE: str = (
    "地图、支付、推送等第三方服务边界复核不触发真实支付、不产生任何写操作、不批量"
    "读取；默认只做材料、配置、授权流量和最小读验证，任何写入和真实支付必须审批"
)
THIRD_PARTY_ATTRIBUTION_RULE: str = (
    "平台共享资产不得误报为自有资产；attribution 归属枚举与 hosts 分类状态同源对齐"
)


def derive_evidence_kinds(evidence: Mapping[str, object]) -> list[str]:
    """观察键 → 证据形态（宿主通用实现，确定性）。"""
    return cloud_engine.derive_evidence_kinds(evidence, THIRD_PARTY_OBSERVATION_EVIDENCE_MAP)


def grade_boundary_observation(
    branch: str,
    evidence_kinds: Iterable[str],
    status_hint: str | None = None,
) -> str:
    """边界观察分级：确认形态满足 → candidate；否则 signal。status_hint 尊重人工
    判定（8 状态合法值原样返回）。宿主通用实现（单一来源）。"""
    return cloud_engine.grade_observation(
        branch,
        evidence_kinds,
        THIRD_PARTY_UPGRADE_RULES,
        THIRD_PARTY_EVIDENCE_KINDS,
        THIRD_PARTY_INSUFFICIENT_KINDS,
        status_hint,
    )


def build_third_party_boundary_row(
    observation: Mapping[str, object], index: int
) -> dict[str, str]:
    """第三方边界观察 → CSV 行（列与 THIRD_PARTY_CSV_FIELDS 一致；row_id 由序号
    确定性生成；boundary_status 由分支升级规则确定性分级，status_hint 尊重人工
    判定）。"""
    branch = str(observation.get("branch") or "").strip()
    kinds = derive_evidence_kinds(observation.get("evidence") or {})
    status = grade_boundary_observation(
        branch, kinds, str(observation.get("status_hint") or "") or None
    )
    return {
        "row_id": f"tp-{index:04d}",
        "service_name": str(observation.get("service_name") or "").strip(),
        "service_type": str(observation.get("service_type") or "").strip(),
        "host": str(observation.get("host") or "").strip(),
        "attribution": str(observation.get("attribution") or "").strip(),
        "boundary_status": status,
        "evidence_ref": str(observation.get("evidence_ref") or "").strip(),
        "reason": str(observation.get("reason") or "").strip(),
        "notes": str(observation.get("notes") or "").strip(),
        # precondition 不是 CSV 列（9 列契约形状）：仅随行 dict 供分支汇总使用，
        # render 按 THIRD_PARTY_CSV_FIELDS 拣选不会写入 CSV（candidate>0 的分支
        # 汇总要求 precondition 非空——统一筛选模式汇总行不变量）。
        "precondition": str(observation.get("precondition") or "").strip(),
    }


def validate_third_party_boundary_rows(rows: Iterable[Mapping[str, object]]) -> list[str]:
    """边界 CSV 行校验（与 skill audit 行校验语义一致）：service_type/attribution
    枚举 + boundary_status ∈ finding 8 状态 + 待确认归属行需非空 reason +
    candidate/needs_manual_validation 需 evidence_ref。"""
    violations: list[str] = []
    for index, row in enumerate(rows, start=1):
        if not isinstance(row, Mapping):
            violations.append(f"row {index}: 边界行必须是键值映射")
            continue
        service_type = str(row.get("service_type") or "").strip()
        if not service_type:
            violations.append(f"row {index}: service_type 为空")
        elif service_type not in THIRD_PARTY_SERVICE_TYPES:
            violations.append(
                f"row {index}: service_type 非法 {service_type!r}"
                f"（允许值 {list(THIRD_PARTY_SERVICE_TYPES)}）"
            )
        attribution = str(row.get("attribution") or "").strip()
        if not attribution:
            violations.append(f"row {index}: attribution 为空")
        elif attribution not in THIRD_PARTY_ATTRIBUTION_VALUES:
            violations.append(
                f"row {index}: attribution 非法 {attribution!r}"
                f"（允许值 {list(THIRD_PARTY_ATTRIBUTION_VALUES)}）"
            )
        boundary_status = str(row.get("boundary_status") or "").strip()
        if boundary_status and boundary_status not in ic.CANDIDATE_STATUS_VALUES:
            violations.append(
                f"row {index}: boundary_status 非法 {boundary_status!r}"
                f"（允许值 {list(ic.CANDIDATE_STATUS_VALUES)}）"
            )
        reason = str(row.get("reason") or "").strip()
        if attribution in THIRD_PARTY_PENDING_ATTRIBUTIONS and not reason:
            violations.append(
                f"row {index}: attribution {attribution!r} 需要非空 reason"
                "（待确认归属不得静默留空）"
            )
        if boundary_status in ("candidate", "needs_manual_validation") and not str(
            row.get("evidence_ref") or ""
        ).strip():
            violations.append(
                f"row {index}: boundary_status={boundary_status} 但 evidence_ref 为空"
                "（候选必须可证明）"
            )
    return violations


def screen_third_party_boundary_observations(
    observations: Iterable[Mapping[str, object]],
    all_branches: bool = True,
    label: str = "third_party_platform_boundary",
) -> tuple[list[dict], list[dict], list[str]]:
    """第三方边界复核筛选 → (边界 CSV 行, 分支汇总行, 违例)。

    观察必需键：branch（本域分支之一）、service_type、attribution；可选：
    service_name/host/notes/evidence/evidence_ref/reason/precondition/status_hint/
    observation_schema_version（缺失按当前版本，显式不符记违例）。
    分支汇总经 aggregate_category_status 单一引擎聚合（branch_status 六值；
    approval_required 仅由复核显式设置）。
    """
    rows: list[dict] = []
    na_counts: dict[str, int] = {}
    na_reasons: dict[str, list[str]] = {}
    applicable_counts_acc: dict[str, int] = {}
    unknown_counts_acc: dict[str, int] = {}
    branch_of_row: list[str] = []
    source_of_row: list[str] = []
    violations: list[str] = []
    for index, observation in enumerate(observations, start=1):
        if not isinstance(observation, Mapping):
            violations.append(f"{label}: 第 {index} 条观察必须是键值映射")
            continue
        obs_version = observation.get("observation_schema_version")
        if obs_version is not None and str(obs_version) != ic.OBSERVATION_SCHEMA_VERSION:
            violations.append(
                f"{label}: 第 {index} 条观察 observation_schema_version={obs_version!r} "
                f"与当前版本 {ic.OBSERVATION_SCHEMA_VERSION!r} 不符"
            )
        branch = str(observation.get("branch") or "").strip()
        if branch not in THIRD_PARTY_BRANCHES:
            violations.append(
                f"{label}: 第 {index} 条观察 branch 非法 {branch!r}（允许值 {list(THIRD_PARTY_BRANCHES)}）"
            )
            continue
        applicability = str(observation.get("applicability") or "unknown")
        if applicability not in ic.APPLICABLE_VALUES:
            violations.append(
                f"{label}: 第 {index} 条观察 applicability 非法 {applicability!r}"
                f"（允许值 {list(ic.APPLICABLE_VALUES)}）"
            )
            continue
        reason = str(observation.get("reason") or "").strip()
        if applicability == "not_applicable":
            na_counts[branch] = na_counts.get(branch, 0) + 1
            if reason:
                na_reasons.setdefault(branch, []).append(reason)
            else:
                violations.append(
                    f"{label}: 第 {index} 条观察 branch={branch} not_applicable 但 reason 为空"
                    "（没有理由的 not_applicable 是违例，coverage_substatus_schema 不变量）"
                )
            continue
        if applicability == "applicable":
            applicable_counts_acc[branch] = applicable_counts_acc.get(branch, 0) + 1
        else:
            unknown_counts_acc[branch] = unknown_counts_acc.get(branch, 0) + 1
        row = build_third_party_boundary_row(observation, len(rows) + 1)
        source = str(observation.get("source") or "").strip()
        if not source:
            violations.append(f"{label}: 第 {index} 条观察缺少来源 source")
        rows.append(row)
        branch_of_row.append(branch)
        source_of_row.append(source)
        violations += validate_third_party_boundary_rows([row])

    summary_branches = (
        list(THIRD_PARTY_BRANCHES)
        if all_branches
        else sorted(
            set(branch_of_row)
            | set(na_counts)
            | set(applicable_counts_acc)
            | set(unknown_counts_acc)
        )
    )
    summaries: list[dict] = []
    for branch in summary_branches:
        branch_rows = [row for row, b in zip(rows, branch_of_row) if b == branch]
        status_counts = {s: 0 for s in ic.CANDIDATE_STATUS_VALUES}
        for row in branch_rows:
            status_counts[row["boundary_status"]] += 1
        applicability_counts = {
            "applicable": applicable_counts_acc.get(branch, 0),
            "not_applicable": na_counts.get(branch, 0),
            "unknown": unknown_counts_acc.get(branch, 0),
        }
        tested_count = sum(status_counts[s] for s in ic.DEFINITIVE_RESULT_STATUSES)
        branch_status = ic.aggregate_category_status(
            [row["boundary_status"] for row in branch_rows], na_counts.get(branch, 0) > 0
        )
        reasons = [
            str(row.get("reason") or "")
            for row in branch_rows
            if row.get("reason")
        ]
        if na_reasons.get(branch):
            reasons += na_reasons[branch]
        summaries.append(
            {
                "branch": branch,
                "branch_status": branch_status,
                "applicability_counts": applicability_counts,
                "status_counts": status_counts,
                "tested_count": tested_count,
                "reason": "; ".join(reasons[:1]) if reasons else "本次筛选无该分支升级观察",
                "source": next(
                    (source for source, b in zip(source_of_row, branch_of_row) if b == branch and source),
                    "",
                ),
                "precondition": next(
                    (str(row.get("precondition") or "") for row in branch_rows if row.get("precondition")),
                    "",
                ),
            }
        )
        violations += cloud_engine.validate_branch_summary(
            summaries[-1], THIRD_PARTY_BRANCHES, label=f"{label}.summary[{branch}]"
        )
    return rows, summaries, violations


def render_third_party_boundary_csv(rows: Iterable[Mapping[str, object]]) -> str:
    """边界行 → CSV 文本（表头精确等于 THIRD_PARTY_CSV_FIELDS，顺序敏感；调用方
    负责校验并以 utf-8-sig 落盘）。"""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(THIRD_PARTY_CSV_FIELDS))
    writer.writeheader()
    for row in rows:
        writer.writerow({field: str(row.get(field) or "") for field in THIRD_PARTY_CSV_FIELDS})
    return buffer.getvalue()


def _cli() -> int:
    """离线 CLI：观察 JSON 文件 → 第三方边界 CSV（纯文件到文件；违例 fail-closed
    不落盘）。不发任何网络请求、不触发真实支付。"""
    import argparse
    import json
    from pathlib import Path

    parser = argparse.ArgumentParser(
        description="Offline third-party boundary review (no network, no writes, no "
        "real payments; minimal read verification only)."
    )
    parser.add_argument(
        "--observations", required=True,
        help="Observations JSON file (list or {observations: [...]})",
    )
    parser.add_argument("--out", required=True, help="Output CSV path")
    args = parser.parse_args()
    payload = json.loads(Path(args.observations).read_text(encoding="utf-8-sig"))
    observations = payload.get("observations", []) if isinstance(payload, dict) else payload
    if not isinstance(observations, list):
        print("ERROR: observations must be a list", flush=True)
        return 2
    rows, _summaries, violations = screen_third_party_boundary_observations(observations)
    violations += validate_third_party_boundary_rows(rows)
    if violations:
        for violation in violations:
            print(f"VIOLATION: {violation}", flush=True)
        print(f"rejected: {len(violations)} violation(s); nothing written", flush=True)
        return 2
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render_third_party_boundary_csv(rows), encoding="utf-8-sig")
    print(f"rows={len(rows)} out={out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
