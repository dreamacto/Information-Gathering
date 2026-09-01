"""签名重放离线复核域（实施规格 6.5 第三模块 1590 行，Batch 10）。

只读离线：复用 platform_login_exchange 的共享引擎（单一实现），本模块只定义签名
重放分支/证据形态/观察映射/升级规则常量与筛选入口。操作员指令红线（Batch 10
交接提示词）：signature_replay 只做离线重放假设与观察筛选，写操作/并发验证仍归
审批门——本模块不自动重放任何请求（读或写）、不发并发验证。观察输入为复核会话
从操作员提供的授权材料或本地流量提炼的结构化记录。

四分支（与 contracts/miniapp_auth_schema.json phases.signature_replay.branches
同源；规格 6.5 覆盖清单：nonce/timestamp；签名规范化和重放；设备、用户、租户
绑定）：
- nonce_timestamp：nonce/timestamp 使用（缺失/时间窗/同 nonce 重复接受）；
- signature_canonicalization：签名规范化（规范化未定义或歧义导致的可变体）；
- replay_window：重放窗口（同一签名请求重放被接受/窗口控制）；
- binding_scope：签名的设备/用户/租户上下文绑定。

与 session_token_lifecycle.device_user_tenant_binding 的边界（避免双计）：本域
binding_scope 仅针对"签名/nonce 的上下文绑定"（同一签名是否能跨上下文复用）；
token 自身的设备/用户/租户绑定归 session_token_lifecycle，按观察对象区分。

升级边界（实现定义供操作者复核）：仅对应分支的确认证据（*_confirmed，来自既有
只读证据的复核判定且可复现——不是实际重放成功的记录）可升级 candidate；"请求
被接受/机制标记存在/绑定缺失线索"等形态与支持性观察永不升级（signal 不是漏洞）。
confirmed 五门判定仍归 finding_quality_gate；本模块只做候选层分级校验。
"""
from __future__ import annotations

from typing import Iterable, Mapping

from authorized_assessment.miniapp import platform_login_exchange as auth_engine

# 四分支（契约 phases.signature_replay.branches 同源）。
SIGNATURE_REPLAY_BRANCHES: tuple[str, ...] = (
    "nonce_timestamp",
    "signature_canonicalization",
    "replay_window",
    "binding_scope",
)

# 证据形态（12：8 形态/支持性永不升级 + 4 确认形态与分支一一对应）。
SIGNATURE_REPLAY_EVIDENCE_KINDS: tuple[str, ...] = (
    "nonce_missing_observed",
    "timestamp_window_marker_observed",
    "canonicalization_ambiguous_observed",
    "signature_field_marker_observed",
    "replay_accepted_observed",
    "replay_cache_marker_observed",
    "signature_binding_absent_observed",
    "signature_binding_marker_observed",
    "same_nonce_accepted_confirmed",
    "signature_malleability_confirmed",
    "signature_replay_impact_confirmed",
    "signature_cross_context_confirmed",
)

# "不算漏洞"证据形态：仅形态/支持性观察，未证明服务端重放边界失效。
SIGNATURE_REPLAY_INSUFFICIENT_KINDS: tuple[str, ...] = (
    "nonce_missing_observed",
    "timestamp_window_marker_observed",
    "canonicalization_ambiguous_observed",
    "signature_field_marker_observed",
    "replay_accepted_observed",
    "replay_cache_marker_observed",
    "signature_binding_absent_observed",
    "signature_binding_marker_observed",
)

# 升级规则（实现定义，固定语义；确认形态与分支一一对应、不跨分支升级）：
# "确认"语义要求观察来自既有只读证据的复核判定且可复现（不是本模块实际重放）；
# 本模块不自动重放任何请求、不发并发验证（写操作/并发验证归审批门，precondition
# 必须留痕）。
SIGNATURE_REPLAY_UPGRADE_RULES: dict[str, dict[str, tuple[tuple[str, ...], ...]]] = {
    "nonce_timestamp": {
        "required_any_groups": (("same_nonce_accepted_confirmed",),)
    },
    "signature_canonicalization": {
        "required_any_groups": (("signature_malleability_confirmed",),)
    },
    "replay_window": {
        "required_any_groups": (("signature_replay_impact_confirmed",),)
    },
    "binding_scope": {
        "required_any_groups": (("signature_cross_context_confirmed",),)
    },
}

# v1 观察键 → 证据形态（确定性映射；版本化演进同 OBSERVATION_SCHEMA_VERSION）。
SIGNATURE_REPLAY_OBSERVATION_EVIDENCE_MAP: dict[str, str] = {
    "nonce_missing_observed": "nonce_missing_observed",
    "timestamp_window_marker_observed": "timestamp_window_marker_observed",
    "canonicalization_ambiguous_observed": "canonicalization_ambiguous_observed",
    "signature_field_marker_observed": "signature_field_marker_observed",
    "replay_accepted_observed": "replay_accepted_observed",
    "replay_cache_marker_observed": "replay_cache_marker_observed",
    "signature_binding_absent_observed": "signature_binding_absent_observed",
    "signature_binding_marker_observed": "signature_binding_marker_observed",
    "same_nonce_accepted_confirmed": "same_nonce_accepted_confirmed",
    "signature_malleability_confirmed": "signature_malleability_confirmed",
    "signature_replay_impact_confirmed": "signature_replay_impact_confirmed",
    "signature_cross_context_confirmed": "signature_cross_context_confirmed",
}

SIGNATURE_REPLAY_OBSERVATION_FIELD_DOCS: dict[str, str] = {
    "nonce_missing_observed": "请求未见 nonce 参数（缺失≠不存在，仅形态）",
    "timestamp_window_marker_observed": "观察到 timestamp 时间窗校验标记（支持性，正向线索）",
    "canonicalization_ambiguous_observed": "签名规范化未定义或存在歧义线索（参数排序/"
    "编码变体，仅形态）",
    "signature_field_marker_observed": "观察到签名字段/签名算法标记（支持性，正向线索）",
    "replay_accepted_observed": "观察到同一签名请求的重复提交被服务端接受（仅形态，"
    "不代表服务端状态重复变更）",
    "replay_cache_marker_observed": "观察到重放缓存/序列号/一次性标记（支持性，正向线索）",
    "signature_binding_absent_observed": "未见签名携带设备/用户/租户上下文绑定线索"
    "（缺失≠不存在，仅形态）",
    "signature_binding_marker_observed": "观察到签名上下文绑定标记（设备指纹/租户 ID "
    "入签等，支持性，正向线索）",
    "same_nonce_accepted_confirmed": "已确认同一 nonce 在多个不同请求中被服务端接受"
    "（既有只读证据复核且可复现；本模块不实际重放）",
    "signature_malleability_confirmed": "已确认签名可变体（参数重排/编码变换后签名"
    "仍有效）跨请求复用（既有只读证据复核且可复现）",
    "signature_replay_impact_confirmed": "已确认签名重放产生服务端状态影响（重复消费/"
    "重复提交生效等，既有只读证据复核且可复现；写操作/并发验证归审批门）",
    "signature_cross_context_confirmed": "已确认同一签名可跨设备/用户/租户上下文复用"
    "（既有只读证据复核且可复现）",
}

# 红线常量（操作员指令 + 规格 1610 行；写入 artifact 与候选 precondition）。
SIGNATURE_REPLAY_OFFLINE_RULE: str = (
    "签名重放只做离线重放假设与观察筛选；不自动重放任何请求（读或写），写操作/"
    "并发验证归审批门"
)
SIGNATURE_REPLAY_MATERIAL_RULE: str = (
    "签名材料仅来自操作员提供的授权材料或本地流量；不自动创建或滥用登录凭证"
)


def screen_signature_replay_observations(
    observations: Iterable[Mapping[str, object]],
    all_branches: bool = True,
    label: str = "signature_replay",
) -> tuple[list[dict], list[dict], list[str]]:
    """签名重放复核筛选 → (候选行, 分支汇总行, 违例)。"""
    return auth_engine.screen_auth_observations(
        observations,
        SIGNATURE_REPLAY_BRANCHES,
        SIGNATURE_REPLAY_OBSERVATION_EVIDENCE_MAP,
        SIGNATURE_REPLAY_EVIDENCE_KINDS,
        SIGNATURE_REPLAY_INSUFFICIENT_KINDS,
        SIGNATURE_REPLAY_UPGRADE_RULES,
        all_branches=all_branches,
        label=label,
    )


def validate_signature_replay_candidate(
    row: Mapping[str, object], label: str = "signature_replay_candidate"
) -> list[str]:
    return auth_engine.validate_auth_review_row(
        row,
        SIGNATURE_REPLAY_BRANCHES,
        SIGNATURE_REPLAY_EVIDENCE_KINDS,
        SIGNATURE_REPLAY_INSUFFICIENT_KINDS,
        SIGNATURE_REPLAY_UPGRADE_RULES,
        label=label,
    )


def build_signature_replay_review_artifact(
    rows: Iterable[Mapping[str, object]],
    summaries: Iterable[Mapping[str, object]],
    violations: Iterable[str],
    authorization_basis: str,
    updated_at: str,
    substatuses: Mapping[str, str] | None = None,
) -> dict:
    return auth_engine.build_auth_review_artifact(
        "signature_replay",
        rows,
        summaries,
        violations,
        authorization_basis,
        updated_at,
        substatuses=substatuses,
    )


def validate_signature_replay_review_artifact(
    artifact: Mapping[str, object], label: str = "signature_replay_review_artifact"
) -> list[str]:
    return auth_engine.validate_auth_review_artifact(
        artifact,
        "signature_replay",
        SIGNATURE_REPLAY_BRANCHES,
        SIGNATURE_REPLAY_EVIDENCE_KINDS,
        SIGNATURE_REPLAY_INSUFFICIENT_KINDS,
        SIGNATURE_REPLAY_UPGRADE_RULES,
        label=label,
    )


def _cli() -> int:
    """离线 CLI：观察 JSON 文件 → auth review artifact JSON（纯文件到文件）。"""
    import argparse
    import json
    from datetime import datetime
    from pathlib import Path

    parser = argparse.ArgumentParser(
        description="Offline signature replay review (no network, no request replay)."
    )
    parser.add_argument("--observations", required=True, help="Observations JSON file (list or {observations: [...]})")
    parser.add_argument("--out", required=True, help="Output artifact JSON path")
    parser.add_argument(
        "--authorization-basis",
        default="operator_supplied_material",
        choices=list(auth_engine.AUTHORIZATION_BASIS_VALUES),
    )
    args = parser.parse_args()
    payload = json.loads(Path(args.observations).read_text(encoding="utf-8-sig"))
    observations = payload.get("observations", []) if isinstance(payload, dict) else payload
    if not isinstance(observations, list):
        print("ERROR: observations must be a list", flush=True)
        return 2
    rows, summaries, violations = screen_signature_replay_observations(observations)
    artifact = build_signature_replay_review_artifact(
        rows,
        summaries,
        violations,
        authorization_basis=args.authorization_basis,
        updated_at=datetime.now().astimezone().isoformat(timespec="seconds"),
    )
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(artifact, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"rows={len(artifact['rows'])} summaries={len(artifact['summaries'])} "
          f"violations={len(artifact['violations'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
