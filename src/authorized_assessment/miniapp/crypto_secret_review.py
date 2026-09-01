"""密码学与密钥处理复核域（实施规格 6.6 1612-1633 行 + 6.2 拆分 1499-1534 行，
Batch 11）。

只读离线：复用 package_integrity_update 承载的 Batch 11 共享引擎（统一筛选模式：
观察键→证据形态确定性映射→rule_satisfied 升级判定→8 状态分级），本模块只定义
密码学与密钥处理分支/证据形态/观察映射/升级规则常量与筛选入口。不发任何请求、
不读取凭证文件、不复制密钥/AppSecret 原文到普通日志/报告/prompt/ledger/交接
内容；不做密钥有效性的主动验证——有效性确认只来自既有只读证据（包源码/清单/
本地流量）的复核（红线常量留痕）。

四分支（与 contracts/miniapp_storage_package_schema.json phases.crypto_and_secret_
handling.branches 同源；规格 6.6 检查项四至六项逐一对应 + batch11_0 去重分配）：
- hardcoded_secrets：AppSecret、固定 token、密钥硬编码；
- custom_crypto：自定义加密；
- weak_random_key_derivation：弱随机数、密钥派生；
- debug_config_env_keys：包中调试配置和环境密钥（只覆盖密钥材料暴露面；调试
  开关本身归 package_integrity_update_review.debug_switches，契约 invariant 留痕，
  避免重复计数）。

secret_candidate 红线（规格 1633 行）："发现密钥字符串但无法证明有效性时只能是
secret_candidate，不能直接称为密钥泄露漏洞"。落地方式：secret_candidate 是未证实
线索的台账语义，不是 finding 8 状态（8 状态模型被契约三方锁定，不新增状态）；
未证实密钥字符串在候选层记 status=signal（仅形态观察永不升级），只有密钥有效性
被既有只读证据确认（服务端接受/可达使用点，可复现）才升级 candidate；confirmed
五门判定仍归 finding_quality_gate。
"""
from __future__ import annotations

from typing import Iterable, Mapping

from authorized_assessment.miniapp import package_integrity_update as sp_engine

# 四分支（契约 phases.crypto_and_secret_handling.branches 同源）。
CRYPTO_SECRET_BRANCHES: tuple[str, ...] = (
    "hardcoded_secrets",
    "custom_crypto",
    "weak_random_key_derivation",
    "debug_config_env_keys",
)

# 证据形态（12：8 形态/支持性永不升级 + 4 确认形态与分支一一对应）。
CRYPTO_SECRET_EVIDENCE_KINDS: tuple[str, ...] = (
    "secret_like_string_observed",
    "secret_reference_marker_observed",
    "custom_crypto_code_observed",
    "custom_crypto_usage_marker_observed",
    "weak_random_call_observed",
    "key_derivation_marker_observed",
    "env_key_in_config_observed",
    "debug_config_key_clue_observed",
    "secret_reachable_confirmed",
    "custom_crypto_bypassable_confirmed",
    "predictable_random_confirmed",
    "env_key_accepted_confirmed",
)

# "不算漏洞"证据形态：仅形态/支持性观察——密钥字符串未经有效性确认时只能是
# secret_candidate（未证实线索，8 状态记 signal），不能直接称为密钥泄露漏洞。
CRYPTO_SECRET_INSUFFICIENT_KINDS: tuple[str, ...] = (
    "secret_like_string_observed",
    "secret_reference_marker_observed",
    "custom_crypto_code_observed",
    "custom_crypto_usage_marker_observed",
    "weak_random_call_observed",
    "key_derivation_marker_observed",
    "env_key_in_config_observed",
    "debug_config_key_clue_observed",
)

# 升级规则（实现定义，固定语义；确认形态与分支一一对应、不跨分支升级）：
# "确认"语义要求观察来自既有只读证据（包源码/清单/本地流量）的复核判定且可
# 复现；不主动验证密钥有效性、不发送请求、不复制密钥原文（precondition 必须
# 留痕）。
CRYPTO_SECRET_UPGRADE_RULES: dict[str, dict[str, tuple[tuple[str, ...], ...]]] = {
    "hardcoded_secrets": {
        "required_any_groups": (("secret_reachable_confirmed",),)
    },
    "custom_crypto": {
        "required_any_groups": (("custom_crypto_bypassable_confirmed",),)
    },
    "weak_random_key_derivation": {
        "required_any_groups": (("predictable_random_confirmed",),)
    },
    "debug_config_env_keys": {
        "required_any_groups": (("env_key_accepted_confirmed",),)
    },
}

# v1 观察键 → 证据形态（确定性映射；版本化演进同 OBSERVATION_SCHEMA_VERSION）。
CRYPTO_SECRET_OBSERVATION_EVIDENCE_MAP: dict[str, str] = {
    key: key for key in CRYPTO_SECRET_EVIDENCE_KINDS
}

CRYPTO_SECRET_OBSERVATION_FIELD_DOCS: dict[str, str] = {
    "secret_like_string_observed": "观察到疑似密钥/AppSecret/固定 token 字符串"
    "（仅形态——secret_candidate 线索，未证实有效性不得升级）",
    "secret_reference_marker_observed": "观察到密钥引用/加载点标记（支持性）",
    "custom_crypto_code_observed": "观察到自定义加密实现代码（仅形态）",
    "custom_crypto_usage_marker_observed": "观察到自定义加密调用点标记（支持性）",
    "weak_random_call_observed": "观察到弱随机数调用（Math.random/time 种子等）"
    "（仅形态）",
    "key_derivation_marker_observed": "观察到密钥派生/固定盐标记（仅形态）",
    "env_key_in_config_observed": "观察到配置中的环境密钥字段（仅形态）",
    "debug_config_key_clue_observed": "观察到调试配置中密钥相关线索（仅形态）",
    "secret_reachable_confirmed": "已确认硬编码密钥被服务端接受或到达可达使用点且"
    "产生实际权限（既有只读证据复核且可复现；不主动验证、不复制密钥原文）",
    "custom_crypto_bypassable_confirmed": "已确认自定义加密可被标准工具复原或绕过"
    "且保护的数据可读（既有只读证据复核且可复现）",
    "predictable_random_confirmed": "已确认随机数/派生输出可预测并影响密钥或凭证"
    "强度（既有只读证据复核且可复现）",
    "env_key_accepted_confirmed": "已确认环境密钥真实有效且被客户端用于敏感决策"
    "（既有只读证据复核且可复现；不主动验证）",
}

# 红线常量（规格 6.6 1633 行原文 + 凭证纪律；写入 artifact 与候选 precondition）。
SECRET_CANDIDATE_RED_LINE: str = (
    "发现密钥字符串但无法证明有效性时只能是 secret_candidate（未证实线索，"
    "8 状态模型记 signal），不能直接称为密钥泄露漏洞"
)
CRYPTO_MATERIAL_RULE: str = (
    "密钥与加密复核仅使用操作员提供的授权材料或包副本的既有只读证据；不主动"
    "验证密钥有效性、不发送请求、不读取凭证文件、不复制密钥/AppSecret 原文到"
    "普通日志、报告、prompt、ledger 或交接内容"
)


def screen_crypto_secret_observations(
    observations: Iterable[Mapping[str, object]],
    all_branches: bool = True,
    label: str = "crypto_and_secret_handling",
) -> tuple[list[dict], list[dict], list[str]]:
    """密码学与密钥处理复核筛选 → (候选行, 分支汇总行, 违例)。"""
    return sp_engine.screen_observations(
        observations,
        CRYPTO_SECRET_BRANCHES,
        CRYPTO_SECRET_OBSERVATION_EVIDENCE_MAP,
        CRYPTO_SECRET_EVIDENCE_KINDS,
        CRYPTO_SECRET_INSUFFICIENT_KINDS,
        CRYPTO_SECRET_UPGRADE_RULES,
        all_branches=all_branches,
        label=label,
    )


def validate_crypto_secret_candidate(
    row: Mapping[str, object], label: str = "crypto_secret_candidate"
) -> list[str]:
    return sp_engine.validate_review_row(
        row,
        CRYPTO_SECRET_BRANCHES,
        CRYPTO_SECRET_EVIDENCE_KINDS,
        CRYPTO_SECRET_INSUFFICIENT_KINDS,
        CRYPTO_SECRET_UPGRADE_RULES,
        label=label,
    )


def build_crypto_secret_review_artifact(
    rows: Iterable[Mapping[str, object]],
    summaries: Iterable[Mapping[str, object]],
    violations: Iterable[str],
    authorization_basis: str,
    updated_at: str,
    substatuses: Mapping[str, str] | None = None,
) -> dict:
    return sp_engine.build_storage_package_review_artifact(
        "crypto_and_secret_handling",
        rows,
        summaries,
        violations,
        authorization_basis,
        updated_at,
        substatuses=substatuses,
    )


def validate_crypto_secret_review_artifact(
    artifact: Mapping[str, object], label: str = "crypto_secret_review_artifact"
) -> list[str]:
    return sp_engine.validate_storage_package_review_artifact(
        artifact,
        "crypto_and_secret_handling",
        CRYPTO_SECRET_BRANCHES,
        CRYPTO_SECRET_EVIDENCE_KINDS,
        CRYPTO_SECRET_INSUFFICIENT_KINDS,
        CRYPTO_SECRET_UPGRADE_RULES,
        label=label,
    )


def _cli() -> int:
    """离线 CLI：观察 JSON 文件 → review artifact JSON（纯文件到文件）。"""
    import argparse
    import json
    from datetime import datetime
    from pathlib import Path

    parser = argparse.ArgumentParser(
        description="Offline crypto and secret handling review (no network, no credential "
        "files, no key value export; unproven secret strings stay secret_candidate clues)."
    )
    parser.add_argument("--observations", required=True, help="Observations JSON file (list or {observations: [...]})")
    parser.add_argument("--out", required=True, help="Output artifact JSON path")
    parser.add_argument(
        "--authorization-basis",
        default="operator_supplied_material",
        choices=list(sp_engine.AUTHORIZATION_BASIS_VALUES),
    )
    args = parser.parse_args()
    payload = json.loads(Path(args.observations).read_text(encoding="utf-8-sig"))
    observations = payload.get("observations", []) if isinstance(payload, dict) else payload
    if not isinstance(observations, list):
        print("ERROR: observations must be a list", flush=True)
        return 2
    rows, summaries, violations = screen_crypto_secret_observations(observations)
    artifact = build_crypto_secret_review_artifact(
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
