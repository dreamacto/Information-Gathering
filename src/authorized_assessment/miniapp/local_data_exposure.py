"""本地数据暴露复核域（实施规格 6.6 1612-1633 行 + 6.2 拆分 1499-1534 行，Batch 11）。

只读离线：复用 package_integrity_update 承载的 Batch 11 共享引擎（统一筛选模式：
观察键→证据形态确定性映射→rule_satisfied 升级判定→8 状态分级），本模块只定义
本地数据暴露分支/证据形态/观察映射/升级规则常量与筛选入口。不发任何请求、不
读取凭证文件、不导出敏感数据原文——观察输入为复核会话从操作员提供的授权材料、
本地流量或包副本提炼的结构化记录；token/AppSecret/密钥原文等敏感值不得复制到
普通日志、报告、prompt、ledger 或交接内容（凭证纪律，红线常量留痕）。

五分支（与 contracts/miniapp_storage_package_schema.json phases.local_data_exposure.
branches 同源；规格 6.6 检查项前三项逐一对应）：
- token_persistence：token 是否落地；
- logout_cleanup：logout 是否清理；
- local_cache_database：本地缓存、数据库；
- logs_clipboard_screenshots：日志、剪贴板、截图；
- temp_files：临时文件。

升级边界（实现定义供操作者复核）：仅对应分支的确认证据（*_confirmed，来自既有
只读证据的复核判定且可复现）可升级 candidate；"存储键存在/缓存目录线索/清理
代码缺失"等形态与支持性观察永不升级（signal 不是漏洞）。confirmed 五门判定仍归
finding_quality_gate；本模块只做候选层分级校验。
"""
from __future__ import annotations

from typing import Iterable, Mapping

from authorized_assessment.miniapp import package_integrity_update as sp_engine

# 五分支（契约 phases.local_data_exposure.branches 同源）。
LOCAL_DATA_BRANCHES: tuple[str, ...] = (
    "token_persistence",
    "logout_cleanup",
    "local_cache_database",
    "logs_clipboard_screenshots",
    "temp_files",
)

# 证据形态（15：10 形态/支持性永不升级 + 5 确认形态与分支一一对应）。
LOCAL_DATA_EVIDENCE_KINDS: tuple[str, ...] = (
    "token_storage_key_observed",
    "token_value_persisted_observed",
    "logout_cleanup_code_observed",
    "residual_data_after_logout_observed",
    "cache_directory_clue_observed",
    "local_database_record_clue_observed",
    "log_sensitive_field_observed",
    "clipboard_write_marker_observed",
    "screenshot_capture_marker_observed",
    "temp_file_retention_clue_observed",
    "token_survives_logout_confirmed",
    "cross_account_cache_reuse_confirmed",
    "database_sensitive_rows_confirmed",
    "log_or_clipboard_leak_confirmed",
    "temp_file_sensitive_content_confirmed",
)

# "不算漏洞"证据形态：仅形态/支持性观察，未证明本地数据边界失效。
LOCAL_DATA_INSUFFICIENT_KINDS: tuple[str, ...] = (
    "token_storage_key_observed",
    "token_value_persisted_observed",
    "logout_cleanup_code_observed",
    "residual_data_after_logout_observed",
    "cache_directory_clue_observed",
    "local_database_record_clue_observed",
    "log_sensitive_field_observed",
    "clipboard_write_marker_observed",
    "screenshot_capture_marker_observed",
    "temp_file_retention_clue_observed",
)

# 升级规则（实现定义，固定语义；确认形态与分支一一对应、不跨分支升级）：
# "确认"语义要求观察来自既有只读证据（本地副本/流量/包源码）的复核判定且可复现；
# 禁止为取得确认而批量导出、下载或复制敏感数据原文（凭证/敏感数据纪律，
# precondition 必须留痕）。
LOCAL_DATA_UPGRADE_RULES: dict[str, dict[str, tuple[tuple[str, ...], ...]]] = {
    "token_persistence": {
        "required_any_groups": (("token_survives_logout_confirmed",),)
    },
    "logout_cleanup": {
        "required_any_groups": (("token_survives_logout_confirmed",),)
    },
    "local_cache_database": {
        "required_any_groups": (
            ("cross_account_cache_reuse_confirmed", "database_sensitive_rows_confirmed"),
        )
    },
    "logs_clipboard_screenshots": {
        "required_any_groups": (("log_or_clipboard_leak_confirmed",),)
    },
    "temp_files": {
        "required_any_groups": (("temp_file_sensitive_content_confirmed",),)
    },
}

# v1 观察键 → 证据形态（确定性映射；版本化演进同 OBSERVATION_SCHEMA_VERSION）。
LOCAL_DATA_OBSERVATION_EVIDENCE_MAP: dict[str, str] = {
    key: key for key in LOCAL_DATA_EVIDENCE_KINDS
}

LOCAL_DATA_OBSERVATION_FIELD_DOCS: dict[str, str] = {
    "token_storage_key_observed": "观察到本地存储/缓存中存在 token 相关键名（仅形态，"
    "不代表敏感值落地）",
    "token_value_persisted_observed": "观察到 token 值被写入本地存储/缓存线索（仅形态）",
    "logout_cleanup_code_observed": "观察到 logout 清理代码路径（支持性，正向线索）",
    "residual_data_after_logout_observed": "观察到注销后本地残留数据线索（仅形态）",
    "cache_directory_clue_observed": "观察到本地缓存目录/文件线索（仅形态）",
    "local_database_record_clue_observed": "观察到本地数据库/结构化存储记录线索"
    "（仅形态）",
    "log_sensitive_field_observed": "观察到日志/输出包含敏感字段名线索（仅形态）",
    "clipboard_write_marker_observed": "观察到剪贴板写入调用标记（仅形态）",
    "screenshot_capture_marker_observed": "观察到截图/屏幕捕获调用标记（仅形态）",
    "temp_file_retention_clue_observed": "观察到临时文件保留/未清理线索（仅形态）",
    "token_survives_logout_confirmed": "已确认注销/切换账号后 token 仍留在本地存储且"
    "可被再次使用（既有只读证据复核且可复现；不读取或导出凭证值）",
    "cross_account_cache_reuse_confirmed": "已确认跨账号缓存/数据库记录复用可复现"
    "（既有只读证据复核且可复现）",
    "database_sensitive_rows_confirmed": "已确认本地数据库保存敏感记录且无访问控制"
    "（既有只读证据复核且可复现；不导出记录原文）",
    "log_or_clipboard_leak_confirmed": "已确认日志/剪贴板/截图内容含敏感数据且可被"
    "其他应用或进程读取（既有只读证据复核且可复现）",
    "temp_file_sensitive_content_confirmed": "已确认临时文件含敏感数据且保留到会话"
    "之外（既有只读证据复核且可复现）",
}

# 红线常量（规格 6.6 + 凭证纪律；写入 artifact 与候选 precondition 语义）。
LOCAL_DATA_MATERIAL_RULE: str = (
    "本地数据复核仅使用操作员提供的授权材料、本地流量或包副本；不读取凭证文件、"
    "不导出敏感数据原文，token/密钥等敏感值不复制到普通日志、报告、prompt、"
    "ledger 或交接内容"
)


def screen_local_data_observations(
    observations: Iterable[Mapping[str, object]],
    all_branches: bool = True,
    label: str = "local_data_exposure",
) -> tuple[list[dict], list[dict], list[str]]:
    """本地数据暴露复核筛选 → (候选行, 分支汇总行, 违例)。"""
    return sp_engine.screen_observations(
        observations,
        LOCAL_DATA_BRANCHES,
        LOCAL_DATA_OBSERVATION_EVIDENCE_MAP,
        LOCAL_DATA_EVIDENCE_KINDS,
        LOCAL_DATA_INSUFFICIENT_KINDS,
        LOCAL_DATA_UPGRADE_RULES,
        all_branches=all_branches,
        label=label,
    )


def validate_local_data_candidate(
    row: Mapping[str, object], label: str = "local_data_candidate"
) -> list[str]:
    return sp_engine.validate_review_row(
        row,
        LOCAL_DATA_BRANCHES,
        LOCAL_DATA_EVIDENCE_KINDS,
        LOCAL_DATA_INSUFFICIENT_KINDS,
        LOCAL_DATA_UPGRADE_RULES,
        label=label,
    )


def build_local_data_review_artifact(
    rows: Iterable[Mapping[str, object]],
    summaries: Iterable[Mapping[str, object]],
    violations: Iterable[str],
    authorization_basis: str,
    updated_at: str,
    substatuses: Mapping[str, str] | None = None,
) -> dict:
    return sp_engine.build_storage_package_review_artifact(
        "local_data_exposure",
        rows,
        summaries,
        violations,
        authorization_basis,
        updated_at,
        substatuses=substatuses,
    )


def validate_local_data_review_artifact(
    artifact: Mapping[str, object], label: str = "local_data_review_artifact"
) -> list[str]:
    return sp_engine.validate_storage_package_review_artifact(
        artifact,
        "local_data_exposure",
        LOCAL_DATA_BRANCHES,
        LOCAL_DATA_EVIDENCE_KINDS,
        LOCAL_DATA_INSUFFICIENT_KINDS,
        LOCAL_DATA_UPGRADE_RULES,
        label=label,
    )


def _cli() -> int:
    """离线 CLI：观察 JSON 文件 → review artifact JSON（纯文件到文件）。"""
    import argparse
    import json
    from datetime import datetime
    from pathlib import Path

    parser = argparse.ArgumentParser(
        description="Offline local data exposure review (no network, no credential files, "
        "no sensitive value export)."
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
    rows, summaries, violations = screen_local_data_observations(observations)
    artifact = build_local_data_review_artifact(
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
