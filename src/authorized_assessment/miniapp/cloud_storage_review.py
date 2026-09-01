"""对象存储 ACL 复核域（实施规格 6.7 1635-1660 行 + 6.2 拆分 1528-1534 行，
Batch 12）。

只读离线：薄模块，扇形 import 复用 cloud_function_review 承载的 Batch 12 共享引擎
（统一筛选模式：观察键→证据形态确定性映射→rule_satisfied 升级判定→8 状态分级）
与 miniapp_cloud 契约 12 键形状 build/validate；本模块只定义 cloud_storage_acl_
testing phase 的分支/证据形态/观察映射/升级规则常量与筛选入口。不发任何请求、不
批量读取对象、不下载对象内容——签名 URL 验证仅最小读验证（规格 1660 行红线，
CLOUD_STORAGE_NO_BULK_READ_RULE 留痕）。观察输入为复核会话从操作员提供的授权
材料、本地流量或云配置/策略副本提炼的结构化记录。

三分支（与 contracts/miniapp_cloud_schema.json phases.cloud_storage_acl_testing.
branches 同源；规格 6.7 覆盖清单 ACL 域三项逐一对应；云数据库规则归 ACL 域——
数据库权限规则即访问控制规则，batch12_0 卡片出入留痕 3）：
- cloud_database_rules：云数据库规则；
- object_storage_acl：对象存储 ACL；
- signed_url_binding：签名 URL 过期、路径绑定和跨对象访问（单分支覆盖三子项，
  证据形态区分，升级规则任一组满足）。

升级边界（实现定义供操作者复核）：仅对应分支的确认证据（*_confirmed，来自既有
只读证据的复核判定且可复现）可升级 candidate；"ACL 公共标记/列举标记/长过期
标记/无路径绑定线索"等形态与支持性观察永不升级（signal 不是漏洞）。confirmed
五门判定仍归 finding_quality_gate；本模块只做候选层分级校验。
"""
from __future__ import annotations

from typing import Iterable, Mapping

from authorized_assessment.miniapp import cloud_function_review as cloud_engine

# 三分支（契约 phases.cloud_storage_acl_testing.branches 同源）。
CLOUD_STORAGE_BRANCHES: tuple[str, ...] = (
    "cloud_database_rules",
    "object_storage_acl",
    "signed_url_binding",
)

# 证据形态（10：6 形态/支持性永不升级 + 4 确认形态）。
CLOUD_STORAGE_EVIDENCE_KINDS: tuple[str, ...] = (
    "db_rule_open_marker_observed",
    "db_collection_permission_clue_observed",
    "storage_acl_public_marker_observed",
    "storage_listing_marker_observed",
    "signed_url_long_expiry_observed",
    "signed_url_no_path_binding_clue_observed",
    "db_rule_unauthorized_access_confirmed",
    "object_acl_unauthorized_access_confirmed",
    "signed_url_expiry_not_enforced_confirmed",
    "signed_url_cross_object_confirmed",
)

# "不算漏洞"证据形态：仅形态/支持性观察，未证明 ACL/签名边界失效。
CLOUD_STORAGE_INSUFFICIENT_KINDS: tuple[str, ...] = (
    "db_rule_open_marker_observed",
    "db_collection_permission_clue_observed",
    "storage_acl_public_marker_observed",
    "storage_listing_marker_observed",
    "signed_url_long_expiry_observed",
    "signed_url_no_path_binding_clue_observed",
)

# 升级规则（实现定义，固定语义；确认形态与分支对应、不跨分支升级）：
# "确认"语义要求观察来自既有只读证据（授权材料/本地流量/策略副本）的复核判定且
# 可复现；签名 URL 跨对象证明仅以最小读验证记录，不批量读取、不下载对象内容
# （规格 1660 红线，precondition 必须留痕）。
CLOUD_STORAGE_UPGRADE_RULES: dict[str, dict[str, tuple[tuple[str, ...], ...]]] = {
    "cloud_database_rules": {
        "required_any_groups": (("db_rule_unauthorized_access_confirmed",),)
    },
    "object_storage_acl": {
        "required_any_groups": (("object_acl_unauthorized_access_confirmed",),)
    },
    "signed_url_binding": {
        "required_any_groups": (
            ("signed_url_expiry_not_enforced_confirmed", "signed_url_cross_object_confirmed"),
        )
    },
}

# v1 观察键 → 证据形态（确定性映射；版本化演进同 OBSERVATION_SCHEMA_VERSION）。
CLOUD_STORAGE_OBSERVATION_EVIDENCE_MAP: dict[str, str] = {
    key: key for key in CLOUD_STORAGE_EVIDENCE_KINDS
}

CLOUD_STORAGE_OBSERVATION_FIELD_DOCS: dict[str, str] = {
    "db_rule_open_marker_observed": "观察到云数据库权限规则显示 open/任意读写标记"
    "（仅形态，不代表未授权读写可达）",
    "db_collection_permission_clue_observed": "观察到集合级权限配置线索（支持性）",
    "storage_acl_public_marker_observed": "观察到对象存储 ACL/策略显示公共读或公共写"
    "标记（仅形态）",
    "storage_listing_marker_observed": "观察到存储列举权限开启标记（支持性）",
    "signed_url_long_expiry_observed": "观察到签名 URL 过期时间过长标记（仅形态）",
    "signed_url_no_path_binding_clue_observed": "观察到签名未绑定对象路径/资源线索"
    "（仅形态）",
    "db_rule_unauthorized_access_confirmed": "已确认未经授权身份可读写云数据库集合"
    "（既有只读证据复核且可复现；不批量读取记录）",
    "object_acl_unauthorized_access_confirmed": "已确认未经授权身份可读取对象（既有"
    "只读证据复核且可复现；不下载对象内容）",
    "signed_url_expiry_not_enforced_confirmed": "已确认签名 URL 过期不生效（既有只读"
    "证据复核且可复现）",
    "signed_url_cross_object_confirmed": "已确认签名可复用/替换路径取得其他对象"
    "（既有只读证据复核且可复现；仅最小读验证，不批量读取）",
}

# 红线常量（规格 1660 行；写入 artifact 与候选 precondition 语义）。
CLOUD_STORAGE_NO_BULK_READ_RULE: str = (
    "签名 URL 验证不批量读取对象、不下载对象内容；跨对象访问证明仅以最小读验证"
    "记录（服务端限定数量/字段时按 ROE 方案 A 执行）"
)


def screen_cloud_storage_observations(
    observations: Iterable[Mapping[str, object]],
    all_branches: bool = True,
    label: str = "cloud_storage_acl_testing",
) -> tuple[list[dict], list[dict], list[str]]:
    """对象存储 ACL 复核筛选 → (候选行, 分支汇总行, 违例)。"""
    return cloud_engine.screen_observations(
        observations,
        CLOUD_STORAGE_BRANCHES,
        CLOUD_STORAGE_OBSERVATION_EVIDENCE_MAP,
        CLOUD_STORAGE_EVIDENCE_KINDS,
        CLOUD_STORAGE_INSUFFICIENT_KINDS,
        CLOUD_STORAGE_UPGRADE_RULES,
        all_branches=all_branches,
        label=label,
    )


def validate_cloud_storage_candidate(
    row: Mapping[str, object], label: str = "cloud_storage_candidate"
) -> list[str]:
    return cloud_engine.validate_review_row(
        row,
        CLOUD_STORAGE_BRANCHES,
        CLOUD_STORAGE_EVIDENCE_KINDS,
        CLOUD_STORAGE_INSUFFICIENT_KINDS,
        CLOUD_STORAGE_UPGRADE_RULES,
        label=label,
    )


def build_cloud_storage_review_artifact(
    rows: Iterable[Mapping[str, object]],
    summaries: Iterable[Mapping[str, object]],
    violations: Iterable[str],
    authorization_basis: str,
    updated_at: str,
    substatuses: Mapping[str, str] | None = None,
) -> dict:
    return cloud_engine.build_cloud_review_artifact(
        "cloud_storage_acl_testing",
        rows,
        summaries,
        violations,
        authorization_basis,
        updated_at,
        substatuses=substatuses,
    )


def validate_cloud_storage_review_artifact(
    artifact: Mapping[str, object], label: str = "cloud_storage_review_artifact"
) -> list[str]:
    return cloud_engine.validate_cloud_review_artifact(
        artifact,
        "cloud_storage_acl_testing",
        CLOUD_STORAGE_BRANCHES,
        CLOUD_STORAGE_EVIDENCE_KINDS,
        CLOUD_STORAGE_INSUFFICIENT_KINDS,
        CLOUD_STORAGE_UPGRADE_RULES,
        label=label,
    )


def _cli() -> int:
    """离线 CLI：观察 JSON 文件 → review artifact JSON（纯文件到文件）。"""
    import argparse
    import json
    from datetime import datetime
    from pathlib import Path

    parser = argparse.ArgumentParser(
        description="Offline cloud storage ACL review (no network, no bulk object "
        "reads, no object downloads; writes/real payments are approval-gated)."
    )
    parser.add_argument("--observations", required=True, help="Observations JSON file (list or {observations: [...]})")
    parser.add_argument("--out", required=True, help="Output artifact JSON path")
    parser.add_argument(
        "--authorization-basis",
        default="operator_supplied_material",
        choices=list(cloud_engine.AUTHORIZATION_BASIS_VALUES),
    )
    args = parser.parse_args()
    payload = json.loads(Path(args.observations).read_text(encoding="utf-8-sig"))
    observations = payload.get("observations", []) if isinstance(payload, dict) else payload
    if not isinstance(observations, list):
        print("ERROR: observations must be a list", flush=True)
        return 2
    rows, summaries, violations = screen_cloud_storage_observations(observations)
    artifact = build_cloud_storage_review_artifact(
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
