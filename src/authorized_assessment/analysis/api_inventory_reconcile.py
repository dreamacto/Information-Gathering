"""API 版本/影子面离线盘点与文档↔流量对账(实施规格 5.3 API schema/version 小节
1257-1274 行 + 3.1 analysis/api_inventory_reconcile 模块清单)。

职责边界(纯离线数据变换,不发任何请求、不抓取/下载 OpenAPI 原文、不产生任何
候选、不做 8 状态分级--对账差异是清单不是漏洞,规格 11.3;确认越过边界后另行
投递对应筛选域):

- inventory:从复核会话提炼的结构化 API 记录(文档登记/流量观察)做版本盘点、
  影子/测试面标记、来源/方法/Content-Type 确定性归类、行校验与 manifest 汇总。
- reconciliation:文档↔流量对账--键 = (canonical_host, normalize_endpoint)
  (canonical_keys 单一实现),差异状态为确定性六状态(RECONCILIATION_STATUSES)。

来源可信度(规格 4.3):A=OpenAPI/Swagger/GraphQL schema 声明、B=前端 JS 调用、
C=浏览器/Burp 真实流量、D=HTML 表单或链接、E=猜测路径/固定字典。资格判定引用
canonical_keys.SOURCE_KIND_ELIGIBILITY 单一实现(本模块不重复定义资格表);对账侧
流量记录只接受 A/B/C--D/E 来源不能证明可达,不能作为"文档有但不可达"的反向
证据;inventory 侧接受全部 A-E+unknown(盘点不是队列准入)。

实现定义留痕(供操作者复核,规格仅列检查方向未逐条枚举标记):
- VERSION_LABELS:v1-v10 确定性登记表;路径段/查询版本参数/host 标签三优先级
  派生;超出登记表的版本号(v11+)不猜测,declared_version 保留文档原值。
- SHADOW_MARKERS:shadow/test/debug/staging/uat/qa/dev/preprod/internal/demo/
  beta/experimental 确定性标记表;匹配语义为"分隔符(-_.)切分后的完整部件相等"
  (不做子串包含--latest/contest 等偶然子串会产生假阳性)。影子/测试面标记仅为
  形态线索,永不升级(signal 不是漏洞)。
- 对账差异六状态取固定优先级(method_mismatch > content_type_mismatch >
  version_mismatch;共存的次级差异写入 reason,不改变单值 status)。
- 对账行沿用规格 5.2 七字段形状(RECONCILIATION_ROW_FIELDS);status 值域为对账
  六状态而非 coverage 六子状态(对账状态不是覆盖状态,字段形状复用≠状态枚举
  复用,本 docstring 留痕)。因此对账行校验为模块内自足实现(不复用
  validate_application_map_row--其 status 枚举为 coverage 六子状态,对账六状态
  会全部误报)。
- 两 CSV 表头契约(API_VERSION_INVENTORY_CSV_FIELDS / API_RECONCILIATION_CSV_
  FIELDS)对应规格明示 artifacts/api/api-version-inventory.csv 与
  artifacts/api/api-reconciliation.csv;落盘接线归后续批次,本批只锁表头契约
  (shadow_markers 的 CSV 序列化约定:sorted 后以 "|" 连接)。
"""
from __future__ import annotations

import re
from typing import Iterable, Mapping

from authorized_assessment.analysis.coverage_matrix import APPLICABLE_VALUES
from authorized_assessment.triage import canonical_keys as ck

# ---------------------------------------------------------------------------
# 确定性登记表(实现定义留痕)

# 版本登记表：v1-v10；v11+ 不猜测（declared_version 保留原值）。
# 契约同源：contracts/api_reconciliation_schema.json versioned_definition
# .version_labels（batch8_10 第 9 契约，操作员决定⑤⑥）。
VERSION_LABELS: tuple[str, ...] = tuple(f"v{n}" for n in range(1, 11))

# 版本化实现定义版本（操作员决定⑥：登记表/shadow 表/状态枚举增删改必须 bump
# 本版本并同步契约 versioned_definition.api_inventory_schema_version）。
API_INVENTORY_SCHEMA_VERSION = "1.0"

# 影子/测试面标记表（规格 5.3：shadow/test/debug API 检查方向的最小确定性集合）。
# 契约同源：api_reconciliation_schema.versioned_definition.shadow_markers。
SHADOW_MARKERS: tuple[str, ...] = (
    "shadow",
    "test",
    "debug",
    "staging",
    "uat",
    "qa",
    "dev",
    "preprod",
    "internal",
    "demo",
    "beta",
    "experimental",
)

# 查询版本参数键(规范化后精确匹配;值仅接受登记表内 vN 或纯数字 N 的 vN 形式)。
QUERY_VERSION_KEYS: tuple[str, ...] = ("version", "api_version", "apiversion", "v")

_PART_SPLIT = re.compile(r"[/\-_.]")
_QUERY_VERSION_VALUE = re.compile(r"^(?:v)?([1-9]|10)$")
_SEMVER_VERSION = re.compile(r"^v?(\d+)(?:\.\d+){0,2}$")

# ---------------------------------------------------------------------------
# 产物 CSV 表头契约（规格明示 artifacts/api/ 两 CSV；
# 契约同源：api_reconciliation_schema.csv_artifacts.files；落盘接线归后续批次；
# 序列化约定：列表字段 sorted 后 "|" 连接、缺失值统一空串——serialize_* 函数单一实现）。

# 版本盘点 CSV 表头。
API_VERSION_INVENTORY_CSV_FIELDS: tuple[str, ...] = (
    "endpoint_or_surface",
    "canonical_host",
    "http_method",
    "content_type",
    "source_kind",
    "declared_version",
    "version_label",
    "shadow_markers",
    "source",
    "evidence_ref",
)

# 对账 CSV 表头 = 规格 5.2 七字段(reason 承载差异说明;status 值域为对账六状态)。
RECONCILIATION_ROW_FIELDS: tuple[str, ...] = (
    "applicable",
    "status",
    "source",
    "asset",
    "endpoint_or_surface",
    "reason",
    "evidence_ref",
)
# 对账 CSV 表头 = 规格 5.2 七字段 + object_field_authorization 子状态(行形状
# v1.1,操作员 batch8_5 决定2;v1.0 为七字段,版本化演进见本 docstring 头部
# 与 batch8_7 卡片)。RECONCILIATION_ROW_FIELDS 保持规格 5.2 七字段形状不变。
API_RECONCILIATION_CSV_FIELDS: tuple[str, ...] = RECONCILIATION_ROW_FIELDS + (
    "object_field_authorization",
)

# object_field_authorization 子状态(操作员 batch8_5 决定2:机器可审计子状态,
# 载体 = API 对账产物行;八值 = 操作员七值 + not_applicable 完备项;与 finding
# 8 状态同源对齐--object 级授权确认走既有 finding_quality_gate 五门,本枚举只
# 记录子状态不判定漏洞)。
OBJECT_FIELD_AUTHORIZATION_STATUSES: tuple[str, ...] = (
    "tested",
    "candidate",
    "needs_manual_validation",
    "confirmed",
    "rejected",
    "blocked",
    "inconclusive",
    "not_applicable",
)

# 子状态升级语义(操作员决定2,非证明语义的字段说明):OpenAPI 字段存在、前端
# 字段可见、客户端可提交字段均不构成字段级授权漏洞证据--这些只是清单差异;
# 仅真正证明字段级越权(跨用户对象访问确认等,经对应域候选流程)后才可记
# candidate/confirmed;对账模块只产清单不产候选,确认后的投递(授权漏洞候选
# 或人工复核队列)为下游会话职责;独立字段授权验证逻辑出现时再单独立项
# (操作员决定2原文,版本化演进随本文件 docstring 版本记录)。
OBJECT_FIELD_AUTHORIZATION_FIELD_DOC: str = (
    "API/字段级授权覆盖子状态(机器可审计,操作员 batch8_5 决定2):"
    "字段存在/前端可见/客户端可提交不构成授权漏洞证据;"
    "确认越权后由下游投递授权候选或人工复核队列;"
    "非证明语义详见 api_inventory_reconcile 模块 docstring"
)

INVENTORY_VERSION = "1.0"
RECONCILIATION_VERSION = "1.0"

# 对账差异六状态（实现定义，固定优先级：共存的次级差异写入 reason）。
# 契约同源：api_reconciliation_schema.reconciliation_statuses + status_priority_rule。
RECONCILIATION_STATUSES: tuple[str, ...] = (
    "doc_only",
    "traffic_only",
    "method_mismatch",
    "content_type_mismatch",
    "version_mismatch",
    "matched",
)

_RECONCILE_STATUS_PRIORITY: tuple[str, ...] = (
    "method_mismatch",
    "content_type_mismatch",
    "version_mismatch",
)


def _text(value: object) -> str:
    return str(value or "").strip()


def _split_parts(text: str) -> set[str]:
    """分隔符(-_.)切分后的完整部件集合(小写)--标记匹配语义的单一实现。"""
    return {part for part in _PART_SPLIT.split((text or "").lower()) if part}


def normalize_source_kind(value: object) -> str:
    """来源标记归一化:A-E 大写;空/非法 → unknown(不猜测)。"""
    text = _text(value).upper()
    return text if text in ck.SOURCE_KINDS else "unknown"


def normalize_content_type(value: object) -> str:
    """Content-Type 归一化:去参数(; 后丢弃)、去空白、小写;空 → 空串(缺失≠冲突)。"""
    return _text(value).split(";", 1)[0].strip().lower()


def _version_label_from_value(value: str) -> str:
    """版本值 → 登记表标签(确定性):"v3"/"3" → v3;语义版本取主版本("1.0"→v1、
    "10.2.3"→v10);超出登记表(v11+/0.x)返回空串(调用方决定保留原值或回落)。"""
    text = (value or "").strip().lower()
    if text in VERSION_LABELS:
        return text
    semver = _SEMVER_VERSION.match(text)
    if semver:
        major = int(semver.group(1))
        if 1 <= major <= 10:
            return f"v{major}"
    return ""


def detect_version_label(record: Mapping[str, object]) -> str:
    """版本标记确定性派生:路径段 → 查询版本参数 → host 标签;无标记 → none。

    优先级依据:路径路由最显式,其次声明的查询参数,最后 host 命名(子域/前缀)。
    每级只取第一个命中(同一记录多版本标记不叠加,declared_version 另行保留)。
    """
    for segment in _text(record.get("path") or record.get("endpoint")).lower().split("/"):
        if segment in VERSION_LABELS:
            return segment
    query = record.get("query")
    if isinstance(query, Mapping):
        for key, raw in query.items():
            normalized_key = _text(key).lower().replace("-", "_")
            if normalized_key not in QUERY_VERSION_KEYS:
                continue
            mapped = _version_label_from_value(_text(raw))
            if mapped:
                return mapped
    for part in _split_parts(_text(record.get("host"))):
        if part in VERSION_LABELS:
            return part
    return "none"


def detect_shadow_markers(record: Mapping[str, object]) -> tuple[str, ...]:
    """影子/测试面标记确定性识别(路径段 + host 部件,按标记表顺序去重)。

    仅形态线索,永不升级(signal 不是漏洞)。
    """
    parts = _split_parts(_text(record.get("path") or record.get("endpoint")))
    parts |= _split_parts(_text(record.get("host")))
    return tuple(marker for marker in SHADOW_MARKERS if marker in parts)


def _declared_version_label(record: Mapping[str, object]) -> str:
    """declared_version → 登记表内标签(含语义版本主版本映射,"1.0"→v1);
    无法映射(如 v11+/0.9)保留原值小写。"""
    declared = _text(record.get("declared_version")).lower()
    if not declared:
        return ""
    return _version_label_from_value(declared) or declared


def _record_endpoint(record: Mapping[str, object]) -> str:
    return _text(record.get("path") or record.get("endpoint") or record.get("endpoint_or_surface"))


def _reconcile_path(path: str) -> str:
    """对账键路径:normalize_endpoint 后剥离第一个版本段(v1-v10,两侧一致剥离)。

    同一资源路径的不同版本(/api/v1/users vs /api/v2/users)必须落在同一对账键上,
    版本差异由 versions 集合比较产生 version_mismatch;键不剥离则版本差异永远
    表现为 doc_only/traffic_only 而不可对账。版本段可能是真实资源名的风险由
    "两侧一致剥离"抵消(键对齐不受影响)。"""
    normalized = ck.normalize_endpoint(path)
    if normalized == "/":
        return normalized
    segments = normalized.strip("/").split("/")
    for i, segment in enumerate(segments):
        if segment in VERSION_LABELS:
            segments = segments[:i] + segments[i + 1 :]
            break
    return "/" + "/".join(segments) if segments else "/"


def validate_inventory_row(row: Mapping[str, object], label: str = "api_inventory") -> list[str]:
    """盘点行结构校验(盘点不是队列准入:不强制 evidence_ref)。"""
    violations: list[str] = []
    if not isinstance(row, Mapping):
        return [f"{label}: 盘点行必须是键值映射"]
    if not _text(row.get("endpoint_or_surface")):
        violations.append(f"{label}: endpoint_or_surface 为空(盘点行必须可定位)")
    source_kind = _text(row.get("source_kind"))
    if source_kind and source_kind not in ck.SOURCE_KINDS and source_kind != "unknown":
        violations.append(
            f"{label}.source_kind 非法: {source_kind!r}"
            f"(允许值 {list(ck.SOURCE_KINDS)} 或 unknown,规格 4.3)"
        )
    version_label = _text(row.get("version_label"))
    if version_label and version_label not in VERSION_LABELS and version_label != "none":
        violations.append(
            f"{label}.version_label 非法: {version_label!r}(允许值 {list(VERSION_LABELS)} 或 none)"
        )
    markers = row.get("shadow_markers")
    if markers is not None:
        if not isinstance(markers, (list, tuple)):
            violations.append(f"{label}.shadow_markers 必须为列表")
        else:
            unknown = sorted({str(m) for m in markers} - set(SHADOW_MARKERS))
            if unknown:
                violations.append(f"{label}.shadow_markers 未知标记: {unknown}")
    return violations


def build_api_version_inventory(
    records: Iterable[Mapping[str, object]],
    label: str = "api_inventory",
) -> dict:
    """结构化 API 记录 → 版本盘点行 + manifest 汇总(离线数据变换,不落盘)。

    记录键:path(或 endpoint)/ host / http_method / content_type / source_kind /
    declared_version / query / source / evidence_ref。全部确定性派生,缺值归
    unknown/空串,不猜测。
    返回 {"inventory_version", "rows", "summary", "violations"}。
    """
    rows: list[dict] = []
    violations: list[str] = []
    by_source_kind: dict[str, int] = {}
    by_version_label: dict[str, int] = {"none": 0}
    by_version_label.update({v: 0 for v in VERSION_LABELS})
    by_content_type: dict[str, int] = {}
    by_method: dict[str, int] = {}
    by_shadow_marker: dict[str, int] = {m: 0 for m in SHADOW_MARKERS}
    shadow_hit_rows = 0
    for index, record in enumerate(records, start=1):
        if not isinstance(record, Mapping):
            violations.append(f"{label}: 第 {index} 条记录必须是键值映射")
            continue
        endpoint_or_surface = _record_endpoint(record)
        canonical_host = ck.canonical_host(_text(record.get("host"))) if _text(record.get("host")) else ""
        http_method = ck.normalize_http_method(record.get("http_method"))
        content_type = normalize_content_type(record.get("content_type"))
        source_kind = normalize_source_kind(record.get("source_kind"))
        declared_version = _text(record.get("declared_version"))
        version_label = detect_version_label(record)
        shadow_markers = list(detect_shadow_markers(record))
        row = {
            "endpoint_or_surface": endpoint_or_surface,
            "canonical_host": canonical_host,
            "http_method": http_method,
            "content_type": content_type,
            "source_kind": source_kind,
            "declared_version": declared_version,
            "version_label": version_label,
            "shadow_markers": shadow_markers,
            "source": _text(record.get("source")),
            "evidence_ref": _text(record.get("evidence_ref")),
        }
        rows.append(row)
        row_violations = validate_inventory_row(row, label=f"{label}[{index}]")
        violations += row_violations
        by_source_kind[source_kind] = by_source_kind.get(source_kind, 0) + 1
        by_version_label[version_label] = by_version_label.get(version_label, 0) + 1
        by_content_type[content_type or "unknown"] = by_content_type.get(content_type or "unknown", 0) + 1
        by_method[http_method or "UNKNOWN"] = by_method.get(http_method or "UNKNOWN", 0) + 1
        for marker in shadow_markers:
            by_shadow_marker[marker] = by_shadow_marker.get(marker, 0) + 1
        if shadow_markers:
            shadow_hit_rows += 1
    return {
        "inventory_version": INVENTORY_VERSION,
        "rows": rows,
        "summary": {
            "total": len(rows),
            "by_source_kind": by_source_kind,
            "by_version_label": by_version_label,
            "by_content_type": by_content_type,
            "by_method": by_method,
            "shadow_hit_rows": shadow_hit_rows,
            "by_shadow_marker": by_shadow_marker,
        },
        "violations": violations,
    }


def _merge_side(
    records: Iterable[Mapping[str, object]], side: str = "doc"
) -> tuple[dict[tuple[str, str], dict], list[str]]:
    """同键记录合并(确定性:集合排序;首见 evidence_ref 保留)。

    键 = (canonical_host, normalize_endpoint);host 缺失时 canonical_host 为空串
    (仍可对账,双 host 隔离语义由键保证)。同键多版本/多方法为清单事实,不在
    单侧展开差异(差异只在 doc↔traffic 比较时产生)。
    """
    merged: dict[tuple[str, str], dict] = {}
    violations: list[str] = []
    for index, record in enumerate(records, start=1):
        if not isinstance(record, Mapping):
            violations.append(f"第 {index} 条记录必须是键值映射")
            continue
        path = _record_endpoint(record)
        if not path:
            violations.append(f"第 {index} 条记录缺少 path/endpoint(对账键必须可定位)")
            continue
        host = ck.canonical_host(_text(record.get("host"))) if _text(record.get("host")) else ""
        key = (host, _reconcile_path(path))
        entry = merged.setdefault(
            key,
            {
                "methods": set(),
                "content_types": set(),
                "versions": set(),
                "shadow_markers": set(),
                "object_field_authorization": set(),
                "doc_evidence_ref": "",
                "traffic_evidence_ref": "",
            },
        )
        method = ck.normalize_http_method(record.get("http_method"))
        if method:
            entry["methods"].add(method)
        content_type = normalize_content_type(record.get("content_type"))
        if content_type:
            entry["content_types"].add(content_type)
        version_label = detect_version_label(record)
        if version_label != "none":
            entry["versions"].add(version_label)
        declared = _declared_version_label(record)
        if declared:
            entry["versions"].add(declared)
        entry["shadow_markers"] |= set(detect_shadow_markers(record))
        substatus = _text(record.get("object_field_authorization"))
        if substatus:
            entry["object_field_authorization"].add(substatus)
        evidence_ref = _text(record.get("evidence_ref"))
        side_attr = f"{side}_evidence_ref"
        if evidence_ref and not entry.get(side_attr):
            entry[side_attr] = evidence_ref
    for entry in merged.values():
        entry["methods"] = sorted(entry["methods"])
        entry["content_types"] = sorted(entry["content_types"])
        entry["versions"] = sorted(entry["versions"])
        entry["shadow_markers"] = sorted(entry["shadow_markers"])
        entry["object_field_authorization"] = sorted(entry["object_field_authorization"])
    return merged, violations


def validate_reconciliation_row(
    row: Mapping[str, object], label: str = "api_reconciliation"
) -> list[str]:
    """对账行校验(模块内自足):七字段形状 + 对账六状态值域 + 子状态值域。

    不复用 validate_application_map_row:其 status 枚举为 coverage 六子状态,
    对账六状态非覆盖子状态(docstring"字段形状复用≠状态枚举复用"留痕)。
    """
    violations: list[str] = []
    if not isinstance(row, Mapping):
        return [f"{label}: 行必须是键值映射"]
    for field in RECONCILIATION_ROW_FIELDS:
        if field not in row:
            violations.append(f"{label}: 缺少最小字段 {field}(规格 5.2 七字段形状)")
    applicable = _text(row.get("applicable"))
    if applicable and applicable not in APPLICABLE_VALUES:
        violations.append(
            f"{label}.applicable 非法: {applicable!r}(允许值 {list(APPLICABLE_VALUES)})"
        )
    status = _text(row.get("status"))
    if status and status not in RECONCILIATION_STATUSES:
        violations.append(
            f"{label}.status 非法: {status!r}(对账状态值域 {list(RECONCILIATION_STATUSES)},"
            "非 coverage 子状态--对账状态不是覆盖状态)"
        )
    violations += _validate_object_field_authorization(row, label)
    return violations


def _validate_object_field_authorization(row: Mapping[str, object], label: str) -> list[str]:
    """子状态值域与可审计性校验(操作员 batch8_5 决定2)。

    candidate/confirmed/needs_manual_validation 必须 evidence_ref 非空--子状态
    升级必须可审计(与候选层 evidence_ref 契约同构)。
    """
    violations: list[str] = []
    substatus = _text(row.get("object_field_authorization"))
    if not substatus:
        return violations  # 缺省由构建侧填 inconclusive;外部构造的行不强制存在
    if substatus not in OBJECT_FIELD_AUTHORIZATION_STATUSES:
        violations.append(
            f"{label}.object_field_authorization 非法: {substatus!r}"
            f"(允许值 {list(OBJECT_FIELD_AUTHORIZATION_STATUSES)})"
        )
    if substatus in ("candidate", "confirmed", "needs_manual_validation") and not _text(
        row.get("evidence_ref")
    ):
        violations.append(
            f"{label}: object_field_authorization={substatus} 但 evidence_ref 为空"
            "(子状态升级必须可审计)"
        )
    return violations


def _substatus_from_side(doc: dict | None, traffic: dict | None) -> str:
    """子状态确定性合并:双侧声明时流量侧优先(流量对实际行为更权威);
    任一侧声明则取声明值(同侧多声明由调用侧行校验拦截非法值,多值取排序末位
    保确定性);均未声明 → inconclusive(未测,不猜测)。"""
    doc_values = (doc or {}).get("object_field_authorization") or []
    traffic_values = (traffic or {}).get("object_field_authorization") or []
    if traffic_values:
        return sorted(traffic_values)[-1]
    if doc_values:
        return sorted(doc_values)[-1]
    return "inconclusive"


def serialize_inventory_row(row: Mapping[str, object]) -> dict[str, str]:
    """版本盘点行 → CSV 单元格字典（确定性序列化，契约 csv_artifacts 序列化规则）。

    字段顺序 = API_VERSION_INVENTORY_CSV_FIELDS；shadow_markers sorted+"|"；
    缺失值统一空串。同输入两次调用逐字节相等（决定⑥：序列化确定性可测）。
    """
    markers = row.get("shadow_markers") or []
    values = {
        "endpoint_or_surface": _text(row.get("endpoint_or_surface")),
        "canonical_host": _text(row.get("canonical_host")),
        "http_method": _text(row.get("http_method")),
        "content_type": _text(row.get("content_type")),
        "source_kind": _text(row.get("source_kind")),
        "declared_version": _text(row.get("declared_version")),
        "version_label": _text(row.get("version_label")),
        "shadow_markers": "|".join(sorted(str(m) for m in markers)),
        "source": _text(row.get("source")),
        "evidence_ref": _text(row.get("evidence_ref")),
    }
    return {field: values.get(field, "") for field in API_VERSION_INVENTORY_CSV_FIELDS}


def serialize_reconciliation_row(row: Mapping[str, object]) -> dict[str, str]:
    """对账行 → CSV 单元格字典（确定性序列化；字段顺序 = API_RECONCILIATION_CSV_FIELDS）。"""
    values = {
        "applicable": _text(row.get("applicable")),
        "status": _text(row.get("status")),
        "source": _text(row.get("source")),
        "asset": _text(row.get("asset")),
        "endpoint_or_surface": _text(row.get("endpoint_or_surface")),
        "reason": _text(row.get("reason")),
        "evidence_ref": _text(row.get("evidence_ref")),
        "object_field_authorization": _text(row.get("object_field_authorization")),
    }
    return {field: values.get(field, "") for field in API_RECONCILIATION_CSV_FIELDS}


def reconcile_api_inventory(
    doc_records: Iterable[Mapping[str, object]],
    traffic_records: Iterable[Mapping[str, object]],
    label: str = "api_reconcile",
) -> dict:
    """文档↔流量对账(键 = (canonical_host, normalize_endpoint),canonical_keys 单一实现)。

    流量记录只接受 A/B/C 来源(规格 4.3 queue_eligible,canonical_keys 单一实现):
    D/E 来源不能证明可达,拒绝该行并记违例--猜测路径不能进入"文档有但不可达"
    的反向证据。差异六状态固定优先级:method_mismatch > content_type_mismatch >
    version_mismatch(共存次级差异写入 reason)。对账清单不是漏洞:不产生候选、
    不做 8 状态分级。
    返回 {"reconciliation_version", "rows", "summary", "violations"}。
    """
    # Iterable 具体化(同入参迭代两次以上:违例扫描 + 过滤 + 合并)。
    doc_records = [r for r in doc_records]
    traffic_records = [r for r in traffic_records]
    eligible = set(ck.SOURCE_KIND_ELIGIBILITY["queue_eligible"])
    pre_violations: list[str] = []
    for index, record in enumerate(traffic_records, start=1):
        if not isinstance(record, Mapping):
            continue
        source_kind = normalize_source_kind(record.get("source_kind"))
        if source_kind not in eligible:
            pre_violations.append(
                f"{label}.traffic: 第 {index} 条流量记录 source_kind={source_kind!r} "
                f"不在可证明可达来源 {sorted(eligible)} 内(规格 4.3),该行不参与对账"
            )

    doc_map, doc_violations = _merge_side(doc_records, side="doc")
    traffic_filtered = [
        dict(record)
        for record in traffic_records
        if isinstance(record, Mapping)
        and normalize_source_kind(record.get("source_kind")) in eligible
    ]
    traffic_map, traffic_violations = _merge_side(traffic_filtered, side="traffic")
    violations = pre_violations + [f"{label}.doc: {v}" for v in doc_violations] + [
        f"{label}.traffic: {v}" for v in traffic_violations
    ]

    rows: list[dict] = []
    by_status = {status: 0 for status in RECONCILIATION_STATUSES}
    union_keys = sorted(set(doc_map) | set(traffic_map), key=lambda k: (k[0], k[1]))
    for host, path in union_keys:
        doc = doc_map.get((host, path))
        traffic = traffic_map.get((host, path))
        reasons: list[str] = []
        if doc is None:
            status = "traffic_only"
            reasons.append("实际可达但文档未登记(来源 B/C 流量)")
            if traffic["versions"]:
                reasons.append(f"traffic_versions={traffic['versions']}")
        elif traffic is None:
            status = "doc_only"
            reasons.append("文档登记但无 B/C 流量证据(文档有但不可达待复核)")
            if doc["versions"]:
                reasons.append(f"doc_versions={doc['versions']}")
        else:
            diffs: list[str] = []
            if doc["methods"] and traffic["methods"] and doc["methods"] != traffic["methods"]:
                diffs.append(
                    f"method_mismatch: doc={doc['methods']} traffic={traffic['methods']}"
                )
            if doc["content_types"] and traffic["content_types"] and doc["content_types"] != traffic["content_types"]:
                diffs.append(
                    f"content_type_mismatch: doc={doc['content_types']} traffic={traffic['content_types']}"
                )
            if doc["versions"] and traffic["versions"] and not (
                set(doc["versions"]) & set(traffic["versions"])
            ):
                diffs.append(
                    f"version_mismatch: doc={doc['versions']} traffic={traffic['versions']}"
                )
            if not diffs:
                status = "matched"
            else:
                status = diffs[0].split(":", 1)[0]
                reasons = diffs
        if doc is not None and traffic is not None and status == "matched":
            reasons = ["文档与流量一致"]
        evidence_parts = []
        if doc is not None and doc["doc_evidence_ref"]:
            evidence_parts.append(f"doc:{doc['doc_evidence_ref']}")
        if traffic is not None and traffic["traffic_evidence_ref"]:
            evidence_parts.append(f"traffic:{traffic['traffic_evidence_ref']}")
        markers = sorted(set((doc or {}).get("shadow_markers") or []) | set((traffic or {}).get("shadow_markers") or []))
        if markers:
            reasons.append(f"shadow_markers={markers}")
        row = {
            "applicable": "applicable",
            "status": status,
            "source": "openapi_doc"
            if status == "doc_only"
            else ("captured_traffic" if status == "traffic_only" else "openapi_doc+captured_traffic"),
            "asset": host,
            "endpoint_or_surface": path,
            "reason": "; ".join(reasons),
            "evidence_ref": "; ".join(evidence_parts),
            "object_field_authorization": _substatus_from_side(doc, traffic),
        }
        rows.append(row)
        by_status[status] += 1
        violations += [
            f"{label}[{path}]: {v}" for v in validate_reconciliation_row(row, label=f"{label}.row")
        ]
    return {
        "reconciliation_version": RECONCILIATION_VERSION,
        "rows": rows,
        "summary": {
            "doc_key_count": len(doc_map),
            "traffic_key_count": len(traffic_map),
            "union_key_count": len(union_keys),
            "by_status": by_status,
        },
        "violations": violations,
    }
