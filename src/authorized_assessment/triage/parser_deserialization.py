"""解析器与反序列化筛选（实施规格 5.4：parser_deserialization_screening 子阶段）。

XXE/XML/YAML/反序列化四类的解析面发现与前置条件判定。纯 stdlib、零网络、只读：
只从结构化观察（content_type / 端点标记 / 正文形态标记）确定性识别解析面并输出
signal 级候选与类别汇总；候选分级、升级规则与行级校验全部复用
injection_candidates（单一实现，不造第二套判定）。

规格红线：仅依赖名称、类名或序列化格式不算漏洞；默认只做解析器和实体处理能力的
低风险判定，不读取本地敏感文件、不访问内网、不导出数据；最小 OOB/进一步验证均为审批门。
"""
from __future__ import annotations

from typing import Iterable, Mapping

from authorized_assessment.triage import injection_candidates as ic

# parser_deserialization_screening 负责的四个类别（与契约 category_screening 同源）。
PARSER_CATEGORIES: tuple[str, ...] = ic.CATEGORY_SCREENING["parser_deserialization_screening"]

# content_type 标记 → 解析面（确定性子串匹配，小写比较）。
CONTENT_TYPE_MARKERS: dict[str, tuple[str, ...]] = {
    "xml": (
        "application/xml",
        "text/xml",
        "application/soap+xml",
        "image/svg+xml",
        "application/rss+xml",
        "application/atom+xml",
        "application/xhtml+xml",
    ),
    "yaml": ("application/yaml", "application/x-yaml", "text/yaml", "text/x-yaml"),
    "java_serialized": (
        "application/x-java-serialized-object",
        "application/java-archive",
    ),
}

# 端点路径标记 → 解析面（子串匹配，小写比较）。
ENDPOINT_MARKERS: dict[str, tuple[str, ...]] = {
    "xml": ("soap", "saml", "rss", "atom", "wsdl", "xml", "svg", "export", "import"),
    "yaml": ("yaml", "yml", "config"),
    "java_serialized": ("remoting", "jmx", "spring", "hessian", "axis"),
}

    # 正文/参数形态标记 → 解析面（复核会话从请求体样本提炼的形态线索，非原始正文）；
    # 键统一小写（匹配时对标记做 lower，Java 序列化魔数 rO0AB 小写形为 r0ab）。
BODY_MARKER_CATEGORIES: dict[str, str] = {
    "<!doctype": "xml",
    "<soap": "xml",
    "<saml": "xml",
    "<?xml": "xml",
    "<rss": "xml",
    "<feed": "xml",
    "- xmlns": "yaml",
    "ac ed 00 05": "java_serialized",
    "ro0ab": "java_serialized",
    "!!python": "yaml",
    "org.springframework": "java_serialized",
}

# 规格 5.4 XXE 五类前置条件（发现任一才进入 parser 筛选）。
PRECONDITION_KINDS: tuple[str, ...] = (
    "xml_api",
    "soap_saml_feed",
    "document_upload_import",
    "xml_config_import",
    "backend_parser",
)

_CONTENT_TYPE_ALIASES = {
    "xml": ("xml", "svg", "xhtml"),
    "soap": ("soap+xml",),
}


def surface_categories(
    content_type: str = "", endpoint: str = "", body_markers: Iterable[str] = ()
) -> list[str]:
    """从内容类型/端点/正文形态标记确定性推断解析面类别（PARSER_CATEGORIES 子集，去重稳定序）。"""
    found: list[str] = []
    lowered_ct = (content_type or "").lower()
    lowered_ep = (endpoint or "").lower()
    markers = [str(m).lower() for m in body_markers]

    def _mark(category: str) -> None:
        if category in PARSER_CATEGORIES and category not in found:
            found.append(category)

    if any(marker in lowered_ct for marker in CONTENT_TYPE_MARKERS["xml"]):
        _mark("xml_parser")
    if "soap+xml" in lowered_ct or any(m in lowered_ep for m in ("soap", "saml", "rss", "atom")):
        _mark("xml_parser")
    if any(marker in lowered_ct for marker in CONTENT_TYPE_MARKERS["yaml"]) or any(
        m in lowered_ep for m in ("yaml", "yml")
    ):
        _mark("yaml_parser")
    if any(marker in lowered_ct for marker in CONTENT_TYPE_MARKERS["java_serialized"]) or any(
        m in lowered_ep for m in ENDPOINT_MARKERS["java_serialized"]
    ):
        _mark("unsafe_deserialization")
    for marker in markers:
        surface = BODY_MARKER_CATEGORIES.get(marker.strip().lower())
        if surface == "xml":
            _mark("xml_parser")
        elif surface == "yaml":
            _mark("yaml_parser")
        elif surface == "java_serialized":
            _mark("unsafe_deserialization")
    return found


def parse_surface_preconditions(
    content_type: str = "", endpoint: str = "", body_markers: Iterable[str] = (), parser_confirmed: bool = False
) -> dict[str, str]:
    """判定规格 5.4 前置条件命中集合：kind → 命中依据。空 dict = 未发现解析面，不进入筛选。"""
    lowered_ct = (content_type or "").lower()
    lowered_ep = (endpoint or "").lower()
    markers = [str(m).strip().lower() for m in body_markers]
    hit: dict[str, str] = {}
    if lowered_ct in ("application/xml", "text/xml", "application/json+xml") or any(
        a in lowered_ct for a in _CONTENT_TYPE_ALIASES["xml"]
    ):
        hit["xml_api"] = f"content_type={content_type}"
    if "soap+xml" in lowered_ct:
        hit["soap_saml_feed"] = "SOAP content type"
    if any(m in lowered_ep for m in ("soap", "saml", "rss", "atom", "wsdl")):
        hit["soap_saml_feed"] = f"endpoint={endpoint}"
    if any(m in lowered_ep for m in ("upload", "import", "export")) and (
        "xml" in lowered_ct or surface_categories(content_type, endpoint, markers)
    ):
        hit["document_upload_import"] = f"endpoint={endpoint}"
    if any(m in lowered_ep for m in ("config",)) and (
        "xml" in lowered_ct
        or "yaml" in lowered_ct
        or "yml" in lowered_ct
        or any(m in lowered_ep for m in ("xml", "yaml", "yml"))
    ):
        hit["xml_config_import"] = f"endpoint={endpoint}"
    if parser_confirmed:
        hit["backend_parser"] = "parser_confirmed 观察证据"
    return hit


def screen_parser_observations(
    observations: Iterable[Mapping[str, object]],
    label: str = "parser_deserialization_screening",
) -> tuple[list[dict], list[dict], list[str]]:
    """解析面筛选：先做解析面发现与前置条件判定，再复用 injection_candidates 筛选。

    观察必需键：applicability（与 screen_observations 一致）；category 可省略——
    由 content_type/endpoint/body_markers 确定性推断（显式给出时必须与推断一致，
    否则记违例）。可选键继承 screen_observations，另加 parser_confirmed（bool，
    对应 backend_parser 前置条件与 parser_confirmed 证据形态）。

    返回 (候选行, 汇总行[仅 PARSER_CATEGORIES 四类], 违例)。
    """
    rows: list[dict] = []
    violations: list[str] = []
    prepared: list[dict] = []
    for index, observation in enumerate(observations, start=1):
        if not isinstance(observation, Mapping):
            violations.append(f"{label}: 第 {index} 条观察必须是键值映射")
            continue
        content_type = str(observation.get("content_type") or "")
        endpoint = str(observation.get("endpoint") or "")
        markers = [str(m) for m in (observation.get("body_markers") or [])]
        parser_confirmed = bool(observation.get("parser_confirmed"))
        preconditions = parse_surface_preconditions(
            content_type, endpoint, markers, parser_confirmed
        )
        surfaces = surface_categories(content_type, endpoint, markers)
        if not preconditions and surfaces:
            # 规格 5.4 五类前置针对 XML 面；yaml/序列化面以解析面标记命中为入口
            # （signal 级筛选入口，"确认后端解析器"的升级证据仍由 parser_confirmed 承担）。
            preconditions = {"backend_parser": f"解析面标记命中: {','.join(surfaces)}"}
        if not preconditions:
            # 未发现解析面：宣称 applicable 是违例（未做适用性判定不得宣称适用）；
            # not_applicable 记录带合法显式类别时仍要落入汇总 not_applicable 计数。
            applicability = str(observation.get("applicability") or "")
            declared = str(observation.get("category") or "")
            if applicability == "applicable":
                violations.append(
                    f"{label}: 第 {index} 条观察宣称 applicable 但未命中任何解析面前置条件"
                    "（未做适用性判定不得宣称适用）"
                )
            if applicability == "not_applicable" and declared in PARSER_CATEGORIES:
                prepared.append(
                    {**observation, "evidence": dict(observation.get("evidence") or {})}
                )
            continue
        inferred = surface_categories(content_type, endpoint, markers)
        declared = str(observation.get("category") or "")
        if declared and declared not in inferred:
            violations.append(
                f"{label}: 第 {index} 条观察 category={declared!r} 与解析面推断 {inferred} 不符"
            )
            continue
        category = declared or (inferred[0] if inferred else "")
        if not category:
            continue
        evidence = dict(observation.get("evidence") or {})
        if parser_confirmed:
            evidence.setdefault("parser_confirmed", True)
        prepared.append(
            {
                **observation,
                "category": category,
                "evidence": evidence,
                "precondition": observation.get("precondition")
                or "; ".join(sorted(preconditions)),
            }
        )
    rows, summaries, screen_violations = ic.screen_observations(
        prepared, all_categories=False, label=label
    )
    violations += screen_violations
    return rows, summaries, violations
