#!/usr/bin/env python3
"""Offline product-aware triage for controlled exercise runs.

This module does not send network requests. It reads existing run outputs,
identifies mainstream OA/CMS/middleware/framework products, and writes an
operator queue with recommended tool branches and local template coverage.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse


BASE_DIR = Path(__file__).resolve().parent
DDDD_POC_DIR = BASE_DIR / "tools" / "dddd" / "common" / "config" / "pocs"
OA_EXP_BOOK_DIR = BASE_DIR / "tools" / "OA-EXPTOOL" / "book"
NUCLEI_TEMPLATE_ROOT = BASE_DIR / "tools" / "managed" / "nuclei-templates" / "10.4.4"

SOURCE_FILES = {
    "fingerprints": "fingerprints.jsonl",
    "verified_exposures": "verified_exposures.jsonl",
    "candidate_exposures": "candidate_exposures.jsonl",
    "impact_candidates": "impact_candidates.jsonl",
    "api_candidates": "api_candidates.jsonl",
    "api_interesting": "api_interesting.jsonl",
    "shiro_candidates": "shiro_candidates.jsonl",
    "tool_fingerprints": "tool_fingerprints.jsonl",
    "authenticated_impact_candidates": "authenticated_impact_candidates.jsonl",
}

APPROVAL_TOKENS = re.compile(
    r"(rce|upload|fileupload|file-upload|arbitrary-login|auth-bypass|default-login|weak-login|"
    r"deserialization|log4j|command|shell|getshell|memory|bypass|ssrf|xxe|sqli|sql.?inject|"
    r"sql注入|反序列|任意用户登录|默认口令|弱口令)",
    re.I,
)
REVIEW_TOKENS = re.compile(
    r"(info|leak|disclosure|config|detect|panel|swagger|druid|unauth|directory|traversal|"
    r"fileread|file-read|read|version|dashboard|monitor|api)",
    re.I,
)


@dataclass(frozen=True)
class ProductRule:
    product_id: str
    display_name: str
    family: str
    patterns: tuple[str, ...]
    template_keywords: tuple[str, ...]
    primary_tools: tuple[str, ...]
    backup_tools: tuple[str, ...]
    branch: str
    notes: str


RULES: tuple[ProductRule, ...] = (
    ProductRule("weaver_ecology", "Weaver E-Cology", "oa", (r"\bweaver\b", r"e-cology", r"ecology", r"fanwei", r"泛微"), ("weaver", "ecology", "e-cology"), ("OA-EXPTOOL", "dddd/nuclei"), ("afrog", "manual proxy"), "oa_weaver", "Prioritize info-leak/auth boundary checks; uploads and RCE stay approval-gated."),
    ProductRule("weaver_eoffice", "Weaver E-Office", "oa", (r"e-office", r"eoffice", r"e-mobile", r"泛微"), ("e-office", "eoffice", "weaver", "e-mobile"), ("OA-EXPTOOL", "dddd/nuclei"), ("afrog", "manual proxy"), "oa_weaver", "Separate E-Office/E-Mobile paths from E-Cology before validation."),
    ProductRule("seeyon", "Seeyon OA", "oa", (r"\bseeyon\b", r"\bseeyou\b", r"致远", r"/seeyon/"), ("seeyon", "seeyou"), ("OA-EXPTOOL", "dddd/nuclei"), ("afrog", "manual proxy"), "oa_seeyon", "Default queue only; file upload/RCE templates require explicit approval."),
    ProductRule("tongda", "Tongda OA", "oa", (r"\btongda\b", r"通达", r"office anywhere", r"/general/login"), ("tongda"), ("OA-EXPTOOL", "dddd/nuclei"), ("afrog", "manual proxy"), "oa_tongda", "Check unauth/session exposure first; do not run arbitrary-login templates full-scope."),
    ProductRule("yonyou", "Yonyou", "oa_erp", (r"\byonyou\b", r"用友", r"\bu8\b", r"\bnc\b", r"nccloud", r"grp-u8"), ("yonyou", "u8", "nc", "grp"), ("OA-EXPTOOL", "dddd/nuclei"), ("afrog", "manual proxy"), "erp_yonyou", "ERP targets need strict evidence minimization; file/data export checks stay manual."),
    ProductRule("wanhu", "Wanhu OA", "oa", (r"\bwanhu\b", r"万户", r"ezoffice"), ("wanhu", "ezoffice"), ("OA-EXPTOOL", "dddd/nuclei"), ("afrog", "manual proxy"), "oa_wanhu", "Prefer panel/version/info exposure confirmation before any exploit template."),
    ProductRule("landray", "Landray OA", "oa", (r"\blandray\b", r"蓝凌", r"\bekp\b", r"/sys/ui/"), ("landray", "lanray"), ("OA-EXPTOOL", "dddd/nuclei"), ("afrog", "manual proxy"), "oa_landray", "RCE and upload templates are approval-gated."),
    ProductRule("kingdee", "Kingdee EAS/K3 Cloud", "oa_erp", (r"\bkingdee\b", r"金蝶", r"\beas\b", r"k3.?cloud", r"apusic"), ("kingdee", "eas", "k3", "apusic"), ("dddd/nuclei", "OA-EXPTOOL"), ("afrog", "manual proxy"), "erp_kingdee", "Start with product/version and file-read exposure review; uploads and RCE require approval."),
    ProductRule("chanjet", "Chanjet T+", "oa_erp", (r"\bchanjet\b", r"畅捷通", r"tplus", r"t\+"), ("chanjet", "畅捷通", "tplus"), ("OA-EXPTOOL", "dddd/nuclei"), ("afrog", "manual proxy"), "erp_chanjet", "File read, SQL injection, upload, and auth checks are operator-gated."),
    ProductRule("hongfan", "Hongfan OA", "oa", (r"\bhongfan\b", r"红帆", r"ioffice"), ("hongfan", "红帆", "ioffice"), ("dddd/nuclei", "manual browser"), ("afrog",), "oa_hongfan", "Queue product-specific templates only after fingerprint confirmation."),
    ProductRule("jinher", "Jinher OA", "oa", (r"\bjinher\b", r"金和", r"c6.?oa"), ("jinher", "金和", "c6"), ("dddd/nuclei", "manual browser"), ("afrog",), "oa_jinher", "Prefer disclosure and panel checks; write or execution payloads require approval."),
    ProductRule("ruoyi", "RuoYi", "framework", (r"\bruoyi\b", r"若依", r"/prod-api/", r"ruoyi-admin"), ("ruoyi"), ("dddd/nuclei", "manual browser"), ("afrog", "Shiro triage"), "framework_ruoyi", "Often overlaps Shiro/Druid/SpringBoot; route to those branches too."),
    ProductRule("jeecgboot", "JeecgBoot", "framework", (r"jeecg", r"jeecgboot", r"jeecg-boot"), ("jeecg"), ("dddd/nuclei", "manual browser"), ("afrog", "API review"), "framework_jeecg", "Swagger and unauth checks are usually more useful than broad path scans."),
    ProductRule("springboot", "Spring Boot", "middleware", (r"spring.?boot", r"spring_actuator", r"/actuator", r"actuator_"), ("springboot", "spring-boot", "actuator"), ("springboot_triage.py", "nuclei"), ("SpringBoot-Scan.py manual",), "java_springboot", "Only read actuator metadata by default; heapdump/env needs careful review."),
    ProductRule("druid", "Alibaba Druid", "middleware", (r"\bdruid\b", r"druid monitor", r"druid stat"), ("druid"), ("runner high-value paths", "dddd/nuclei"), ("manual browser",), "middleware_druid", "Druid panels may be login-only; JSON endpoints need truth verification."),
    ProductRule("swagger", "Swagger/Knife4j/OpenAPI", "api", (r"swagger", r"knife4j", r"openapi", r"api-docs", r"swagger_api"), ("swagger", "openapi", "knife4j"), ("api_discovery.py", "api_endpoint_confirm.py"), ("dddd/nuclei", "manual browser"), "api_docs", "Extract schema and GET-like endpoints only; skip writes/downloads by default."),
    ProductRule("shiro", "Apache Shiro", "middleware", (r"\bshiro\b", r"rememberme", r"shiro_"), ("shiro"), ("shiro_triage.py",), ("ShiroAttack2 single-target manual",), "java_shiro", "Default branch only screens rememberMe behavior; key testing is manual approval."),
    ProductRule("log4j", "Apache Log4j", "java_component", (r"log4j", r"log4shell", r"cve-2021-44228", r"jndi", r"ldap://", r"rmi://"), ("log4j", "log4shell", "cve-2021-44228"), ("nuclei", "manual request review"), ("dddd legacy templates",), "java_log4j", "Queue only. Safe confirmation normally needs version evidence; JNDI/RCE callbacks are approval-gated."),
    ProductRule("thinkphp", "ThinkPHP", "cms_framework", (r"thinkphp", r"thinkcmf", r"index\.php\?s="), ("thinkphp", "thinkcmf"), ("dddd/nuclei", "afrog"), ("manual browser",), "php_thinkphp", "Keep RCE templates approval-gated; use version/info checks first."),
    ProductRule("wordpress", "WordPress", "cms", (r"wordpress", r"wp-content", r"wp-includes"), ("wordpress", "wp-"), ("dddd/nuclei", "manual browser"), ("afrog",), "cms_wordpress", "Enumerate exposed version/plugin metadata only; credential and active plugin checks are gated."),
    ProductRule("dedecms", "DedeCMS", "cms", (r"dedecms", r"织梦", r"/dede/"), ("dedecms", "dede"), ("dddd/nuclei", "afrog"), ("manual browser",), "cms_dedecms", "Use panel/version and disclosure checks before any exploit template."),
    ProductRule("discuz", "Discuz!", "cms", (r"discuz", r"comsenz", r"forum\.php"), ("discuz", "comsenz"), ("dddd/nuclei", "afrog"), ("manual browser",), "cms_discuz", "No account guessing; route only confirmed products."),
    ProductRule("confluence", "Atlassian Confluence", "collaboration", (r"confluence", r"x-confluence", r"/wiki/"), ("confluence",), ("dddd/nuclei", "manual browser"), ("afrog",), "collab_confluence", "Version and public-space checks are safe candidates; RCE/auth bypass stays gated."),
    ProductRule("jira", "Atlassian Jira", "collaboration", (r"atlassian.?jira", r"x-arequestid", r"/secure/dashboard"), ("jira", "atlassian"), ("dddd/nuclei", "manual browser"), ("afrog",), "collab_jira", "Review public projects and version exposure; do not test credentials automatically."),
    ProductRule("fastjson", "Fastjson", "java_component", (r"fastjson", r"com\.alibaba\.fastjson"), ("fastjson"), ("fastjson_triage.py", "nuclei"), ("FastjsonScan.exe",), "java_fastjson", "Treat RCE templates as approval-gated; version detection is safe to queue."),
    ProductRule("weblogic", "WebLogic", "middleware", (r"weblogic", r"bea weblogic", r"/console/login"), ("weblogic"), ("tomcat_triage.py", "nuclei"), ("nuclei weblogic cves templates",), "middleware_weblogic", "Prefer console/version/protocol detection; exploit checks need approval."),
    ProductRule("struts2", "Apache Struts", "framework", (r"struts", r"struts2", r"\.action\b"), ("struts"), ("struts2_triage.py", "nuclei"), ("Struts2Scan.py",), "java_struts", "Only route candidates; OGNL/RCE payload validation is approval-gated."),
    ProductRule("tomcat", "Apache Tomcat", "middleware", (r"tomcat", r"catalina", r"/manager/html", r"apache-coyote"), ("tomcat"), ("tomcat_triage.py", "nuclei"), ("manual browser",), "middleware_tomcat", "Manager/default-login checks must not brute force."),
    ProductRule("nacos", "Nacos", "middleware", (r"\bnacos\b", r"/nacos/"), ("nacos"), ("nacos_triage.py", "nuclei"), ("nuclei nacos templates",), "middleware_nacos", "Default identity/token checks are sensitive; queue for single-target review."),
    ProductRule("redis", "Redis/ES/ZK", "middleware", (r"\bredis\b", r"elasticsearch", r"\bzk\b", r"zookeeper"), ("redis", "elasticsearch", "zookeeper"), ("redis_triage.py", "nuclei"), ("redis-cli manual",), "middleware_store", "PING/connect probes only; ssh-key/crontab writes and index reads are approval-gated."),
    ProductRule("solr", "Apache Solr", "middleware", (r"\bsolr\b", r"/solr/"), ("solr"), ("dddd/nuclei", "manual browser"), ("afrog",), "middleware_solr", "Use dashboard/version checks first; file read/RCE stays approval-gated."),
    ProductRule("jenkins", "Jenkins", "devops", (r"jenkins", r"x-jenkins", r"/jenkins/"), ("jenkins"), ("dddd/nuclei", "manual browser"), ("afrog",), "devops_jenkins", "No credential guessing; only public panel/registration/script exposure triage."),
    ProductRule("grafana", "Grafana", "devops", (r"grafana", r"/grafana/"), ("grafana"), ("dddd/nuclei", "manual browser"), ("afrog",), "devops_grafana", "Public signup/default login checks need operator approval."),
    ProductRule("zabbix", "Zabbix", "devops", (r"zabbix",), ("zabbix",), ("dddd/nuclei", "manual browser"), ("afrog",), "devops_zabbix", "Panel exposure is queue-only unless an authorized login is supplied."),
    ProductRule("smartbi", "Smartbi", "bi", (r"smartbi",), ("smartbi",), ("dddd/nuclei", "manual browser"), ("afrog",), "bi_smartbi", "Deserialization/default-login checks are approval-gated."),
    ProductRule("showdoc", "ShowDoc", "knowledge_base", (r"showdoc",), ("showdoc",), ("dddd/nuclei", "manual browser"), ("afrog",), "kb_showdoc", "Default-login checks are not automatic."),
    ProductRule("yapi", "YApi", "api", (r"\byapi\b",), ("yapi",), ("dddd/nuclei", "manual browser"), ("afrog",), "api_yapi", "Treat RCE checks as approval-gated; start from public project/API exposure."),
    ProductRule("xxl_job", "XXL-Job", "devops", (r"xxl.?job", r"/xxl-job-admin"), ("xxl", "xxl-job"), ("dddd/nuclei", "manual browser"), ("afrog",), "devops_xxljob", "Executor token/RCE checks are approval-gated."),
)


JAVA_STACK_PRODUCT_IDS = {
    "springboot",
    "shiro",
    "struts2",
    "fastjson",
    "log4j",
    "nacos",
    "solr",
    "tomcat",
    "weblogic",
    "ruoyi",
    "jeecgboot",
    "yonyou",
    "kingdee",
    "chanjet",
    "seeyon",
    "weaver_ecology",
    "weaver_eoffice",
    "landray",
}


VULN_CANDIDATE_RULES: dict[str, tuple[dict, ...]] = {
    "fastjson": ({
        "candidate_type": "fastjson_deserialization",
        "teacher_focus": "Fastjson is common in Java APIs and older versions have high-impact deserialization/RCE history.",
        "safe_review": "Confirm framework/version clues from errors, dependencies, JS/API behavior, or reports before any payload.",
        "approval_gate": "Active deserialization or callback payload testing requires explicit single-target approval.",
        "evidence_to_collect": "Java/API fingerprint, JSON-heavy endpoints, dependency/version clues, stack traces mentioning fastjson, vendor product version.",
        "recommended_review": "Start with product/version evidence and API schema review. Use local template names only to choose a manual checklist.",
        "do_not_do": "Do not send deserialization, callback, JNDI, DNSLog, or command payloads in batch.",
    },),
    "log4j": ({
        "candidate_type": "log4j_log4shell",
        "teacher_focus": "Log4j may be hidden inside Java applications; impact can be RCE even when the web stack looks ordinary.",
        "safe_review": "Look for version banners, dependency disclosures, stack traces, vendor advisories, or product/version matches.",
        "approval_gate": "JNDI/callback/RCE validation is approval-gated and must not run full-scope.",
        "evidence_to_collect": "Java stack/product fingerprint, Log4j version disclosure, error pages, dependency files, known affected product version.",
        "recommended_review": "Treat as a hidden dependency candidate. Prioritize systems with confirmed Java middleware/OA/ERP products.",
        "do_not_do": "Do not send JNDI, LDAP/RMI, DNSLog, or callback payloads without explicit single-target approval.",
    },),
    "struts2": ({
        "candidate_type": "struts2_ognl_rce",
        "teacher_focus": "Struts2 has many historic OGNL/RCE vulnerabilities and .action routes are easy to miss in generic crawling.",
        "safe_review": "Confirm .action routes, Struts errors, headers, or framework page patterns before single-candidate validation.",
        "approval_gate": "OGNL/RCE payload validation is approval-gated.",
        "evidence_to_collect": ".action URLs, Struts2 error pages, framework headers, stack traces, page source clues.",
        "recommended_review": "Use crawling/API output to find .action routes, then manually verify product/framework evidence only.",
        "do_not_do": "Do not send OGNL/RCE payloads or content-type exploit probes in batch.",
    },),
    "springboot": ({
        "candidate_type": "spring_boot_actuator_exposure",
        "teacher_focus": "Spring Boot actuator and management endpoints often expose config, mappings, env, metrics, or service structure.",
        "safe_review": "Use read-only metadata endpoints and truth verification; avoid heapdump/env extraction unless approved.",
        "approval_gate": "Sensitive file/data retrieval or exploit chains are approval-gated.",
        "evidence_to_collect": "Actuator path status/title/content-type, metadata keys, server headers, Spring Boot fingerprints.",
        "recommended_review": "Prefer /actuator health/info/mappings-style metadata. Confirm it is not a unified error page.",
        "do_not_do": "Do not download heapdump/logfile/env or extract secrets without approval.",
    },),
    "nacos": ({
        "candidate_type": "nacos_auth_config_exposure",
        "teacher_focus": "Nacos often sits near service discovery/config and auth mistakes can expose internal configuration.",
        "safe_review": "Confirm panel/version/config exposure signals with low-rate read-only requests only.",
        "approval_gate": "Default identity, auth bypass, config retrieval, or token abuse requires approval.",
        "evidence_to_collect": "Nacos panel, version, login state, config/list API metadata without values.",
        "recommended_review": "Verify product and scope first; collect only panel/version and access-control evidence.",
        "do_not_do": "Do not retrieve config contents, change namespaces, use default token tricks, or brute force login.",
    },),
    "thinkphp": ({
        "candidate_type": "thinkphp_route_rce",
        "teacher_focus": "ThinkPHP is common in Chinese PHP systems and older route/RCE issues are widely weaponized.",
        "safe_review": "Confirm framework/version/route style first; avoid payload testing in bulk.",
        "approval_gate": "RCE payload validation is approval-gated.",
        "evidence_to_collect": "ThinkPHP error page, route style, version clues, index.php?s= patterns, framework headers.",
        "recommended_review": "Start from passive page/error evidence and local template names, then decide whether a single target is worth approval.",
        "do_not_do": "Do not send RCE or function-call payloads in batch.",
    },),
    "shiro": ({
        "candidate_type": "shiro_rememberme_deserialization",
        "teacher_focus": "Shiro rememberMe issues are easy to screen safely and have mature single-target verification tools.",
        "safe_review": "Use the existing Shiro baseline plus invalid rememberMe triage output as the candidate signal.",
        "approval_gate": "Key brute force, serialized payloads, command execution, or memory shell checks require approval.",
        "evidence_to_collect": "rememberMe cookie behavior, Shiro headers/cookies, Java/login/OA context, shiro_triage confidence.",
        "recommended_review": "Use only the project Shiro triage first. Queue ShiroAttack2 for one target only after approval.",
        "do_not_do": "Do not brute force keys, send serialized payloads, or use memory shell options.",
    },),
    "weaver_ecology": ({
        "candidate_type": "weaver_oa_boundary_and_upload",
        "teacher_focus": "OA systems frequently expose auth-boundary, file, workflow, and integration interfaces.",
        "safe_review": "Start from information disclosure and auth-boundary checks; uploads/RCE stay manual.",
        "approval_gate": "Upload, arbitrary login, RCE, or data export checks require approval.",
        "evidence_to_collect": "Product/version page, login state, workflow/file interface paths, API schema, non-sensitive metadata.",
        "recommended_review": "Prioritize auth-boundary and interface exposure checks using browser/Burp evidence.",
        "do_not_do": "Do not upload scripts, bypass auth, export documents, or run OA exploit templates automatically.",
    },),
    "weaver_eoffice": ({
        "candidate_type": "weaver_oa_boundary_and_upload",
        "teacher_focus": "OA systems frequently expose auth-boundary, file, workflow, and integration interfaces.",
        "safe_review": "Separate E-Office/E-Mobile paths and review disclosure/auth-boundary templates first.",
        "approval_gate": "Upload, arbitrary login, RCE, or data export checks require approval.",
        "evidence_to_collect": "E-Office/E-Mobile product clues, login/API paths, file/workflow interface metadata.",
        "recommended_review": "Separate product family first, then check only read-only disclosure/auth-boundary candidates.",
        "do_not_do": "Do not upload scripts, bypass auth, export documents, or run OA exploit templates automatically.",
    },),
    "seeyon": ({
        "candidate_type": "seeyon_oa_file_and_auth_boundary",
        "teacher_focus": "Seeyon appears often in domestic OA environments and has historically high-impact file/auth/RCE chains.",
        "safe_review": "Confirm product and exposed paths first; queue risky templates for single-target review.",
        "approval_gate": "Upload/RCE/auth bypass checks require approval.",
        "evidence_to_collect": "Seeyon path/product page, login state, file/workflow interface metadata, non-sensitive API structure.",
        "recommended_review": "Use product confirmation plus interface exposure evidence; route risky templates to approval queue.",
        "do_not_do": "Do not test file upload, auth bypass, arbitrary file read, or RCE chains automatically.",
    },),
    "yonyou": ({
        "candidate_type": "yonyou_erp_auth_file_sqli",
        "teacher_focus": "Yonyou/ERP targets often combine auth, file, API, and SQL risk, with sensitive business data nearby.",
        "safe_review": "Use metadata and auth-boundary evidence only; do not export data.",
        "approval_gate": "SQLMap, file read/export, auth bypass, and upload checks require approval.",
        "evidence_to_collect": "Yonyou/NC/U8/GRP product clues, API paths, login state, metadata/status evidence without business values.",
        "recommended_review": "Prioritize auth-boundary and schema evidence. Escalate SQL/file candidates one target at a time.",
        "do_not_do": "Do not use SQLMap, download files, export data, bypass auth, or test upload automatically.",
    },),
}


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def read_jsonl(path: Path) -> list[dict]:
    rows = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def host_of(url: str) -> str:
    try:
        return urlparse(url).hostname or url
    except Exception:
        return url


def row_url(row: dict) -> str:
    return str(row.get("base_url") or row.get("url") or row.get("final_url") or "").rstrip("/")


def row_text(row: dict) -> str:
    parts = []
    for key in (
        "url",
        "base_url",
        "final_url",
        "host",
        "server",
        "content_type",
        "title",
        "kind",
        "path",
        "name",
        "finding",
        "keyword",
        "source",
        "snippet",
        "confidence",
    ):
        value = row.get(key)
        if value:
            parts.append(str(value))
    for key in ("categories", "tags", "source_tags", "top_level_keys", "verification_reasons", "body_keyword_hits", "technologies"):
        value = row.get(key)
        if isinstance(value, list):
            parts.extend(str(item) for item in value)
    return " ".join(parts)


def load_source_rows(run_dir: Path) -> list[tuple[str, dict]]:
    rows = []
    for source, filename in SOURCE_FILES.items():
        for row in read_jsonl(run_dir / filename):
            if row_url(row):
                rows.append((source, row))
    return rows


def source_weight(source: str) -> int:
    return {
        "verified_exposures": 35,
        "api_interesting": 30,
        "shiro_candidates": 30,
        "authenticated_impact_candidates": 30,
        "impact_candidates": 22,
        "candidate_exposures": 18,
        "api_candidates": 16,
        "fingerprints": 14,
    }.get(source, 10)


def confidence_label(score: int) -> str:
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def template_risk(path: Path) -> str:
    name = path.name.lower()
    if APPROVAL_TOKENS.search(name):
        return "approval_required"
    if REVIEW_TOKENS.search(name):
        return "review_readonly"
    return "review_unknown"


def tuple_values(values) -> tuple[str, ...]:
    if isinstance(values, str):
        return (values,)
    if values is None:
        return ()
    return tuple(str(value) for value in values if value)


def template_inventory() -> list[dict]:
    templates = []
    for root, tool in (
        (NUCLEI_TEMPLATE_ROOT, "nuclei-templates"),
        (DDDD_POC_DIR, "dddd-legacy"),
        (OA_EXP_BOOK_DIR, "OA-EXPTOOL-legacy"),
    ):
        if not root.exists():
            continue
        for path in root.rglob("*.yaml"):
            templates.append({
                "tool": tool,
                "name": path.name,
                "path": str(path),
                "risk": template_risk(path),
                "haystack": str(path).lower(),
            })
    return templates


def modern_tool_order(rule: ProductRule) -> tuple[list[str], list[str]]:
    """Prefer maintained engines while preserving old template sets as references."""
    original = list(rule.primary_tools) + list(rule.backup_tools)
    if rule.family in {"oa", "oa_erp"}:
        primary = ["afrog", "nuclei"]
    else:
        primary = ["nuclei" if name == "dddd/nuclei" else name for name in rule.primary_tools]
    backup = [
        ("dddd legacy templates" if name == "dddd/nuclei" else "OA-EXPTOOL legacy templates" if name == "OA-EXPTOOL" else name)
        for name in original
        if name not in primary
    ]
    return list(dict.fromkeys(primary)), list(dict.fromkeys(backup))


def matching_templates(rule: ProductRule, templates: list[dict], limit: int = 24) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {"review_readonly": [], "approval_required": [], "review_unknown": []}
    keywords = [kw.lower() for kw in tuple_values(rule.template_keywords)]
    for item in templates:
        if any(keyword in item["haystack"] for keyword in keywords):
            grouped.setdefault(item["risk"], []).append({k: item[k] for k in ("tool", "name", "path", "risk")})
    for risk, items in grouped.items():
        grouped[risk] = sorted(items, key=lambda row: (row["tool"], row["name"]))[:limit]
    return grouped


def build_findings(run_dir: Path) -> list[dict]:
    source_rows = load_source_rows(run_dir)
    templates = template_inventory()
    template_matches_by_product = {
        rule.product_id: matching_templates(rule, templates)
        for rule in RULES
    }
    by_key: dict[tuple[str, str], dict] = {}

    for source, row in source_rows:
        # 活体证据门：固定路径探针行必须真实命中（status < 400）才能当指纹证据。
        # 否则探针 path 本身（/actuator、/druid/index.html…）会被 regex 当成"产品存在"，
        # 逐级放大成产品漏洞候选（20260822 run：43 探针全 404/403 仍产出 10 条指纹、7 条候选）。
        if source == "candidate_exposures":
            try:
                if row.get("status") is None or int(row.get("status")) >= 400:
                    continue
            except (TypeError, ValueError):
                continue
        base_url = row_url(row)
        text = row_text(row)
        if not base_url or not text:
            continue
        for rule in RULES:
            matched = []
            for pattern in tuple_values(rule.patterns):
                if re.search(pattern, text, re.I):
                    matched.append(pattern)
            if not matched:
                continue
            key = (base_url, rule.product_id)
            primary_tools, backup_tools = modern_tool_order(rule)
            item = by_key.setdefault(key, {
                "checked_at": now_iso(),
                "base_url": base_url,
                "host": host_of(base_url),
                "product_id": rule.product_id,
                "product": rule.display_name,
                "family": rule.family,
                "branch": rule.branch,
                "score": 0,
                "confidence": "low",
                "primary_tools": primary_tools,
                "backup_tools": backup_tools,
                "default_action": "queue_only",
                "notes": rule.notes,
                "evidence": [],
                "template_matches": template_matches_by_product[rule.product_id],
            })
            increment = source_weight(source) + min(15, 4 * len(matched))
            if source == "verified_exposures" and row.get("verification_score"):
                increment += min(12, int(row.get("verification_score") or 0))
            item["score"] += increment
            item["evidence"].append({
                "source": source,
                "matched_patterns": matched[:4],
                "url": row.get("url") or row.get("base_url"),
                "path": row.get("path"),
                "kind": row.get("kind"),
                "title": row.get("title"),
                "finding": row.get("finding"),
                "status": row.get("status"),
            })

    findings = []
    for item in by_key.values():
        item["score"] = min(100, int(item["score"]))
        item["confidence"] = confidence_label(item["score"])
        # 二次佐证规则：证据全部来自 impact_candidates（JS 关键词）的指纹，
        # 无论分数多高一律封顶 low——第三方压缩库里的 't+'/'redis' 命中不构成产品存在证明。
        ev_sources = {e.get("source") for e in item["evidence"]}
        if ev_sources and ev_sources <= {"impact_candidates"}:
            item["confidence"] = "low"
            item["notes"] = (item.get("notes") or "") + " | JS-keyword-only match, needs corroboration"
        item["evidence"] = item["evidence"][:8]
        findings.append(item)
    findings.sort(key=lambda row: (-row["score"], row["family"], row["host"], row["product_id"]))
    return findings


def build_vuln_candidates(findings: list[dict]) -> list[dict]:
    candidates: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for finding in findings:
        product_id = str(finding.get("product_id") or "")
        rules = list(VULN_CANDIDATE_RULES.get(product_id, ()))
        if product_id in JAVA_STACK_PRODUCT_IDS and product_id != "log4j":
            rules.extend(VULN_CANDIDATE_RULES["log4j"])
        for rule in rules:
            key = (
                str(finding.get("base_url") or ""),
                product_id,
                str(rule["candidate_type"]),
            )
            if key in seen:
                continue
            seen.add(key)
            candidates.append({
                "checked_at": now_iso(),
                "base_url": finding.get("base_url"),
                "host": finding.get("host"),
                "product_id": product_id,
                "product": finding.get("product"),
                "family": finding.get("family"),
                "confidence": finding.get("confidence"),
                "score": finding.get("score"),
                "candidate_type": rule["candidate_type"],
                "teacher_focus": rule["teacher_focus"],
                "safe_review": rule["safe_review"],
                "approval_gate": rule["approval_gate"],
                "evidence_to_collect": rule["evidence_to_collect"],
                "recommended_review": rule["recommended_review"],
                "do_not_do": rule["do_not_do"],
                "default_action": "queue_only",
                "auto_exploit": False,
                "response_body_persisted": False,
            })
    candidates.sort(key=lambda row: (-(int(row.get("score") or 0)), row["candidate_type"], row["host"] or ""))
    return candidates


def write_outputs(run_dir: Path, findings: list[dict]) -> dict:
    reports = run_dir / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    vuln_candidates = build_vuln_candidates(findings)
    inventory_counts = defaultdict(int)
    for template in template_inventory():
        inventory_counts[template["tool"]] += 1

    jsonl_path = run_dir / "product_fingerprints.jsonl"
    with jsonl_path.open("w", encoding="utf-8") as handle:
        for item in findings:
            handle.write(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n")

    csv_path = run_dir / "product_triage_queue.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=[
            "base_url",
            "host",
            "product",
            "family",
            "confidence",
            "score",
            "branch",
            "primary_tools",
            "backup_tools",
            "review_templates",
            "approval_templates",
            "default_action",
        ])
        writer.writeheader()
        for item in findings:
            templates = item.get("template_matches") or {}
            writer.writerow({
                "base_url": item["base_url"],
                "host": item["host"],
                "product": item["product"],
                "family": item["family"],
                "confidence": item["confidence"],
                "score": item["score"],
                "branch": item["branch"],
                "primary_tools": ";".join(item["primary_tools"]),
                "backup_tools": ";".join(item["backup_tools"]),
                "review_templates": ";".join(row["name"] for row in templates.get("review_readonly", [])[:8]),
                "approval_templates": ";".join(row["name"] for row in templates.get("approval_required", [])[:8]),
                "default_action": item["default_action"],
            })

    vuln_jsonl_path = run_dir / "product_vuln_candidates.jsonl"
    with vuln_jsonl_path.open("w", encoding="utf-8") as handle:
        for item in vuln_candidates:
            handle.write(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n")

    vuln_csv_path = run_dir / "product_vuln_candidate_queue.csv"
    with vuln_csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=[
            "base_url",
            "host",
            "product",
            "family",
            "confidence",
            "score",
            "candidate_type",
            "teacher_focus",
            "safe_review",
            "approval_gate",
            "evidence_to_collect",
            "recommended_review",
            "do_not_do",
            "default_action",
        ])
        writer.writeheader()
        for item in vuln_candidates:
            writer.writerow({
                "base_url": item["base_url"],
                "host": item["host"],
                "product": item["product"],
                "family": item["family"],
                "confidence": item["confidence"],
                "score": item["score"],
                "candidate_type": item["candidate_type"],
                "teacher_focus": item["teacher_focus"],
                "safe_review": item["safe_review"],
                "approval_gate": item["approval_gate"],
                "evidence_to_collect": item["evidence_to_collect"],
                "recommended_review": item["recommended_review"],
                "do_not_do": item["do_not_do"],
                "default_action": item["default_action"],
            })

    family_counts = defaultdict(int)
    product_counts = defaultdict(int)
    high_count = 0
    for item in findings:
        family_counts[item["family"]] += 1
        product_counts[item["product_id"]] += 1
        if item["confidence"] == "high":
            high_count += 1
    summary = {
        "generated_at": now_iso(),
        "run_dir": str(run_dir),
        "finding_count": len(findings),
        "vuln_candidate_count": len(vuln_candidates),
        "high_confidence_count": high_count,
        "family_counts": dict(sorted(family_counts.items())),
        "product_counts": dict(sorted(product_counts.items())),
        "template_inventory": {
            "nuclei-templates": {
                "root": str(NUCLEI_TEMPLATE_ROOT),
                "yaml_count": inventory_counts.get("nuclei-templates", 0),
            },
            "dddd-legacy": {
                "root": str(DDDD_POC_DIR),
                "yaml_count": inventory_counts.get("dddd-legacy", 0),
            },
            "OA-EXPTOOL-legacy": {
                "root": str(OA_EXP_BOOK_DIR),
                "yaml_count": inventory_counts.get("OA-EXPTOOL-legacy", 0),
            },
        },
        "outputs": {
            "jsonl": str(jsonl_path),
            "csv": str(csv_path),
            "vuln_jsonl": str(vuln_jsonl_path),
            "vuln_csv": str(vuln_csv_path),
            "vuln_markdown": str(reports / "product_vuln_candidate_queue.md"),
            "markdown": str(reports / "product_triage.md"),
        },
        "default_policy": "queue_only_no_live_exploitation",
    }
    summary_path = run_dir / "product_triage_summary.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    md_path = reports / "product_triage.md"
    lines = [
        "# Product-Aware Triage",
        "",
        f"- Generated: {summary['generated_at']}",
        f"- Items: {len(findings)}",
        f"- Default policy: `{summary['default_policy']}`",
        f"- Local templates: nuclei={inventory_counts.get('nuclei-templates', 0)}, dddd-legacy={inventory_counts.get('dddd-legacy', 0)}, OA-EXPTOOL-legacy={inventory_counts.get('OA-EXPTOOL-legacy', 0)}",
        "",
        "| Rank | Score | Confidence | Host | Product | Branch | Tools |",
        "| --- | ---: | --- | --- | --- | --- | --- |",
    ]
    for idx, item in enumerate(findings[:100], 1):
        tools = ", ".join(item["primary_tools"])
        lines.append(
            f"| {idx} | {item['score']} | {item['confidence']} | `{item['host']}` | "
            f"{item['product']} | `{item['branch']}` | {tools} |"
        )
    lines.extend([
        "",
        "## Notes",
        "",
        "- This queue is offline triage. It does not prove a vulnerability.",
        "- `review_readonly` templates are suitable for manual low-rate confirmation.",
        "- `approval_required` templates include uploads, RCE, auth bypass, credential, or sensitive file checks and are not default automation.",
    ])
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    vuln_md_path = reports / "product_vuln_candidate_queue.md"
    vuln_lines = [
        "# Product Vulnerability Candidate Queue",
        "",
        f"- Generated: {summary['generated_at']}",
        f"- Items: {len(vuln_candidates)}",
        "- Default policy: `queue_only_no_live_exploitation`",
        "- Fastjson, Log4j, Struts2 and similar checks are candidates here; active payload validation is not automatic.",
        "",
        "| Rank | Score | Confidence | Host | Product | Candidate | Safe Review |",
        "| --- | ---: | --- | --- | --- | --- | --- |",
    ]
    for idx, item in enumerate(vuln_candidates[:150], 1):
        vuln_lines.append(
            f"| {idx} | {item['score']} | {item['confidence']} | `{item['host']}` | "
            f"{item['product']} | `{item['candidate_type']}` | {item['safe_review']} |"
        )
    vuln_lines.extend([
        "",
        "## Why These Are Emphasized",
        "",
        "- Fastjson, Log4j, and Struts2 are common Java ecosystem risk families with historically high-impact RCE/deserialization paths.",
        "- Spring Boot, Nacos, Shiro, ThinkPHP, and domestic OA/ERP products often expose valuable management, auth-boundary, API, or file-handling surfaces.",
        "- This file is a review queue, not proof of vulnerability.",
    ])
    vuln_md_path.write_text("\n".join(vuln_lines) + "\n", encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Build offline product-aware triage queue")
    parser.add_argument("--run-dir", type=Path, required=True)
    args = parser.parse_args()
    findings = build_findings(args.run_dir)
    print(json.dumps(write_outputs(args.run_dir, findings), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
