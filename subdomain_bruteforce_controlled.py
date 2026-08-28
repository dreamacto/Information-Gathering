#!/usr/bin/env python3
"""Controlled subdomain discovery for authorized exercise runs.

This stage performs low-rate DNS lookups for a small, explicit wordlist. Each
input hostname is a scope anchor: the stage may look below that hostname, but it
must never widen a subdomain to its registered parent or discover sibling
hosts. Resolved hosts are written to handoff files for the next run.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import re
import socket
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen


try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

os.environ.setdefault("PYTHONUTF8", "1")
os.environ.setdefault("PYTHONIOENCODING", "utf-8")


DEFAULT_WORDS = (
    "www",
    "api",
    "app",
    "m",
    "wap",
    "mobile",
    "admin",
    "oa",
    "office",
    "portal",
    "login",
    "sso",
    "auth",
    "cas",
    "id",
    "ids",
    "mail",
    "email",
    "webmail",
    "vpn",
    "ssl",
    "hr",
    "edu",
    "jw",
    "jwc",
    "ehall",
    "service",
    "servicehall",
    "pay",
    "payment",
    "bank",
    "banking",
    "credit",
    "loan",
    "fund",
    "trade",
    "trading",
    "invest",
    "crm",
    "cms",
    "www1",
    "www2",
    "test",
    "dev",
    "uat",
    "stage",
    "staging",
    "pre",
    "prod",
    "old",
    "new",
    "static",
    "assets",
    "cdn",
    "img",
    "file",
    "files",
    "download",
    "upload",
    "open",
    "openapi",
    "gateway",
    "gw",
    "manage",
    "manager",
    "backend",
    "console",
    "monitor",
    "druid",
    "nacos",
    "xxl-job",
    "jenkins",
    "git",
    "svn",
    "wiki",
    "doc",
    "docs",
    "help",
    "support",
    "shop",
    "shop2",
    "shop3",
    "mall",
    "mall2",
    "b2b",
    "b2c",
    "c2c",
    "supplier",
    "supplier2",
    "supply",
    "customer",
    "customers",
    "partner",
    "dealer",
    "agency",
    "channel",
    "store",
    "stores",
    "mall3",
    "goods",
    "product",
    "products",
    "item",
    "items",
    "sku",
    "stock",
    "inventory",
    "order",
    "orders",
    "cashier",
    "checkout",
    "settle",
    "settlement",
    "funds",
    "billing",
    "bill",
    "invoice",
    "recharge",
    "withdraw",
    "coin",
    "points",
    "insure",
    "finance",
    "tax",
    "capital",
    "investor",
    "holding",
    "pay1",
    "pay2",
    "pay3",
    "pays",
    "payment2",
    "cashier2",
    "coupon",
    "promotion",
    "market",
    "marketing",
    "activity",
    "lottery",
    "seckill",
    "trade2",
    "weixin",
    "wx",
    "wx2",
    "mp",
    "miniprogram",
    "applet",
    "applets",
    "h5",
    "ios",
    "android",
    "apk",
    "pad",
    "client",
    "down",
    "dl",
    "wap2",
    "m2",
    "mobile2",
    "h5api",
    "management",
    "console2",
    "backend2",
    "cms2",
    "boss",
    "dashboard",
    "system",
    "sys",
    "core",
    "ops",
    "sre",
    "devops",
    "monitoring",
    "admin1",
    "admin2",
    "admin3",
    "admin4",
    "log",
    "logs",
    "log2",
    "elk",
    "kibana",
    "grafana",
    "grafana2",
    "prometheus",
    "zabbix",
    "nagios",
    "zipkin",
    "skywalking",
    "jaeger",
    "sentinel",
    "apollo",
    "apollo2",
    "nacos2",
    "eureka",
    "consul",
    "etcd",
    "registry",
    "config2",
    "xxljob",
    "job",
    "jobs",
    "task",
    "tasks",
    "schedule",
    "scheduler",
    "queue",
    "mq",
    "rocketmq",
    "rabbitmq",
    "kafka",
    "zookeeper",
    "zk2",
    "redis2",
    "memcached",
    "mongodb",
    "mongo",
    "mysql2",
    "mssql",
    "oracle",
    "postgres",
    "pgsql",
    "influxdb",
    "influx",
    "tidb",
    "clickhouse",
    "es",
    "es2",
    "elastic",
    "search2",
    "solr",
    "solr2",
    "sphinx",
    "mq1",
    "mq2",
    "es1",
    "es3",
    "redis1",
    "db1",
    "db2",
    "db3",
    "kafka1",
    "kafka2",
    "gitlab",
    "gitea",
    "gogs",
    "svn2",
    "jenkins2",
    "ci",
    "cd",
    "drone",
    "runner",
    "harbor",
    "registry2",
    "docker",
    "k8s",
    "kube",
    "kubernetes",
    "rancher",
    "sonar",
    "sonarqube",
    "npm",
    "pypi",
    "mirror",
    "mirrors",
    "repo",
    "repos",
    "maven",
    "nexus",
    "confluence2",
    "wiki2",
    "jira",
    "git1",
    "git2",
    "jenkins1",
    "jenkins3",
    "erp",
    "oms",
    "wms",
    "scm",
    "mes",
    "plm",
    "bi",
    "bi2",
    "report",
    "reports",
    "data",
    "datas",
    "dw",
    "analysis",
    "analyze",
    "olap",
    "etl",
    "kettle",
    "airflow",
    "feishu",
    "lark",
    "dingding",
    "dingtalk",
    "qywx",
    "exmail",
    "meeting",
    "conference",
    "video",
    "vod",
    "live",
    "live2",
    "rtmp",
    "push",
    "im2",
    "msg",
    "message",
    "sms2",
    "email2",
    "mail3",
    "pan",
    "netdisk",
    "fileserver",
    "ftp2",
    "sftp",
    "nas",
    "uploads",
    "media",
    "media2",
    "image",
    "images",
    "pic",
    "pics",
    "photo",
    "photos",
    "avatar",
    "statics",
    "res",
    "resource",
    "resources",
    "crm1",
    "crm2",
    "erp1",
    "erp2",
    "file1",
    "file2",
    "img1",
    "img2",
    "static1",
    "static2",
    "cdn1",
    "cdn2",
    "cdn3",
    "oss",
    "cos",
    "qiniu",
    "upyun",
    "doc2",
    "faq",
    "ask",
    "know",
    "knowledge",
    "kb",
    "share",
    "shared",
    "wiki3",
    "oauth",
    "oauth2",
    "token",
    "session",
    "otp",
    "mfa",
    "vault",
    "bastion",
    "jumpserver",
    "jms",
    "waf",
    "ca",
    "kms",
    "gateway2",
    "apigw",
    "open2",
    "openapi2",
    "inner",
    "internal",
    "intranet",
    "outer",
    "external",
    "soa",
    "rpc",
    "grpc",
    "graphql",
    "rest",
    "restful",
    "service2",
    "services",
    "sso1",
    "sso2",
    "sso3",
    "cas1",
    "cas2",
    "cas3",
    "auth1",
    "auth2",
    "auth3",
    "id1",
    "id2",
    "vpn1",
    "vpn2",
    "vpn3",
    "ssl1",
    "ssl2",
    "edu2",
    "jw2",
    "jwc2",
    "ehall2",
    "hall",
    "hall2",
    "onehall",
    "zwfw",
    "exam",
    "exams",
    "paper",
    "papers",
    "question",
    "questions",
    "learn",
    "learning",
    "study",
    "train",
    "training",
    "teach",
    "teacher",
    "student",
    "students",
    "class",
    "course",
    "courses",
    "mooc",
    "library",
    "lib",
    "research",
    "journal",
    "news2",
    "article",
    "articles",
    "content",
    "blog2",
    "forum2",
    "bbs2",
    "comment",
    "comments",
    "community",
    "group2",
    "groups",
    "team",
    "teams",
    "ent",
    "corp",
    "corporate",
    "company",
    "announce",
    "announcement",
    "notice",
    "notify2",
    "calendar",
    "hr3",
    "jobs2",
    "recruit",
    "recruiting",
    "resume",
    "resumes",
    "talent",
    "salary",
    "payroll",
    "kpi",
    "okr",
    "office2",
    "meeting2",
    "legal",
    "contract",
    "audit",
    "compliance",
    "risk",
    "web1",
    "web2",
    "web3",
    "web4",
    "app1",
    "app2",
    "app3",
    "app4",
    "api1",
    "api2",
    "api3",
    "api4",
    "test1",
    "test2",
    "test3",
    "test4",
    "dev1",
    "dev2",
    "dev3",
    "dev4",
    "server1",
    "server2",
    "server3",
    "node1",
    "node2",
    "node3",
    "srv",
    "ha",
    "master",
    "slave",
    "cluster",
    "v2",
    "v3",
    "v4",
    "beta",
    "release",
    "publish",
    "gray",
    "preprod",
    "sandbox",
    "demo2",
    "uat2",
    "sit2",
    "bak2",
    "old2",
    "new2",
    "ng",
    "lb",
    "proxy",
    "cache",
    "m1",
    "m3",
    "www3",
    "mail1",
    "mail2",
    "oa1",
    "oa2",
    "oa3",
    "hr1",
    "hr2",
    "shop1",
    "home",
    "index",
    "main",
    "user",
    "users",
    "user2",
    "users2",
    "member",
    "members",
    "member2",
    "vip",
    "vip2",
    "guest",
    "account",
    "accounts",
    "profile",
    "mine",
    "my",
    "center",
    "uc",
    "passport",
    "passport2",
    "feedback",
    "survey",
    "vote",
    "poll",
    "award",
    "gift",
    "card",
    "card2",
    "card3",
    "ping",
    "trace",
    "ns1",
    "ns2",
    "ns3",
    "dns",
    "dns2",
    "dns3",
    "mx",
    "mx2",
    "mx3",
    "smtp2",
    "pop3",
    "imap2",
    "webmail2",
    "rdns",
    "whois",
    "telnet",
    "snmp",
    "ssh2",
    "rdp2",
    "nginx2",
    "apache2",
    "tomcat2",
    "tomcat3",
    "iis2",
    "jboss2",
    "weblogic2",
    "websphere",
    "resin",
    "jetty",
    "undertow",
    "thinkphp2",
    "laravel2",
    "spring",
    "springboot",
    "springcloud",
    "springcloud2",
    "dubbo",
    "gateway4",
    "show",
    "preview",
    "print",
    "export",
    "import2",
    "temp",
    "tmp",
    "tmp2",
    "demo3",
    "sample",
    "gz",
    "sz",
    "sh",
    "bj",
    "cq",
    "hz",
    "nj",
    "tj",
    "wh",
    "cs",
    "xn",
    "jump",
    "proxy2",
    "tunnel",
    "relay",
    "forward",
    "redirect",
    "short",
    "shorturl",
    "tinyurl",
    "link",
    "links",
    "url",
    "urls",
    "hot",
    "rank",
    "ranking",
    "top",
    "recommend",
    "guess",
    "like",
    "follow",
    "fans",
    "ai",
    "llm",
    "chat",
    "chat2",
    "gpt",
    "bot",
    "bots",
    "assistant",
    "assistant2",
    "knowledge2",
    "rag",
    "ollama",
    "iot",
    "mqtt",
    "mqtt2",
    "coap",
    "device",
    "devices",
    "sensor",
    "sensors",
    "game",
    "games",
    "play",
    "play2",
    "chess",
    "cardgame",
    "quiz",
    "puzzle",
    "music",
    "movie",
    "movies",
    "novel",
    "book",
    "books",
    "read",
    "reader",
    "reader2",
    "comic",
    "anime",
    "travel",
    "flight",
    "hotel",
    "hotels",
    "bus",
    "trip",
    "journey",
    "visa",
    "health",
    "medical",
    "hospital",
    "doctor",
    "patient",
    "drug",
    "pharmacy",
    "lawyer",
    "notary",
    "court",
    "policy",
    "regulation",
    "startup",
    "incubator",
    "maker",
    "space",
    "lab",
    "lab2",
    "labs",
    "experiment",
    "innovation",
    "tag",
    "tags",
    "category",
    "categories",
    "label",
    "filter",
    "sort",
    "cron",
    "crontab",
    "timer",
    "timer2",
    "event",
    "events",
    "trigger",
    "hooks",
    "hook",
    "stat",
    "stats",
    "metrics",
    "metric",
    "count",
    "counter",
    "analytics",
    "tracking",
    "tracker",
    "apm",
    "apm2",
    "ab",
    "gray2",
    "canary",
    "feature",
    "flag",
    "switch",
    "config3",
    "cdn4",
    "img3",
    "pic3",
    "s3",
    "bucket",
    "buckets",
    "storage",
    "stor",
    "backup2",
    "backups",
    "archive",
    "archives",
    "ssl4",
    "tls",
    "cert",
    "certs",
    "pki",
    "jks",
    "keystore",
    "monitor2",
    "uptime",
    "status2",
    "status3",
    "health2",
    "heartbeat",
    "nav",
    "nav2",
    "menu",
    "sitemap",
    "rss",
    "atom",
    "feed",
    "feeds",
    "csv",
    "excel",
    "export2",
    "import3",
    "data3",
    "sync",
    "sync2",
    "async",
    "worker",
    "workers",
    "queue2",
    "queue3",
    "test5",
    "dev5",
    "stage2",
    "product2",
    "master2",
    "develop",
    "regression",
    "pressure",
    "stress",
    "load2",
)


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def append_jsonl(path: Path, row: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def host_of(value: str) -> str:
    raw = value.strip().split("|", 1)[0].strip()
    if not raw or raw.startswith("#"):
        return ""
    if "://" not in raw:
        raw = "https://" + raw
    return (urlparse(raw).hostname or "").strip(".").lower()


def is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def is_subdomain_root_candidate(root: str) -> bool:
    parts = [part for part in root.strip(".").lower().split(".") if part]
    if len(parts) < 2:
        return False
    if all(part.isdigit() for part in parts):
        return False
    try:
        ".".join(parts).encode("idna")
    except UnicodeError:
        return False
    return True


def intake_scope_hints(anchors: list[str]) -> list[dict]:
    """入口作用域预警（20260823 复盘）：锚点是主机名而非根域时，
    子域枚举只会查 <词>.<主机名> 形态（如 api.www.gxcic.net），现实中几乎必空。
    不自动扩大范围（授权决策属于操作者），但必须在开工前说清楚。"""
    hints = []
    for a in anchors:
        parent = registered_parent(a)
        if parent and a != parent:
            hints.append({
                "anchor": a,
                "registered_parent": parent,
                "effect": f"输入为主机名：原锚点只会查询 *.{a}（几乎必空）；本次已自动补充根域锚点 {parent}（操作者策略 20260823）",
                "suggestion": f"结果按后缀过滤只保留 *.{parent}；若某目标仅授权该主机、不含整域，请单独建 run 并加 --no-subdomain",
            })
    return hints


def registered_parent(host: str) -> str:
    host = host.strip(".").lower()
    if not host or is_ip_address(host):
        return ""
    parts = [part for part in host.split(".") if part]
    if len(parts) <= 2:
        return host if is_subdomain_root_candidate(host) else ""
    second_level_suffixes = {
        "com.cn",
        "net.cn",
        "org.cn",
        "gov.cn",
        "edu.cn",
        "ac.cn",
        "mil.cn",
    }
    suffix = ".".join(parts[-2:])
    if suffix in second_level_suffixes and len(parts) >= 3:
        root = ".".join(parts[-3:])
        return root if is_subdomain_root_candidate(root) else ""
    root = ".".join(parts[-2:])
    return root if is_subdomain_root_candidate(root) else ""


def load_scope_anchors(targets: Path) -> list[str]:
    """Load exact input hosts without widening them to registered parents."""
    anchors: set[str] = set()
    if targets.suffix.lower() == ".csv":
        with targets.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                host = (row.get("host") or host_of(row.get("url") or "")).strip().lower()
                if host and not is_ip_address(host) and is_subdomain_root_candidate(host):
                    anchors.add(host)
        return sorted(anchors)
    for line in targets.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        host = host_of(line)
        if host and not is_ip_address(host) and is_subdomain_root_candidate(host):
            anchors.add(host)
    return sorted(anchors)


def load_roots(targets: Path) -> list[str]:
    """Compatibility alias; values are exact input scope anchors, not roots."""
    return load_scope_anchors(targets)


def is_host_within_scope(host: str, scope_anchor: str) -> bool:
    host = host.strip(".").lower()
    scope_anchor = scope_anchor.strip(".").lower()
    return bool(host and scope_anchor) and (
        host == scope_anchor or host.endswith("." + scope_anchor)
    )


def scope_anchor_for(host: str, scope_anchors: list[str]) -> str:
    matches = [
        anchor
        for anchor in scope_anchors
        if is_host_within_scope(host, anchor)
    ]
    return max(matches, key=len, default="")


def load_existing_target_lines(targets: Path) -> list[str]:
    lines: list[str] = []
    if targets.suffix.lower() == ".csv":
        with targets.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                url = str(row.get("url") or "").strip()
                if not url:
                    continue
                name = str(row.get("name") or "").strip()
                lines.append(f"{url}|{name}" if name else url)
        return lines
    for line in targets.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        value = line.strip()
        if value and not value.startswith("#"):
            lines.append(value)
    return lines


def dedup_target_lines(lines: list[str]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for line in lines:
        url = line.split("|", 1)[0].strip()
        if not url:
            continue
        key = url.rstrip("/").lower()
        if key in seen:
            continue
        seen.add(key)
        output.append(line)
    return output


def load_words(path: Path | None, max_words: int) -> list[str]:
    words: list[str] = []
    if path and path.exists():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            value = line.strip().lower()
            if value and not value.startswith("#"):
                words.append(value.split()[0])
    else:
        words.extend(DEFAULT_WORDS)
    dedup = []
    seen = set()
    for word in words:
        word = word.strip(".")
        if not word or word in seen:
            continue
        seen.add(word)
        dedup.append(word)
    if max_words > 0:
        return dedup[:max_words]
    return dedup


def resolve_host(host: str, timeout: float) -> tuple[list[str], str]:
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        return [], f"dns_error:{exc.errno}"
    except OSError as exc:
        return [], f"os_error:{type(exc).__name__}"
    finally:
        socket.setdefaulttimeout(old_timeout)
    ips = sorted({item[4][0] for item in infos if item and item[4]})
    return ips, ""


class RateGate:
    """Global start-rate limiter for DNS lookups."""

    def __init__(self, interval: float) -> None:
        self.interval = max(0.0, interval)
        self._lock = threading.Lock()
        self._next_start = 0.0

    def wait(self) -> None:
        if self.interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            if now < self._next_start:
                sleep_for = self._next_start - now
                self._next_start += self.interval
            else:
                sleep_for = 0.0
                self._next_start = now + self.interval
        if sleep_for > 0:
            time.sleep(sleep_for)


def build_queries(scope_anchors: list[str], words: list[str], max_queries: int) -> list[tuple[str, str]]:
    queries = [
        (scope_anchor, f"{word}.{scope_anchor}".lower())
        for scope_anchor in scope_anchors
        for word in words
    ]
    if max_queries > 0:
        return queries[:max_queries]
    return queries


_CT_NAME_OK = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")


def _ct_filter(names: set, domain: str) -> list[str]:
    out = set()
    for name in names:
        name = str(name).strip().lstrip("*.").lower()
        if not name or name == domain:
            continue
        if not name.endswith("." + domain):
            continue
        if ".." in name or not _CT_NAME_OK.fullmatch(name):
            continue
        out.add(name)
    return sorted(out)


def _ct_crtsh(domain: str, timeout: float = 25.0) -> tuple[set, str]:
    """crt.sh 证书透明日志（间歇性 502 是常态，调用方负责重试与降级）。"""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        req = Request(url, headers={"User-Agent": "Mozilla/5.0 (authorized-subdomain-ct-lookup)"})
        with urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception as exc:  # noqa: BLE001
        return set(), f"{type(exc).__name__}: {str(exc)[:100]}"
    names = set()
    for entry in data if isinstance(data, list) else []:
        for raw in str(entry.get("name_value", "")).splitlines():
            names.add(raw)
    return names, ""


def _ct_rapiddns(domain: str, timeout: float = 20.0) -> tuple[set, str]:
    """rapiddns.io 被动 DNS 聚合（免费无 key，HTML 提取）。"""
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    try:
        req = Request(url, headers={"User-Agent": "Mozilla/5.0 (authorized-subdomain-passive-lookup)"})
        with urlopen(req, timeout=timeout) as resp:
            html = resp.read().decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001
        return set(), f"{type(exc).__name__}: {str(exc)[:100]}"
    pattern = re.compile(r"[a-zA-Z0-9_-](?:[a-zA-Z0-9_.-]*[a-zA-Z0-9_-])?\." + re.escape(domain))
    return {m.group(0) for m in pattern.finditer(html)}, ""


def ct_log_names(domain: str, timeout: float = 25.0) -> tuple[list[str], str]:
    """被动源链（2026-08-23）：crt.sh（1 次重试）→ rapiddns 兜底，取并集。

    只查第三方被动服务、不碰目标；返回的名字随后仍走 DNS 验证。
    全部源失败才返回错误串，调用方降级为纯字典模式。
    """
    names: set = set()
    errors: list[str] = []
    for attempt in range(2):
        got, err = _ct_crtsh(domain, timeout)
        if not err:
            names |= got
            break
        errors.append(f"crt.sh#{attempt + 1}: {err}")
        time.sleep(2)
    got, err = _ct_rapiddns(domain, min(timeout, 20.0))
    if err:
        errors.append(f"rapiddns: {err}")
    else:
        names |= got
    if not names and errors:
        return [], "; ".join(errors)
    return _ct_filter(names, domain), ""


def detect_wildcard_parents(parents: list[str], probes: int = 2, timeout: float = 3.0) -> dict[str, list[str]]:
    """泛解析检测（操作者实测反馈 20260827）：对注册父域用随机不存在前缀做 DNS 探测，
    能解析即判定该父域开了 wildcard——字典里所有候选都会"解析成功"，全是同 IP 噪声。
    返回 {parent: [泛解析答案 IP...]}（仅命中者）。"""
    import secrets
    result: dict[str, list[str]] = {}
    for parent in sorted(set(p for p in parents if p)):
        hits: set[str] = set()
        for _ in range(max(1, probes)):
            label = "zx-wc-" + secrets.token_hex(5)
            try:
                infos = socket.getaddrinfo(f"{label}.{parent}", None)
            except OSError:
                continue
            for info in infos:
                ip = str(info[4][0]) if info and info[4] else ""
                if ip:
                    hits.add(ip)
        if hits:
            result[parent] = sorted(hits)
    return result


def split_wildcard_results(
    host_ips: dict[str, set[str]], wildcard_map: dict[str, list[str]]
) -> tuple[list[str], list[str]]:
    """泛解析过滤：父域命中 wildcard 时，丢弃 IP 完全落在泛解析答案集内的候选；
    解析到其它 IP 的主机保留（可能是真实站点）。返回 (kept_hosts, dropped_hosts)。"""
    kept: list[str] = []
    dropped: list[str] = []
    for host in sorted(host_ips):
        wc = wildcard_map.get(registered_parent(host))
        ips = host_ips.get(host) or set()
        if wc and ips and ips <= set(wc):
            dropped.append(host)
        else:
            kept.append(host)
    return kept, dropped


def resolve_query(scope_anchor: str, host: str, timeout: float, gate: RateGate) -> dict:
    gate.wait()
    ips, error = resolve_host(host, timeout)
    return {
        "checked_at": now_iso(),
        "scope_anchor": scope_anchor,
        "registered_parent": registered_parent(host),
        "host": host,
        "ips": ",".join(ips),
        "status": "resolved" if ips else "unresolved",
        "error": error,
    }


def write_csv(path: Path, rows: list[dict]) -> None:
    fieldnames = [
        "checked_at",
        "scope_anchor",
        "registered_parent",
        "host",
        "ips",
        "status",
        "error",
        "source",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})


def main() -> int:
    parser = argparse.ArgumentParser(description="Low-rate subdomain brute-force discovery")
    parser.add_argument("--targets", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--wordlist", type=Path)
    parser.add_argument("--delay", type=float, default=1.5)
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--max-words", type=int, default=80)
    parser.add_argument(
        "--max-roots",
        "--max-scope-anchors",
        dest="max_roots",
        type=int,
        default=20,
        help="Maximum exact input host scope anchors; input hosts are never widened",
    )
    parser.add_argument("--qps", type=float, default=0.0, help="Global DNS lookup start rate; overrides --delay when > 0")
    parser.add_argument("--concurrency", type=int, default=3, help="Concurrent DNS workers; global qps/delay is still enforced")
    parser.add_argument("--no-ct-logs", action="store_true", help="跳过 crt.sh CT 日志源（离线环境/只想要字典模式时用）")
    parser.add_argument("--max-queries", type=int, default=0, help="Maximum total DNS queries after root/word expansion")
    args = parser.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    scope_anchors = load_scope_anchors(args.targets)[
        : args.max_roots if args.max_roots > 0 else None
    ]
    # 根域自动锚定（操作者策略 20260823）：输入主机名（如 www.gxcic.net）时自动补充其
    # 注册父域作为锚点，使枚举生成 api.gxcic.net 这类真实形态；结果仍经
    # is_host_within_scope 后缀过滤——只有 *.根域 内的主机会进入后续流程。
    _expanded = list(scope_anchors)
    for _a in scope_anchors:
        _parent = registered_parent(_a)
        if _parent and _parent not in _expanded:
            _expanded.append(_parent)
    if _expanded != scope_anchors:
        _added = [a for a in _expanded if a not in scope_anchors]
        print(f"[*] 根域自动锚定（操作者策略）：已补充根域锚点 {', '.join(_added)}；"
              f"结果按后缀过滤，仅 *.根域 内主机进入后续流程", flush=True)
        scope_anchors = _expanded
    words = load_words(args.wordlist, args.max_words)
    wildcard_map = detect_wildcard_parents(
        [registered_parent(a) for a in scope_anchors], timeout=args.timeout
    )
    if wildcard_map:
        detail = ", ".join(f"{p} → {'/'.join(ips[:2])}{'…' if len(ips) > 2 else ''}" for p, ips in sorted(wildcard_map.items()))
        print(f"[!] 检测到泛解析（wildcard DNS）：{detail}", flush=True)
        print("[!] 字典/被动源命中的候选若仍解析到同一批 IP，将被判为泛解析噪声过滤，不进入自动合并。", flush=True)
    hints = intake_scope_hints(scope_anchors)
    if hints:
        print("[!] 目标作用域预警：以下锚点是主机名而非根域，子域枚举按纪律不扩大范围——", flush=True)
        for h in hints:
            print(f"      · {h['anchor']}：{h['effect']}", flush=True)
            print(f"        {h['suggestion']}", flush=True)
        hint_path = args.out_dir / "subdomain_intake_hints.jsonl"
        with hint_path.open("w", encoding="utf-8") as hf:
            for h in hints:
                hf.write(json.dumps(h, ensure_ascii=False) + "\n")
    raw_path = args.out_dir / "subdomains_raw.txt"
    dedup_path = args.out_dir / "subdomains_dedup.txt"
    pending_path = args.out_dir / "subdomains_for_scope_confirmation.txt"
    next_targets_path = args.out_dir / "subdomains_for_next_run.txt"
    auto_merged_path = args.out_dir / "targets_with_auto_subdomains.txt"
    jsonl_path = args.out_dir / "subdomains_resolved.jsonl"
    csv_path = args.out_dir / "subdomains_resolved.csv"
    rejected_path = args.out_dir / "subdomain_scope_rejections.jsonl"
    manifest_path = args.out_dir / "subdomain_bruteforce_manifest.json"

    for path in (
        raw_path,
        dedup_path,
        pending_path,
        next_targets_path,
        auto_merged_path,
        jsonl_path,
        rejected_path,
    ):
        path.write_text("", encoding="utf-8")

    interval = (1.0 / args.qps) if args.qps and args.qps > 0 else max(0.0, args.delay)
    concurrency = max(1, int(args.concurrency))
    queries = build_queries(scope_anchors, words, args.max_queries)
    rows: list[dict] = []
    gate = RateGate(interval)

    # CT 证书透明日志源（2026-08-23）：crt.sh 被动查询补字典盲区——历史签发记录里
    # 常有 xz-payment-2 这类字典永远猜不到的名字。拿到的名字仍逐个过 DNS 验证，
    # 只留解析成功的；crt.sh 不可达时告警降级为纯字典模式（不打断流程）。
    ct_hosts: set[str] = set()
    if not args.no_ct_logs:
        for anchor in scope_anchors:
            if "." not in anchor:
                continue
            names, err = ct_log_names(anchor)
            if err:
                print(f"[!] CT 日志查询失败（{anchor}）: {err}，降级为纯字典", flush=True)
                continue
            existing = {host for _, host in queries}
            fresh = [n for n in names if n not in existing]
            ct_hosts.update(fresh)
            queries.extend((anchor, n) for n in fresh)
            print(f"[*] CT 日志（{anchor}）: {len(names)} 个候选名，新增 {len(fresh)} 个进入 DNS 验证", flush=True)

    if concurrency == 1:
        for scope_anchor, host in queries:
            row = resolve_query(scope_anchor, host, args.timeout, gate)
            row["source"] = "ct_log" if host in ct_hosts else "wordlist"
            rows.append(row)
            append_jsonl(jsonl_path, row)
    else:
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            futures = [
                pool.submit(resolve_query, scope_anchor, host, args.timeout, gate)
                for scope_anchor, host in queries
            ]
            for future in as_completed(futures):
                row = future.result()
                row["source"] = "ct_log" if row.get("host") in ct_hosts else "wordlist"
                rows.append(row)
                append_jsonl(jsonl_path, row)

    resolved_hosts: list[str] = []
    host_to_scope_anchor: dict[str, str] = {}
    rejected_count = 0
    for row in rows:
        if row.get("status") != "resolved":
            continue
        host = str(row.get("host") or "")
        if not host:
            continue
        scope_anchor = scope_anchor_for(host, scope_anchors)
        if not scope_anchor:
            rejected_count += 1
            append_jsonl(rejected_path, {
                "checked_at": now_iso(),
                "host": host,
                "reason": "outside_input_host_scope",
                "input_scope_anchors": scope_anchors,
            })
            continue
        resolved_hosts.append(host)
        host_to_scope_anchor[host] = scope_anchor
    unique_hosts = sorted(set(resolved_hosts))
    wildcard_dropped_path = args.out_dir / "subdomains_wildcard_dropped.txt"
    wildcard_dropped: list[str] = []
    if wildcard_map and unique_hosts:
        host_ips: dict[str, set[str]] = {}
        for row in rows:
            host = str(row.get("host") or "")
            if row.get("status") == "resolved" and host:
                host_ips.setdefault(host, set()).update(
                    x for x in str(row.get("ips") or "").split(",") if x
                )
        unique_hosts, wildcard_dropped = split_wildcard_results(
            {h: host_ips.get(h, set()) for h in unique_hosts}, wildcard_map
        )
        wildcard_dropped_path.write_text(
            "\n".join(wildcard_dropped) + ("\n" if wildcard_dropped else ""), encoding="utf-8"
        )
        if wildcard_dropped:
            print(f"[!] 泛解析过滤：丢弃 {len(wildcard_dropped)} 个仅解析到 wildcard IP 的噪声候选"
                  f"（完整清单见 {wildcard_dropped_path.name}；原始记录仍保留在 jsonl/csv）", flush=True)
    raw_path.write_text("\n".join(resolved_hosts) + ("\n" if resolved_hosts else ""), encoding="utf-8")
    dedup_path.write_text("\n".join(unique_hosts) + ("\n" if unique_hosts else ""), encoding="utf-8")
    pending_path.write_text(
        "\n".join(f"https://{host}|subdomain_scope_confirmation_required" for host in unique_hosts)
        + ("\n" if unique_hosts else ""),
        encoding="utf-8",
    )
    next_targets_path.write_text(
        "\n".join(f"https://{host}|subdomain_candidate" for host in unique_hosts) + ("\n" if unique_hosts else ""),
        encoding="utf-8",
    )
    existing_lines = load_existing_target_lines(args.targets)
    discovered_lines = [
        f"https://{host}|auto_subdomain_scope_anchor:{host_to_scope_anchor[host]}"
        for host in unique_hosts
    ]
    auto_merged_lines = dedup_target_lines(existing_lines + discovered_lines)
    auto_merged_path.write_text(
        "\n".join(auto_merged_lines) + ("\n" if auto_merged_lines else ""),
        encoding="utf-8",
    )
    write_csv(csv_path, rows)
    manifest = {
        "created_at": now_iso(),
        "targets": str(args.targets),
        "scope_mode": "input_host_subtree",
        "scope_anchor_count": len(scope_anchors),
        "input_scope_anchors": scope_anchors,
        "registered_parent_widening": False,
        "word_count": len(words),
        "query_count": len(queries),
        "resolved_count": len(unique_hosts) + len(wildcard_dropped),
        "wildcard_detected": bool(wildcard_map),
        "wildcard_map": wildcard_map,
        "wildcard_dropped_count": len(wildcard_dropped),
        "out_of_scope_rejected_count": rejected_count,
        "delay": args.delay,
        "qps": args.qps,
        "effective_start_interval_seconds": interval,
        "concurrency": concurrency,
        "max_queries": args.max_queries,
        "timeout": args.timeout,
        "outputs": {
            "raw": str(raw_path),
            "dedup": str(dedup_path),
            "pending_scope_confirmation": str(pending_path),
            "next_run_targets": str(next_targets_path),
            "auto_merged_targets": str(auto_merged_path),
            "jsonl": str(jsonl_path),
            "csv": str(csv_path),
            "scope_rejections": str(rejected_path),
            "wildcard_dropped": str(wildcard_dropped_path),
        },
        "default_policy": "input_host_subtree_only_no_parent_or_sibling_widening",
    }
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
