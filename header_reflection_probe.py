#!/usr/bin/env python3
"""只读 Header 回显探测 — 不携带任何 payload，仅为下游注入测试提供线索队列。

对每个目标 URL 依次发送 User-Agent / Referer / X-Forwarded-For / Origin /
Cookie(uname=...) 注入无害随机 marker，若响应中出现 marker，说明服务端读取了
该 Header 并可能拼接进 SQL，产出 header_reflection_candidates 队列供人工复核后
定向执行 vuln_sqli_pure.py --header ...
"""
import argparse
import base64
import csv
import hashlib
import json
import random
import re
import string
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from pentest_utils import random_ua

import requests as req_lib

MARKER_CHARS = "abcdefghjkmnpqrstuvwxyz23456789"


def read_jsonl_file(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    for ln in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            rows.append(json.loads(ln))
        except json.JSONDecodeError:
            continue
    return rows

# 探测的 Header 注入位：名称 -> 是否可能出现在 urlquery 之外的默认值
HEADER_PROBES = [
    ("User-Agent", None),
    ("Referer", None),
    ("X-Forwarded-For", None),
    ("Origin", None),
    ("Cookie", "uname"),
]


def rand_marker() -> str:
    return "xhmk" + "".join(random.choice(MARKER_CHARS) for _ in range(8))


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def redact(url: str) -> str:
    return url[:180]


def is_http_url(url: str) -> bool:
    return url.startswith("http://") or url.startswith("https://")


def load_urls(seed: str) -> list[str]:
    urls = []
    if is_http_url(seed):
        return [seed.strip()]
    p = Path(seed)
    if p.exists():
        urls = [ln.strip() for ln in p.read_text(encoding="utf-8", errors="ignore").splitlines() if ln.strip()]
    return [u for u in urls if is_http_url(u)]


def reflection_count(text: str, marker: str) -> int:
    return (text or "").count(marker)


def fetch_wait(url: str, timeout: int, delay: float) -> object:
    time.sleep(delay)
    return None


def run_probe(url: str, header_name: str, cookie_key: str | None, marker: str,
              timeout: int, delay: float, run_dir: Path, completed: set,
              login_data: str | None = None) -> dict:
    row = None
    probe_headers = {"User-Agent": random_ua()}
    variants: list[tuple[str, str]] = []
    if header_name.lower() == "cookie" and cookie_key:
        variants.append((f"{cookie_key}={marker}", marker))
        variants.append((f"{cookie_key}={base64.b64encode(marker.encode('utf-8')).decode('ascii')}", marker))
    else:
        variants.append((marker, marker))
    for value, detect in variants:
        probe_headers = {"User-Agent": random_ua()}
        if header_name.lower() == "cookie" and cookie_key:
            probe_headers["Cookie"] = value
        else:
            probe_headers[header_name] = value
        try:
            time.sleep(delay)
            if login_data:
                probe_headers["Content-Type"] = "application/x-www-form-urlencoded"
                resp = req_lib.post(url, data=login_data, headers=probe_headers,
                                    timeout=timeout, verify=False, allow_redirects=True)
            else:
                resp = req_lib.get(url, headers=probe_headers, timeout=timeout,
                                   verify=False, allow_redirects=True)
        except Exception:
            continue
        if resp.status_code < 400 and resp.text:
            cnt = reflection_count(resp.text, detect)
            if cnt:
                context_hint = re.sub(r"<[^>]+>", " ", resp.text)
                idx = context_hint.find(detect)
                snippet = re.sub(r"\s+", " ", context_hint)[max(0, idx - 40): idx + len(detect) + 40] if idx >= 0 else ""
                row = {
                    "url": redact(url),
                    "host": re.sub(r"^https?://", "", url).split("/")[0].lower(),
                    "header": header_name,
                    "cookie_key": cookie_key,
                    "marker": detect,
                    "reflection_count": cnt,
                    "context_snippet": snippet,
                    "action": "manual_sqli_probe",
                    "suggest_command": f"vuln_sqli_pure.py --url \"{url}\" --header {header_name}"
                                       + (f" --cookie-key {cookie_key}" if cookie_key else ""),
                    "checked_at": now_iso(),
                    "source": "header_reflection_probe",
                }
                break
    return row


def load_run_dir_urls(run_dir: Path, max_per_host: int, limit: int) -> list[str]:
    rows: list[dict] = []
    for name in ("api_candidates.jsonl", "api_confirmed.jsonl", "api_interesting.jsonl"):
        for row in read_jsonl_file(run_dir / name):
            if row.get("url"):
                rows.append({"url": row["url"]})
    katana_path = run_dir / "katana_urls.txt"
    if katana_path.exists():
        for line in katana_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            value = line.strip()
            if value:
                rows.append({"url": value})
    targets_csv = run_dir / "targets.csv"
    if targets_csv.exists():
        with targets_csv.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
            for row in csv.DictReader(handle):
                if row.get("url"):
                    rows.append({"url": row["url"]})
    urls: list[str] = []
    seen: set[str] = set()
    per_host: dict[str, int] = defaultdict(int)
    for row in rows:
        url = str(row.get("url") or "").strip()
        if not url or url in seen:
            continue
        host = re.sub(r"^https?://", "", url).split("/")[0].lower()
        if not host:
            continue
        seen.add(url)
        per_host[host] += 1
        if per_host[host] > max_per_host:
            continue
        urls.append(url)
        if limit and len(urls) >= limit:
            break
    return urls


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="只读 Header 回显探测（UA/Referer/XFF/Origin/Cookie）")
    p.add_argument("--url", default=None, help="单个 URL")
    p.add_argument("--seed", default=None, help="URL 列表文件，每行一个；缺省时从 --run-dir 的候选文件自动装载")
    p.add_argument("--run-dir", required=True, help="输出目录（队列写这里）")
    p.add_argument("--url-timeout", type=int, default=12)
    p.add_argument("--delay", type=float, default=0.4, help="请求间最小间隔")
    p.add_argument("--header", default=None, help="只测指定 Header（默认全部）")
    p.add_argument("--marker-prefix", default="xhmk", help="marker 前缀")
    p.add_argument("--max-per-host", type=int, default=5, help="每主机最多探测 URL 数")
    p.add_argument("--limit", type=int, default=0, help="总探测 URL 数上限，0 不限制")
    p.add_argument("--login-data", default=None,
                   help="探测请求用 POST 发送的表单数据（覆盖登录请求内注入场景）。传 URL 编码后的串，"
                        "如 uname=admin&passwd=123%%25df%%252527（%% 需写为 %%%%25）")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    global MARKER_CHARS
    MARKER_CHARS = args.marker_prefix[:4] + MARKER_CHARS[len(args.marker_prefix[:4]):] if args.marker_prefix else MARKER_CHARS

    run_dir = Path(args.run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)

    seed = args.url or args.seed
    if not seed:
        urls = load_run_dir_urls(run_dir, args.max_per_host, args.limit)
    else:
        urls = load_urls(seed)[: args.limit if args.limit else None]
    if not urls:
        print("[-] 没有有效 URL")
        sys.exit(1)

    probes = HEADER_PROBES
    if args.header:
        probes = [probe for probe in probes if probe[0].lower() == args.header.lower()]

    out_path = run_dir / "header_reflection_candidates.jsonl"
    done_path = run_dir / "header_reflection_done.jsonl"
    rows_done = [json.loads(ln) for ln in done_path.read_text(encoding="utf-8", errors="ignore").splitlines()] if done_path.exists() else []
    done_keys = {(r.get("host"), r.get("header"), r.get("cookie_key")) for r in rows_done} if rows_done else set()

    hits = 0
    row_written = 0
    for url in urls:
        host = re.sub(r"^https?://", "", url).split("/")[0].lower()
        for header_name, cookie_key in probes:
            key = (host, header_name, cookie_key)
            if key in done_keys:
                continue
            marker = rand_marker()
            row = run_probe(url, header_name, cookie_key, marker, args.url_timeout, args.delay,
                            run_dir, done_keys, args.login_data)
            with done_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps({"host": host, "header": header_name, "cookie_key": cookie_key, "checked_at": now_iso()}) + "\n")
            if row:
                hits += 1
                with out_path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(row, ensure_ascii=False) + "\n")
                row_written += 1
                print(f"[!!!] {host} | header={header_name} cookie_key={cookie_key} | marker 回显 {row['reflection_count']} 处 | {row['suggest_command']}")
            else:
                print(f"  - {host} | {header_name}{('.' + cookie_key) if cookie_key else ''} 无回显")

    txt_path = run_dir / "header_reflection_candidates.txt"
    if row_written:
        with txt_path.open("w", encoding="utf-8") as fh:
            fh.write("# Header 回显探测结果 — 复核后定向执行注入测试\n")
            fh.write("# 命令: vuln_sqli_pure.py --url <URL> --header <Header> [--cookie-key <key>] [--encode base64]\n")
            for ln in out_path.read_text(encoding="utf-8").splitlines():
                row = json.loads(ln)
                fh.write(f"- {row['host']} | {row['header']}{('.' + str(row['cookie_key'])) if row.get('cookie_key') else ''} | {row['reflection_count']} 处回显 | {row['suggest_command']}\n")
    print(f"[>] 完成: 目标 {len(urls)} 个, 命中回显 {hits} 条 -> {out_path}")


if __name__ == "__main__":
    main()