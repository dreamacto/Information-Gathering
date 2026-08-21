# -*- coding: utf-8 -*-
"""W11 · OOB 监听器 oob_listener.py

stdlib http.server 监听（默认 8899）。每请求记 {token, src_ip, path, ts} 追加 oob_hits.jsonl。
--gen-token 生成随机 token。本地/回环测试可直接跑；VPS 部署场景见文末 docstring。

VPS 部署说明：
  1. VPS: python oob_listener.py --port 8899 --prefix ab12cd   （随机前缀防扫描）
  2. 本地: python oob_listener.py --pull http://<vps>:8899/ab12cd/pull?since=<ts>
     拉取新命中并合并进本地 oob_hits.jsonl
  3. ssrf_triage.py --oob http://<vps>:8899/ab12cd
"""
from __future__ import annotations

import argparse
import json
import secrets
import sys
import time
import urllib.request
from datetime import datetime, timezone, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

CST = timezone(timedelta(hours=8))
HITS = Path(__file__).resolve().parent / "oob_hits.jsonl"


def now_iso():
    return datetime.now(CST).isoformat(timespec="seconds")


class Handler(BaseHTTPRequestHandler):
    prefix = ""

    def log_message(self, *a):
        pass

    def do_GET(self):
        path = self.path
        if self.prefix and not path.startswith(f"/{self.prefix}"):
            self.send_response(404)
            self.end_headers()
            return
        rest = path.lstrip("/" + self.prefix) if self.prefix else path.lstrip("/")
        # 管理接口：/pull?since=<ts>
        if rest.startswith("/pull"):
            self._pull()
            return
        # 回调：/<token>[/anything]
        token = rest.strip("/").split("/")[0]
        rec = {"token": token, "src_ip": self.client_address[0], "path": path, "ts": now_iso()}
        with HITS.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _pull(self):
        since = ""
        if "?" in self.path:
            from urllib.parse import urlparse, parse_qs
            q = parse_qs(urlparse(self.path).query)
            since = (q.get("since") or [""])[0]
        rows = []
        if HITS.is_file():
            for ln in HITS.read_text(encoding="utf-8", errors="replace").splitlines():
                if ln.strip():
                    try:
                        r = json.loads(ln)
                        if not since or r.get("ts", "") > since:
                            rows.append(r)
                    except json.JSONDecodeError:
                        continue
        body = json.dumps({"hits": rows}, ensure_ascii=False).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    ap = argparse.ArgumentParser(description="OOB 回调监听器（W11）")
    ap.add_argument("--port", type=int, default=8899)
    ap.add_argument("--prefix", default="", help="随机 URL 前缀（VPS 防扫描）")
    ap.add_argument("--gen-token", action="store_true", help="生成一个随机 token 后退出")
    ap.add_argument("--pull", metavar="URL", help="从远端 listener 拉取命中合并到本地 oob_hits.jsonl")
    a = ap.parse_args()

    if a.gen_token:
        print(secrets.token_hex(6))
        return
    if a.pull:
        merge_pull(a.pull)
        return

    Handler.prefix = a.prefix
    srv = ThreadingHTTPServer(("0.0.0.0", a.port), Handler)
    print(f"[*] OOB listener 就绪 :{a.port} prefix={a.prefix or '(无)'} hits→{HITS}")
    srv.serve_forever()


def merge_pull(url: str):
    try:
        raw = urllib.request.urlopen(url, timeout=15).read().decode("utf-8")
        data = json.loads(raw)
    except Exception as e:
        sys.exit(f"[!] 拉取失败: {e}")
    added = 0
    existing = set()
    if HITS.is_file():
        for ln in HITS.read_text(encoding="utf-8", errors="replace").splitlines():
            if ln.strip():
                try:
                    r = json.loads(ln)
                    existing.add((r.get("token"), r.get("ts"), r.get("src_ip")))
                except json.JSONDecodeError:
                    pass
    with HITS.open("a", encoding="utf-8") as f:
        for r in data.get("hits", []):
            key = (r.get("token"), r.get("ts"), r.get("src_ip"))
            if key not in existing:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
                added += 1
    print(f"[+] 拉取 {len(data.get('hits', []))} 条，新增 {added} → {HITS}")


if __name__ == "__main__":
    main()
