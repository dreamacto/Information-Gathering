# -*- coding: utf-8 -*-
"""W8 · 竞态双投 L0 race_triage.py

三种模式覆盖两类协议：
  h2_single_packet : socket+ssl 直连 + h2 库单连接多流同发（HTTP/2 单包攻击）
  h1_last_byte     : N 个 socket 先发去掉最后字节的请求，同步窗后统一补最后 1 字节
  barrier          : threading.Barrier + requests（兼容兜底，精度最低）

输入：配方 D 产出的 race_config.json（--config）或命令行直参（--url）。
流程：n_baseline 次串行 → cooldown → n_concurrent 次竞态 → 成功次数矩阵。
判据（纯机器）：concurrent_successes > max(baseline_successes, 预期上限) → limit_overrun=true；
其余 false / inconclusive（网络不稳定）。只输出矩阵布尔，不输出"漏洞确认"。

安全约束：
- 默认只接受幂等/只读端点；写端点必须 race_config.write_risk_ack==true（人工批准）或显式 --write-risk-ack
- 并发上限 30（写端点上限 10）；每轮间 --cooldown（默认10s）；单目标单轮
- UA 与原请求一致；全程仅对单一授权目标

运行时：必须 .venv（唯一装 h2 的环境）。
用法：
  python race_triage.py --config race_config.json
  python race_triage.py --url http://... --n-concurrent 20 --n-baseline 5 --mode auto
"""
from __future__ import annotations

import argparse
import json
import re
import socket
import ssl
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlparse

import requests

try:
    import h2.connection
    import h2.config
    import h2.events
    HAS_H2 = True
except ImportError:
    HAS_H2 = False

DEFAULT_UA = "Mozilla/5.0 (compatible; authorized-review/1.0)"
MAX_CONCURRENT = 30
MAX_CONCURRENT_WRITE = 10


def now_iso():
    from datetime import datetime, timezone, timedelta
    return datetime.now(timezone(timedelta(hours=8))).isoformat(timespec="seconds")


def make_success_fn(expected_codes=(200,), body_probe=None):
    def ok(status, body):
        if status not in expected_codes:
            return False
        if body_probe and body_probe not in (body or ""):
            return False
        return True
    return ok


# ---------- 三种并发实现 ----------
def run_barrier(url, headers, n, timeout, success_fn, method="GET", body=None):
    results = []
    barrier = threading.Barrier(n)

    def one():
        sess = requests.Session()
        try:
            barrier.wait(timeout=10)
            r = sess.request(method, url, headers=headers, timeout=timeout, allow_redirects=False)
            results.append((r.status_code, r.text or ""))
        except Exception as e:
            results.append((0, str(e)))

    with ThreadPoolExecutor(max_workers=n) as ex:
        list(ex.map(lambda _: one(), range(n)))
    return results


def re_status(http_text: str) -> int:
    m = re.match(r"HTTP/[\d.]+\s+(\d+)", http_text)
    return int(m.group(1)) if m else 0


def run_h1_last_byte(url, headers, n, timeout, success_fn, method="GET", body=None):
    u = urlparse(url)
    host, port = u.hostname, u.port or (443 if u.scheme == "https" else 80)
    path = u.path + ("?" + u.query if u.query else "")
    payload = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n"
    for k, v in (headers or {}).items():
        payload += f"{k}: {v}\r\n"
    if body:
        payload += f"Content-Length: {len(body)}\r\n"
    payload += "\r\n"
    if body:
        payload += body
    raw = payload.encode()
    head, tail = raw[:-1], raw[-1:]

    socks = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for _ in range(n):
        s = socket.create_connection((host, port), timeout=timeout)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if u.scheme == "https":
            s = ctx.wrap_socket(s, server_hostname=host)
        socks.append(s)
    try:
        for s in socks:
            s.sendall(head)
        time.sleep(0.5)
        for s in socks:
            s.sendall(tail)
        results = []
        for s in socks:
            data = b""
            s.settimeout(timeout)
            try:
                while True:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    data += chunk
            except socket.timeout:
                pass
            text = data.decode("utf-8", errors="replace")
            results.append((re_status(text), text))
        return results
    finally:
        for s in socks:
            try:
                s.close()
            except OSError:
                pass


def run_h2_single_packet(url, headers, n, timeout, success_fn, method="GET", body=None):
    if not HAS_H2:
        raise RuntimeError("h2 未安装：请用 .venv 运行")
    u = urlparse(url)
    host, port = u.hostname, u.port or (443 if u.scheme == "https" else 80)
    path = u.path + ("?" + u.query if u.query else "")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])
    sock = socket.create_connection((host, port), timeout=timeout)
    tls = ctx.wrap_socket(sock, server_hostname=host)
    try:
        config = h2.config.H2Configuration(client_side=True)
        conn = h2.connection.H2Connection(config=config)
        conn.initiate_connection()
        tls.sendall(conn.data_to_send())

        stream_ids = []
        for i in range(n):
            sid = conn.get_next_available_stream_id()
            conn.send_headers(sid, [
                (":method", method), (":path", path), (":authority", host),
                (":scheme", u.scheme), ("user-agent", headers.get("User-Agent", DEFAULT_UA)),
                ("x-race-probe", str(i)),
            ], end_stream=True)
            stream_ids.append(sid)
        tls.sendall(conn.data_to_send())  # 统一发出：单包多流

        results = []
        remaining = set(stream_ids)
        deadline = time.time() + timeout
        while remaining and time.time() < deadline:
            try:
                data = tls.recv(65536)
                if not data:
                    break
            except socket.timeout:
                break
            for ev in conn.receive_data(data):
                if isinstance(ev, h2.events.ResponseReceived) and ev.stream_id in remaining:
                    status = 0
                    for k, v in ev.headers:
                        if k.decode() == ":status":
                            status = int(v.decode())
                    results.append((status, ""))
                    remaining.discard(ev.stream_id)
                elif isinstance(ev, h2.events.StreamEnded) and ev.stream_id in remaining:
                    remaining.discard(ev.stream_id)
                elif isinstance(ev, h2.events.StreamReset) and ev.stream_id in remaining:
                    results.append((0, "RST_STREAM"))
                    remaining.discard(ev.stream_id)
            out = conn.data_to_send()
            if out:
                tls.sendall(out)
        for sid in remaining:
            results.append((0, "timeout"))
        return results
    finally:
        try:
            tls.close()
        except OSError:
            pass


def detect_mode(url):
    u = urlparse(url)
    if u.scheme == "https" and HAS_H2:
        return "h2_single_packet"
    return "h1_last_byte"


def main():
    ap = argparse.ArgumentParser(description="竞态双投执行器（W8）")
    ap.add_argument("--config", help="配方D 产出的 race_config.json")
    ap.add_argument("--url")
    ap.add_argument("--method", default="GET")
    ap.add_argument("--headers-json", default="{}")
    ap.add_argument("--body", default=None)
    ap.add_argument("--n-baseline", type=int, default=5)
    ap.add_argument("--n-concurrent", type=int, default=20)
    ap.add_argument("--mode", default="auto", choices=["auto", "h2_single_packet", "h1_last_byte", "barrier"])
    ap.add_argument("--expected-status", default="200")
    ap.add_argument("--body-probe", default=None, help="正文需包含的子串才算成功")
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--cooldown", type=float, default=10.0)
    ap.add_argument("--out", default="race_results.jsonl")
    ap.add_argument("--reset-url", default=None,
                    help="基线后、并发前 GET 一次恢复资源（如本地靶场 /reset；真实目标慎用）")
    ap.add_argument("--write-risk-ack", action="store_true",
                    help="写/非幂等端点必须显式传（等价 race_config.write_risk_ack==true）")
    a = ap.parse_args()

    write_risk_ack = a.write_risk_ack
    if a.config:
        cfg = json.loads(Path(a.config).read_text(encoding="utf-8"))
        url = cfg.get("url", "")
        method = (cfg.get("method") or "GET").upper()
        headers = dict(cfg.get("headers") or {})
        body = cfg.get("body")
        n_base = int(cfg.get("n_baseline", 5))
        n_conc = int(cfg.get("n_concurrent", 20))
        mode = cfg.get("mode", "auto")
        if cfg.get("write_risk_ack") is True:
            write_risk_ack = True
    else:
        url = a.url or ""
        method = a.method.upper()
        headers = json.loads(a.headers_json)
        body = a.body
        n_base, n_conc, mode = a.n_baseline, a.n_concurrent, a.mode

    if not url:
        sys.exit("[!] 需要 --url 或 --config")
    if method not in ("GET", "HEAD") and not write_risk_ack:
        sys.exit(f"[!] {method} 为写/非幂等端点：需要 race_config.write_risk_ack==true（人工批准）或显式 --write-risk-ack；拒绝执行")

    cap = MAX_CONCURRENT_WRITE if method not in ("GET", "HEAD") else MAX_CONCURRENT
    if n_conc > cap:
        print(f"[*] 并发 {n_conc} 超上限，封顶 {cap}")
        n_conc = cap

    codes = tuple(int(c) for c in a.expected_status.split(",") if c.strip())
    success_fn = make_success_fn(codes, a.body_probe)

    if mode == "auto":
        mode = detect_mode(url)
    runner = {"h2_single_packet": run_h2_single_packet,
              "h1_last_byte": run_h1_last_byte,
              "barrier": run_barrier}[mode]
    print(f"[*] 目标 {url} · 模式 {mode} · 基线 {n_base} · 并发 {n_conc} · cooldown {a.cooldown}s")

    baseline_successes = 0
    baseline_codes = []
    for _ in range(n_base):
        try:
            r = requests.request(method, url, headers=headers, timeout=a.timeout, allow_redirects=False)
            st, bt = r.status_code, (r.text or "")
        except Exception as e:
            st, bt = 0, str(e)
        baseline_codes.append(st)
        if success_fn(st, bt):
            baseline_successes += 1
        time.sleep(0.6)
    print(f"[*] 基线：成功 {baseline_successes}/{n_base}，码 {baseline_codes}")

    if a.reset_url:
        try:
            rr = requests.get(a.reset_url, timeout=a.timeout)
            print(f"[*] reset-url {a.reset_url} -> {rr.status_code}")
        except Exception as e:
            print(f"[!] reset-url 失败: {e}")

    time.sleep(a.cooldown)

    results = runner(url, headers, n_conc, a.timeout, success_fn, method=method, body=body)
    conc_successes = sum(1 for st, bd in results if success_fn(st, bd))
    resp_codes = [st for st, _ in results]
    distinct_bodies = len({bd[:200] for _, bd in results})
    print(f"[*] 竞态：成功 {conc_successes}/{n_conc}，码 {resp_codes}")

    expected_cap = baseline_successes if method in ("GET", "HEAD") else 1
    if conc_successes > max(baseline_successes, expected_cap):
        overrun = True
    elif resp_codes.count(0) >= 3 and len(set(resp_codes)) > 2:
        overrun = None
    else:
        overrun = False

    rec = {
        "url": url, "mode": mode, "n_baseline": n_base,
        "baseline_successes": baseline_successes,
        "n_concurrent": n_conc, "concurrent_successes": conc_successes,
        "response_codes": resp_codes[:30], "distinct_bodies": distinct_bodies,
        "limit_overrun": overrun,
        "evidence": f"baseline {baseline_successes}/{n_base} vs concurrent {conc_successes}/{n_conc}",
        "ts": now_iso(),
    }
    out = Path(a.out)
    with out.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    verdict_txt = {True: "limit_overrun=true（矩阵异常，待人工复核）",
                   False: "limit_overrun=false",
                   None: "inconclusive（网络不稳定，建议重测）"}[overrun]
    print(f"[+] {verdict_txt} → 追加 {out}")


if __name__ == "__main__":
    main()
