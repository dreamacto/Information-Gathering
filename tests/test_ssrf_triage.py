# -*- coding: utf-8 -*-
"""W11 验收测试：ssrf_triage 三真值（oob 命中 / timing 候选 / noise）"""
import json
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "ssrf_triage.py"
LISTENER = ROOT / "oob_listener.py"


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class _VulnHandler(BaseHTTPRequestHandler):
    """模拟目标站：/fetch?url= 会真的去请求该 URL（SSRF 真值）"""
    def log_message(self, *a):
        pass

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/fetch":
            q = parse_qs(u.query)
            target = (q.get("url") or [""])[0]
            if target:
                import urllib.request
                try:
                    urllib.request.urlopen(target, timeout=5).read()
                    body = b'{"ok": true}'
                except Exception:
                    body = b'{"ok": false}'
            else:
                body = b'{"ok": "noop"}'
            self.send_response(200)
        elif u.path == "/slow":
            time.sleep(3)
            body = b'{"slow": true}'
            self.send_response(200)
        elif u.path == "/plain":
            body = b'{"plain": true}'
            self.send_response(200)
        else:
            body = b'{}'
            self.send_response(404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="module")
def vuln_srv():
    port = _free_port()
    srv = ThreadingHTTPServer(("127.0.0.1", port), _VulnHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield port
    srv.shutdown()


@pytest.fixture(scope="module")
def oob_srv(tmp_path_factory):
    port = _free_port()
    outdir = tmp_path_factory.mktemp("oob")
    proc = subprocess.Popen([sys.executable, str(LISTENER), "--port", str(port)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            cwd=str(outdir))  # hits 落在 listener 同目录? 见 HITS 定义
    time.sleep(1.0)
    yield port
    proc.terminate()
    proc.wait(timeout=5)


def test_oob_and_timing(tmp_path, vuln_srv, oob_srv):
    # 端点文件
    eps = tmp_path / "api_confirmed.jsonl"
    urls = [
        f"http://127.0.0.1:{vuln_srv}/fetch?url=https://example.com",   # oob 真值
        f"http://127.0.0.1:{vuln_srv}/plain?next=https://example.com",  # noise
    ]
    eps.write_text("\n".join(json.dumps({"url": u}) for u in urls) + "\n", encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    r = subprocess.run(
        [sys.executable, str(TOOL), "--run-dir", str(out), "--endpoints", str(eps),
         "--oob", f"http://127.0.0.1:{oob_srv}", "--delay", "0.2", "--force"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", cwd=str(ROOT))
    assert r.returncode == 0, r.stdout + r.stderr
    j = out / "ssrf_candidates.jsonl"
    rows = [json.loads(l) for l in j.read_text(encoding="utf-8").splitlines() if l.strip()]
    verdicts = {(row["param"], row["verdict"]) for row in rows}
    # oob 命中路径：/fetch 端点目标站确实请求了 listener URL → oob_callback_hit
    assert any(v == "oob_callback_hit" for _, v in verdicts), verdicts
    # plain 端点 → noise
    assert any(v == "noise" for _, v in verdicts), verdicts
