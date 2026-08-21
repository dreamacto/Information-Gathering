# -*- coding: utf-8 -*-
"""W12 验收测试：xss_verify_headless 判定逻辑（本地反射真值页 + mock 引擎）"""
import json
import subprocess
import sys
import threading
import time
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "xss_verify_headless.py"


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class _ReflectHandler(BaseHTTPRequestHandler):
    """三真值：/exec 反射进 script（可执行）/ /text 纯文本反射 / /title 反射进 title"""
    def log_message(self, *a):
        pass

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query, keep_blank_values=True)
        marker = (q.get("q") or [""])[0]
        if u.path == "/exec":
            body = f"<html><script>var x='{marker}';</script><body>hi</body></html>".encode()
        elif u.path == "/text":
            body = f"<html><body>{marker}</body></html>".encode()
        elif u.path == "/title":
            body = f"<html><title>{marker}</title><body>ok</body></html>".encode()
        else:
            body = b"<html><body>noop</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="module")
def srv():
    port = _free_port()
    httpd = ThreadingHTTPServer(("127.0.0.1", port), _ReflectHandler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield port
    httpd.shutdown()


def _make_run(tmp, port):
    run = tmp / "run_xss"
    run.mkdir()
    eps = [f"http://127.0.0.1:{port}/exec?q=x",
           f"http://127.0.0.1:{port}/text?q=x",
           f"http://127.0.0.1:{port}/title?q=x"]
    (run / "xss_reflection_checks.jsonl").write_text(
        "\n".join(json.dumps({"url": u, "param": "q"}) for u in eps) + "\n", encoding="utf-8")
    return run


def test_verdicts_via_stdlib_fetch(tmp_path, srv):
    """无 dalfox 无 playwright 时：内置 requests 抓取 + DOM 上下文判定兜底。"""
    run = _make_run(tmp_path, srv)
    r = subprocess.run(
        [sys.executable, str(TOOL), "--run-dir", str(run), "--engine", "playwright", "--force"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", cwd=str(ROOT))
    j = run / "xss_verified.jsonl"
    rows = [json.loads(l) for l in j.read_text(encoding="utf-8").splitlines() if l.strip()]
    by_path = {}
    for row in rows:
        p = urlparse(row["candidate"]).path
        by_path[p] = row["verdict"]
    assert by_path.get("/exec") in ("executable", "inconclusive"), by_path
    assert by_path.get("/title") in ("context_safe", "inconclusive"), by_path


def test_verdict_from_dom_unit():
    sys.path.insert(0, str(ROOT))
    import importlib
    mod = importlib.import_module("xss_verify_headless")
    m = "MARKER123"
    assert mod.verdict_from_dom(m, f"<script>var a='{m}'</script>") == "executable"
    assert mod.verdict_from_dom(m, f"<title>{m}</title>") == "context_safe"
    assert mod.verdict_from_dom(m, "<html>nothing</html>") == "not_reflected"
