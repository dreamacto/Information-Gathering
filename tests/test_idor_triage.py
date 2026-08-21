# -*- coding: utf-8 -*-
"""W7 验收测试：idor_triage 对本地靶场的四真值判定"""
import json
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "labs" / "idor_lab_server.py"
TOOL = ROOT / "idor_triage.py"


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="module")
def lab():
    port = _free_port()
    proc = subprocess.Popen([sys.executable, str(LAB), "--port", str(port)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.0)
    yield port
    proc.terminate()
    proc.wait(timeout=5)


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    return tmp_path_factory.mktemp("run_idor")


@pytest.fixture(scope="module")
def artifacts(run, lab):
    port = lab
    # 会话文件：A/B 两凭证 + 单独 host
    sessions = run / "sessions.jsonl"
    sessions.write_text(
        json.dumps({"host": "127.0.0.1", "headers": {"Authorization": "Bearer token-userA"}, "label": "A"}) + "\n" +
        json.dumps({"host": "127.0.0.1", "headers": {"Authorization": "Bearer token-userB"}, "label": "B"}) + "\n",
        encoding="utf-8")
    # 端点文件（api_confirmed 风格）
    reqs = run / "api_confirmed.jsonl"
    eps = [
        f"http://127.0.0.1:{port}/api/order/1",       # 正确鉴权 → B 403 → 非 candidate
        f"http://127.0.0.1:{port}/api/order_vuln/1",  # IDOR 真值
        f"http://127.0.0.1:{port}/api/leak/1",        # unauth 真值
        f"http://127.0.0.1:{port}/api/soft_deny",     # 200-with-error → noise
    ]
    reqs.write_text("\n".join(json.dumps({"url": u, "status": 200}) for u in eps) + "\n", encoding="utf-8")
    return sessions, reqs


def test_four_truth_values(run, lab, artifacts):
    sessions, reqs = artifacts
    out = run / "out"
    out.mkdir(exist_ok=True)
    r = subprocess.run(
        [sys.executable, str(TOOL),
         "--run-dir", str(out),
         "--sessions", str(sessions),
         "--requests", str(reqs),
         "--delay", "0", "--max-per-host", "10", "--force"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", cwd=str(ROOT))
    assert r.returncode == 0, r.stdout + r.stderr
    rows = [json.loads(l) for l in (out / "idor_candidates.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    from urllib.parse import urlparse
    by_ep = {}
    for row in rows:
        by_ep[urlparse(row["endpoint"]).path] = row["verdict"]
    assert by_ep.get("/api/order/1") not in ("unauth_access", "idor_horizontal_candidate"), "正确鉴权端点不该是候选"
    assert by_ep.get("/api/order_vuln/1") == "idor_horizontal_candidate", by_ep
    assert by_ep.get("/api/leak/1") == "unauth_access", by_ep
    assert by_ep.get("/api/soft_deny") == "noise", by_ep
    # 输出契约字段
    for row in rows:
        for fld in ("endpoint", "host", "a", "anon", "verdict", "ts"):
            assert fld in row
    assert (out / "idor_manual_review.md").is_file()
