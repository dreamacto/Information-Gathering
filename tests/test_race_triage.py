# -*- coding: utf-8 -*-
"""W8 验收测试：race_triage 三模式对本地靶场的 overrun 判定"""
import json
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "labs" / "race_lab_server.py"
TOOL = ROOT / "race_triage.py"


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


def _reset(lab):
    import urllib.request
    urllib.request.urlopen(f"http://127.0.0.1:{lab}/reset", timeout=5).read()


def _run(lab, endpoint, mode, tmp_path, method="GET", extra=None, write_ack=False):
    args = [sys.executable, str(TOOL),
            "--url", f"http://127.0.0.1:{lab}{endpoint}",
            "--n-baseline", "3", "--n-concurrent", "12",
            "--mode", mode, "--cooldown", "1",
            "--expected-status", "200", "--body-probe", "成功",
            "--reset-url", f"http://127.0.0.1:{lab}/reset",
            "--out", str(tmp_path / "race_results.jsonl")]
    if method != "GET":
        args += ["--method", method]
    if write_ack:
        args += ["--write-risk-ack"]
    if extra:
        args += extra
    r = subprocess.run(args, capture_output=True, text=True, encoding="utf-8",
                       errors="replace", cwd=str(ROOT))
    return r


def _last_overrun(tmp_path):
    lines = [l for l in (tmp_path / "race_results.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    assert lines, "race_results.jsonl 无输出"
    return json.loads(lines[-1])["limit_overrun"]


def test_h1_vulnerable_and_safe(lab, tmp_path):
    _reset(lab)
    r1 = _run(lab, "/claim", "h1_last_byte", tmp_path)
    assert r1.returncode == 0, r1.stdout + r1.stderr
    assert _last_overrun(tmp_path) is True, "非原子 /claim 应 overrun=true"

    _reset(lab)
    r2 = _run(lab, "/claim_safe", "h1_last_byte", tmp_path)
    assert r2.returncode == 0, r2.stdout + r2.stderr
    assert _last_overrun(tmp_path) is False, "加锁 /claim_safe 应 overrun=false"


def test_barrier_vulnerable(lab, tmp_path):
    _reset(lab)
    r = _run(lab, "/claim", "barrier", tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    assert _last_overrun(tmp_path) is True, "barrier 模式对 /claim 也应成立"


def test_write_endpoint_refused_without_ack(lab, tmp_path):
    _reset(lab)
    r = _run(lab, "/transfer", "h1_last_byte", tmp_path, method="POST")
    assert r.returncode != 0, "POST 无 write_risk_ack 应拒绝执行"
    assert "write_risk_ack" in (r.stdout + r.stderr)
