# -*- coding: utf-8 -*-
"""W13 验收测试：whitebox_triage 对 fixture 源码树的命中"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "whitebox_triage.py"
SINK_LIB = ROOT / "knowledge_base" / "sink_lib.jsonl"


@pytest.fixture(scope="module")
def fixture_tree(tmp_path_factory):
    tree = tmp_path_factory.mktemp("wxapp")
    (tree / "app.js").write_text(
        "var api = {\n"
        "  getOrder: function(id){\n"
        "    wx.request({url: 'https://x/api/order/' + id})\n"   # sqli/URL 拼接
        "  },\n"
        "  del: function(id){\n"
        "    $.post('/api/admin/del', {id: id})\n"
        "  }\n"
        "}\n", encoding="utf-8")
    (tree / "util" ).mkdir()
    (tree / "util" / "crypto.js").write_text(
        "function hash(p){ return md5(p) }\n"                    # weak_crypto
        "var APP_SECRET = 'abcd1234efgh5678'\n"                  # 硬编码密钥
        "function run(c){ return eval(c) }\n",                   # command/eval
        encoding="utf-8")
    (tree / "comp.wxml").write_text("<view>{{msg}}</view>", encoding="utf-8")
    return tree


def test_sink_lib_seeds():
    assert SINK_LIB.is_file(), "先跑 scripts/gen_sink_lib.py"
    rows = [json.loads(l) for l in SINK_LIB.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(rows) >= 60, f"sink 种子应≥60，实际 {len(rows)}"
    cats = {r["category"] for r in rows}
    assert cats == {"sqli", "command", "path_traversal", "ssrf", "deserialize", "weak_crypto", "authz_missing"}


def test_scan_finds_known_sinks(fixture_tree, tmp_path):
    out = tmp_path / "out"
    r = subprocess.run(
        [sys.executable, str(TOOL), "--source-dir", str(fixture_tree),
         "--out-dir", str(out), "--scan"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", cwd=str(ROOT))
    assert r.returncode == 0, r.stdout + r.stderr
    j = out / "sink_findings.jsonl"
    assert j.is_file()
    rows = [json.loads(l) for l in j.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert rows, "fixture 树应至少命中一条 sink"
    cats = {row["category"] for row in rows}
    assert "sqli" in cats or "weak_crypto" in cats or "command" in cats, cats
    # 契约字段
    for row in rows:
        for fld in ("file", "line", "category", "snippet", "severity", "confidence"):
            assert fld in row
    # md
    assert (out / "whitebox_review.md").is_file()
    # .wxml 无命中不报错
