# -*- coding: utf-8 -*-
"""W6 验收测试：fh_review_dispatch prepare/aggregate"""
import csv, json, os, subprocess, sys
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "fh_review_dispatch.py"

QUEUE_COLS = [
    "target_id", "review_order", "priority", "value_score", "host", "base_url",
    "representative_url", "run_dirs", "categories", "signals", "source_files",
    "safe_readonly_plan", "approval_gates", "rate_limit", "status", "disposition",
    "evidence_paths", "notes",
]


def make_workspace(tmp_path: Path, n=5) -> Path:
    run = tmp_path / "run_x"
    ws = run / "postrun_review"
    (ws / "target_reviews").mkdir(parents=True)
    rows = []
    for i in range(1, n + 1):
        host = f"h{i}.target-authorized.cn"
        rows.append({c: "" for c in QUEUE_COLS} | {
            "target_id": f"T{i:04d}", "review_order": str(i), "priority": "P1" if i <= 2 else "P2",
            "value_score": str(100 - i * 10), "host": host,
            "representative_url": f"https://{host}/", "disposition": "pending",
        })
        (ws / "target_reviews" / f"{i}_{host}.md").write_text(f"# 卷宗 {host}", encoding="utf-8")
    with (ws / "target_review_queue.csv").open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=QUEUE_COLS)
        w.writeheader(); w.writerows(rows)
    (ws / "review_ledger.csv").write_text(
        "item_id,order,priority,category,run_dir,source_file,item_count,safe_default,approval_gate,recommended_action,status,notes\n"
        "I1,1,P1,web,run_x,a.jsonl,3,yes,,review,status_pending,\n", encoding="utf-8-sig")
    (ws / "findings_ledger.csv").write_text(
        "finding_id,status,run_dir,source_item_id,target,url_or_path,category,title,impact,permission_level,evidence_paths,video_time,cleanup,retest,notes\n",
        encoding="utf-8-sig")
    return run


def run_tool(*args):
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    r = subprocess.run([sys.executable, str(TOOL), *args], capture_output=True, text=True,
                       encoding="utf-8", errors="replace", cwd=str(ROOT), env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    return r.stdout


def test_prepare_batches(tmp_path):
    run = make_workspace(tmp_path, 5)
    out = run_tool("--run-dir", str(run), "--prepare", "--batch-size", "2")
    ws = run / "postrun_review"
    batches = sorted((ws / "review_batches").glob("batch_*.md"))
    assert len(batches) == 3  # 5 目标 / 批 2 = 3 批
    b1 = batches[0].read_text(encoding="utf-8")
    assert "verdicts/1.json" in b1 and "disposition" in b1 and "九值" in b1
    assert (ws / "verdicts").is_dir()
    assert "下一个未审 review_order=1" in out
    # 幂等：再跑一次不重复生成（批次文件已存在则跳过）
    out2 = run_tool("--run-dir", str(run), "--prepare", "--batch-size", "2")
    assert "已存在，跳过" in out2 or "待出批次 0" in out2


def test_aggregate_flow(tmp_path):
    run = make_workspace(tmp_path, 5)
    run_tool("--run-dir", str(run), "--prepare")
    ws = run / "postrun_review"
    vdir = ws / "verdicts"
    # 一条 confirmed + 一条 rejected(带fp_pattern)
    (vdir / "1.json").write_text(json.dumps({
        "review_order": 1, "target_id": "T0001", "host": "h1.target-authorized.cn",
        "disposition": "confirmed", "confidence": 0.9,
        "basis": "target_reviews/1_h1.target-authorized.cn.md:12 明确 unauth 数据接口与差异证据",
        "next_action": "人工终审", "fp_pattern": "",
        "source_status": {"a.jsonl": "reviewed"},
    }, ensure_ascii=False), encoding="utf-8")
    (vdir / "2.json").write_text(json.dumps({
        "review_order": 2, "host": "h2.target-authorized.cn",
        "disposition": "rejected", "confidence": 0.8,
        "basis": "同模板导航页泛匹配, 无真实泄露",
        "fp_pattern": "HTML200 导航页同模板误报",
    }, ensure_ascii=False), encoding="utf-8")
    out = run_tool("--run-dir", str(run), "--aggregate")
    # findings_ledger +1
    with (ws / "findings_ledger.csv").open(encoding="utf-8-sig") as f:
        frows = list(csv.DictReader(f))
    assert len(frows) == 1 and frows[0]["status"] == "confirmed"
    # fp_memory 追加（run 工作区内, 因为测试 cwd 下无 knowledge_base 时回退）
    fp_candidates = [ws / "fp_memory.jsonl", ROOT / "knowledge_base" / "fp_memory.jsonl"]
    fp_hits = [p for p in fp_candidates if p.is_file()]
    assert fp_hits, "fp_memory 未生成"
    # queue 回填
    with (ws / "target_review_queue.csv").open(encoding="utf-8-sig") as f:
        qrows = list(csv.DictReader(f))
    by = {r["review_order"]: r for r in qrows}
    assert by["1"]["disposition"] == "confirmed"
    assert by["2"]["disposition"] == "rejected"
    # TOP 文件
    assert (ws / "review_batches" / "TOP_人工复核.md").is_file()
    assert "已审 2/总数 5" in out


def test_invalid_verdict(tmp_path):
    run = make_workspace(tmp_path, 3)
    ws = run / "postrun_review"
    (ws / "verdicts").mkdir()
    (ws / "verdicts" / "1.json").write_text(json.dumps({
        "review_order": 1, "host": "h1.target-authorized.cn",
        "disposition": "definitely_vulnerable", "confidence": 1.0, "basis": "x",
    }), encoding="utf-8")
    out = run_tool("--run-dir", str(run), "--aggregate")
    assert "无效 1" in out
    assert (ws / "invalid_verdicts.csv").is_file()
