"""tests/test_static_dynamic_reconciliation.py —— static/dynamic 端点对账模块测试
（batch12_1，实施规格 6.4 1558-1581 行；规格指定测试文件名 1565 行）。

覆盖：
  - 模块常量 ↔ contracts/miniapp_reconciliation_schema.json 无漂移（phase/分支/十值
    端点状态/判定状态/CSV 列/产物路径/契约名与版本）；
  - 十值端点状态与规格 1570-1581 行逐一对应；
  - classify_endpoint_status 确定性：判定资格修饰优先于出现位置（优先级实现定义，
    batch12_1 卡片留痕），同输入同输出，两基线均未出现兜底 needs_manual_validation；
  - build/validate/render 正负例（endpoint_id 必需、status 枚举、判定行 reason 强制、
    渲染表头精确匹配与往返）；
  - CLI 正负例（观察 JSON → CSV；违例 fail-closed 不落盘）；
  - 导入纪律子进程测试（导入期不改 os.environ；CLI 兜底仅 __main__）。

纯离线，不发任何网络请求。
"""
from __future__ import annotations

import csv
import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
CONTRACT_PATH = ROOT / "contracts" / "miniapp_reconciliation_schema.json"

from authorized_assessment.miniapp import static_dynamic_reconciliation as sdr

SPEC_ENDPOINT_STATES = (
    "static_only",
    "dynamic_only",
    "both_seen",
    "feature_gated",
    "stale",
    "version_specific",
    "third_party",
    "platform_shared",
    "unreachable",
    "needs_manual_validation",
)


@pytest.fixture(scope="module")
def contract():
    return json.loads(CONTRACT_PATH.read_text(encoding="utf-8-sig"))


# ---------------------------------------------------------------------------
# 契约常量无漂移
# ---------------------------------------------------------------------------

def test_module_constants_match_contract(contract):
    phase_contract = contract["phases"]["static_dynamic_reconciliation"]
    assert sdr.MINIAPP_RECONCILIATION_CONTRACT == contract["contract"]
    assert sdr.MINIAPP_RECONCILIATION_SCHEMA_VERSION == contract["schema_version"]
    assert sdr.RECONCILIATION_PHASE == "static_dynamic_reconciliation"
    assert sdr.RECONCILIATION_ARTIFACT == phase_contract["artifact"]
    assert sdr.RECONCILIATION_ARTIFACT == (
        "artifacts/miniapp/reconciliation/static-dynamic-endpoints.csv"
    )
    assert sdr.RECONCILIATION_BRANCHES == tuple(phase_contract["branches"])
    assert sdr.RECONCILIATION_ENDPOINT_STATES == tuple(phase_contract["endpoint_states"])
    assert sdr.RECONCILIATION_JUDGMENT_STATES == tuple(phase_contract["judgment_states"])
    assert sdr.RECONCILIATION_CSV_FIELDS == tuple(phase_contract["csv_fields"])


def test_endpoint_states_match_spec_literal():
    assert sdr.RECONCILIATION_ENDPOINT_STATES == SPEC_ENDPOINT_STATES
    assert len(sdr.RECONCILIATION_ENDPOINT_STATES) == 10
    assert set(sdr.RECONCILIATION_JUDGMENT_STATES) < set(sdr.RECONCILIATION_ENDPOINT_STATES)


def test_branches_match_skill_scripts():
    """模块分支与 skill init/audit 常量同源（三方锁：模块 ↔ 契约 ↔ skill 脚本）。"""
    import importlib.util

    def _load(name: str, path: Path):
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    init_mod = _load(
        "xcx_init_b12_sdr",
        ROOT / ".agents" / "skills" / "xcx" / "scripts" / "init_miniapp_engagement.py",
    )
    audit_mod = _load(
        "xcx_audit_b12_sdr",
        ROOT / ".agents" / "skills" / "xcx" / "scripts" / "audit_miniapp_engagement.py",
    )
    assert init_mod.RECONCILIATION_REVIEW_BRANCHES["static_dynamic_reconciliation"] == (
        sdr.RECONCILIATION_BRANCHES
    )
    assert tuple(audit_mod.RECONCILIATION_REVIEW_BRANCHES["static_dynamic_reconciliation"]) == (
        sdr.RECONCILIATION_BRANCHES
    )
    assert tuple(init_mod.RECONCILIATION_CSV_FIELDS) == sdr.RECONCILIATION_CSV_FIELDS
    assert tuple(audit_mod.RECONCILIATION_CSV_FIELDS) == sdr.RECONCILIATION_CSV_FIELDS
    assert tuple(init_mod.RECONCILIATION_ENDPOINT_STATES) == sdr.RECONCILIATION_ENDPOINT_STATES


def test_red_line_constants():
    assert "不发任何新请求" in sdr.RECONCILIATION_NO_PROBE_RULE
    assert "unreachable" in sdr.RECONCILIATION_NO_PROBE_RULE
    assert "不得误报为自有资产" in sdr.PLATFORM_SHARED_ATTRIBUTION_RULE
    assert "不得作为活跃问题上报" in sdr.STALE_NOT_FINDING_RULE


# ---------------------------------------------------------------------------
# classify_endpoint_status 确定性
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "evidence,expected",
    [
        ({"static_seen": True, "dynamic_seen": True}, "both_seen"),
        ({"static_seen": True}, "static_only"),
        ({"dynamic_seen": True}, "dynamic_only"),
        # 判定资格修饰覆盖出现位置（优先级实现定义）
        ({"static_seen": True, "dynamic_seen": True, "needs_manual_hint": True}, "needs_manual_validation"),
        ({"dynamic_seen": True, "unreachable_hint": True}, "unreachable"),
        ({"static_seen": True, "dynamic_seen": True, "stale_hint": True}, "stale"),
        ({"static_seen": True, "feature_gated_hint": True}, "feature_gated"),
        ({"static_seen": True, "dynamic_seen": True, "version_hint": True}, "version_specific"),
        ({"static_seen": True, "third_party_hint": True}, "third_party"),
        ({"dynamic_seen": True, "platform_shared_hint": True}, "platform_shared"),
        # 修饰间优先级：needs_manual > unreachable > stale > feature_gated > version
        ({"unreachable_hint": True, "stale_hint": True}, "unreachable"),
        ({"stale_hint": True, "feature_gated_hint": True}, "stale"),
        ({"feature_gated_hint": True, "version_hint": True}, "feature_gated"),
        ({"version_hint": True, "third_party_hint": True}, "version_specific"),
        ({"third_party_hint": True, "platform_shared_hint": True}, "third_party"),
    ],
)
def test_classify_precedence(evidence, expected):
    assert sdr.classify_endpoint_status(evidence) == expected
    # 确定性：同输入同输出
    assert sdr.classify_endpoint_status(dict(evidence)) == expected


def test_classify_no_sighting_defaults_manual():
    """两基线均未出现且无修饰 → needs_manual_validation 兜底（无证据的行不可凭空
    定状态）。"""
    assert sdr.classify_endpoint_status({}) == "needs_manual_validation"
    assert sdr.classify_endpoint_status({"static_seen": False, "dynamic_seen": False}) == (
        "needs_manual_validation"
    )


# ---------------------------------------------------------------------------
# build / validate / render
# ---------------------------------------------------------------------------

def _valid_row(**overrides) -> dict:
    row = {
        "endpoint_id": "ep-0001",
        "host": "api.example.com",
        "method": "GET",
        "path": "/v1/items",
        "source_material": "mat-0001",
        "static_evidence_ref": "endpoints.csv",
        "dynamic_evidence_ref": "dynamic.csv",
        "status": "both_seen",
        "reason": "",
        "notes": "",
    }
    row.update(overrides)
    return row


def test_build_row_shape_and_explicit_status():
    row = sdr.build_reconciliation_row(
        {
            "endpoint_id": "ep-0002",
            "host": "api.example.com",
            "method": "POST",
            "path": "/v1/orders",
            "evidence": {"dynamic_seen": True},
        }
    )
    assert set(row.keys()) == set(sdr.RECONCILIATION_CSV_FIELDS)
    assert row["status"] == "dynamic_only"
    # 显式 status 仅接受十值之一，人工判定覆盖分类
    row = sdr.build_reconciliation_row(
        {"endpoint_id": "ep-0003", "evidence": {"static_seen": True}},
        status="needs_manual_validation",
    )
    assert row["status"] == "needs_manual_validation"
    row = sdr.build_reconciliation_row({"endpoint_id": "ep-0004"}, status="bogus")
    assert row["status"] == "bogus"  # 透传给校验器判违例，模块不做静默纠正
    assert sdr.validate_reconciliation_rows([row]) != []


def test_validate_rows_accepts_valid_and_rejects_invalid():
    assert sdr.validate_reconciliation_rows([_valid_row()]) == []
    rows = [
        {"endpoint_id": "", "status": "both_seen"},
        _valid_row(status="not-a-state"),
        _valid_row(status="unreachable", reason=""),
        _valid_row(status="stale", reason="   "),
        _valid_row(status="needs_manual_validation", reason=""),
        "not-a-mapping",
    ]
    violations = sdr.validate_reconciliation_rows(rows)
    text = "\n".join(violations)
    assert "row 1: endpoint_id 为空" in text
    assert "row 2: status 非法 'not-a-state'" in text
    assert "row 3: status 'unreachable' 需要非空 reason" in text
    assert "row 4: status 'stale' 需要非空 reason" in text
    assert "row 5: status 'needs_manual_validation' 需要非空 reason" in text
    assert "row 6" in text and "键值映射" in text


def test_render_csv_header_exact_and_round_trip():
    rows = [
        _valid_row(),
        _valid_row(endpoint_id="ep-0002", status="unreachable", reason="host decommissioned"),
    ]
    text = sdr.render_reconciliation_csv(rows)
    reader = csv.reader(io.StringIO(text))
    header = next(reader)
    assert header == list(sdr.RECONCILIATION_CSV_FIELDS)
    parsed = list(csv.DictReader(io.StringIO(text)))
    assert len(parsed) == 2
    assert parsed[0]["status"] == "both_seen"
    assert parsed[1]["reason"] == "host decommissioned"
    # 判定行已带 reason，往返后仍过校验
    assert sdr.validate_reconciliation_rows(parsed) == []


# ---------------------------------------------------------------------------
# CLI（__main__ guard）
# ---------------------------------------------------------------------------

def test_cli_writes_reconciliation_csv(tmp_path):
    endpoints = tmp_path / "endpoints.json"
    endpoints.write_text(
        json.dumps(
            {
                "endpoints": [
                    {
                        "endpoint_id": "ep-0001", "host": "api.example.com",
                        "method": "GET", "path": "/v1/items",
                        "evidence": {"static_seen": True, "dynamic_seen": True},
                    },
                    {
                        "endpoint_id": "ep-0002", "host": "legacy.example.com",
                        "method": "GET", "path": "/v1/old",
                        "evidence": {"static_seen": True, "stale_hint": True},
                        "reason": "only in v1 package, not in current build",
                    },
                ]
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    out = tmp_path / "reconciliation" / "static-dynamic-endpoints.csv"
    result = subprocess.run(
        [sys.executable, "-m", "authorized_assessment.miniapp.static_dynamic_reconciliation",
         "--endpoints", str(endpoints), "--out", str(out)],
        capture_output=True, text=True,
        encoding="utf-8",  # batch14_5: hermetic——子进程 UTF-8 中文输出，GBK locale 父进程解码崩溃(stdout=None)
        timeout=60,
        env={**os.environ, "PYTHONPATH": str(SRC), "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"},
    )
    assert result.returncode == 0, result.stderr
    text = out.read_text(encoding="utf-8-sig")
    parsed = list(csv.DictReader(io.StringIO(text)))
    assert len(parsed) == 2
    assert parsed[0]["status"] == "both_seen"
    assert parsed[1]["status"] == "stale"
    assert parsed[1]["reason"] == "only in v1 package, not in current build"


def test_cli_fail_closed_on_violations(tmp_path):
    """违例 fail-closed：不落盘、退出码非 0、违例逐条打印。"""
    endpoints = tmp_path / "bad.json"
    endpoints.write_text(
        json.dumps({"endpoints": [{"endpoint_id": "", "status": "bogus"}]}),
        encoding="utf-8",
    )
    out = tmp_path / "out" / "static-dynamic-endpoints.csv"
    result = subprocess.run(
        [sys.executable, "-m", "authorized_assessment.miniapp.static_dynamic_reconciliation",
         "--endpoints", str(endpoints), "--out", str(out)],
        capture_output=True, text=True,
        encoding="utf-8",  # batch14_5: hermetic——子进程 UTF-8 中文输出，GBK locale 父进程解码崩溃(stdout=None)
        timeout=60,
        env={**os.environ, "PYTHONPATH": str(SRC), "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"},
    )
    assert result.returncode == 2
    assert "VIOLATION" in result.stdout
    assert "nothing written" in result.stdout
    assert not out.exists()


# ---------------------------------------------------------------------------
# 导入纪律（子进程全新导入；导入期不改 os.environ/locale/stdout 编码）
# ---------------------------------------------------------------------------

def test_import_has_no_environment_side_effect():
    code = (
        "import os, sys; "
        "before = dict(os.environ); "
        f"sys.path.insert(0, r'{SRC}'); "
        "import authorized_assessment.miniapp.static_dynamic_reconciliation; "
        "changed = {k: os.environ[k] for k in os.environ if before.get(k) != os.environ[k]}; "
        "removed = [k for k in before if k not in os.environ]; "
        "assert not changed and not removed, (changed, removed); "
        "print('IMPORT_CLEAN')"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr
    assert "IMPORT_CLEAN" in result.stdout
