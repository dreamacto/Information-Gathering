"""tests/test_state_machine_reconstruction.py —— 业务流程状态机离线重建测试
（batch9_0，规格 5.5 state_machine 子分支 1453-1472 行）。

覆盖：确定性重建与 fingerprint 幂等、必需字段/来源/重复 step_id 负例、守卫台账、
序列回放（ok/state_mismatch/unknown_step/not_evaluated 确定性四态）、mismatch
假设种子、表头契约常量、无网络无并发 AST 结构负例。纯离线数据变换，不发任何
请求、不发并发请求。
"""
from __future__ import annotations

import ast
import json
from pathlib import Path

from authorized_assessment.analysis import state_machine_reconstruction as smr

NORMAL_STEPS = [
    {
        "step_id": "s1",
        "endpoint": "/api/v1/orders",
        "method": "POST",
        "event": "create_order",
        "state_before": "cart_active",
        "state_after": "order_pending",
        "server_precondition": "购物车非空且归属当前用户（服务端会话态）",
        "effect": "创建订单",
        "source": "runs/demo/evidence/flow/order-flow.json",
        "evidence_ref": "runs/demo/evidence/flow/order-flow.json:L3",
    },
    {
        "step_id": "s2",
        "endpoint": "/api/v1/orders/1001/pay",
        "method": "POST",
        "event": "pay_order",
        "state_before": "order_pending",
        "state_after": "order_paid",
        "server_precondition": "订单状态=order_pending 且余额充足（服务端前置校验）",
        "effect": "扣款",
        "source": "runs/demo/evidence/flow/order-flow.json",
        "evidence_ref": "runs/demo/evidence/flow/order-flow.json:L7",
    },
    {
        "step_id": "s3",
        "endpoint": "/api/v1/orders/1001/redeem",
        "method": "POST",
        "event": "redeem",
        "state_before": "order_paid",
        "state_after": "order_redeemed",
        "server_precondition": "订单状态=order_paid 且未核销（一次性消费标记）",
        "effect": "核销发放权益",
        "source": "runs/demo/evidence/flow/order-flow.json",
        "evidence_ref": "runs/demo/evidence/flow/order-flow.json:L11",
    },
]

# 无守卫记录的转移（guard_unrecorded 台账负例步骤）。
UNGUARDED_STEP = {
    "step_id": "s4",
    "endpoint": "/api/v1/coupons/claim",
    "method": "POST",
    "event": "claim_coupon",
    "state_before": "order_redeemed",
    "state_after": "coupon_granted",
    "effect": "发放优惠券",
    "source": "runs/demo/evidence/flow/coupon-flow.json",
}


def _build(steps=NORMAL_STEPS):
    return smr.build_state_machine(steps)


def test_build_deterministic_structure():
    machine_a, violations_a = _build()
    machine_b, violations_b = _build()
    assert violations_a == [] and violations_b == []
    assert machine_a == machine_b
    assert machine_a["machine_schema_version"] == "1.0"
    assert machine_a["entry_state"] == "cart_active"
    assert machine_a["states"] == sorted(
        {"cart_active", "order_pending", "order_paid", "order_redeemed"}
    )
    assert [t["transition_id"] for t in machine_a["transitions"]] == [
        "t-0001",
        "t-0002",
        "t-0003",
    ]
    assert machine_a["guard_unrecorded_transitions"] == []


def test_fingerprint_and_machine_id_stable():
    machine, _ = _build()
    again, _ = _build()
    fp = smr.machine_fingerprint(machine)
    assert fp == smr.machine_fingerprint(again)
    assert len(fp) == 64 and all(c in "0123456789abcdef" for c in fp)
    assert smr.machine_id(machine) == f"sm-{fp[:12]}" == smr.machine_id(again)
    # 内容变化 → 指纹变化（引用可区分）。
    mutated = json.loads(json.dumps(machine, ensure_ascii=False))
    mutated["transitions"][0]["server_precondition"] = "不同守卫文本"
    assert smr.machine_fingerprint(mutated) != fp


def test_missing_required_field_and_non_mapping_violations():
    broken = [dict(NORMAL_STEPS[0])]
    broken.append({k: v for k, v in NORMAL_STEPS[1].items() if k != "state_after"})
    machine, violations = smr.build_state_machine(broken)
    # 违例步骤跳过并留痕；合法步骤照常登记（违例不静默丢弃有效输入）。
    assert [t["step_id"] for t in machine["transitions"]] == ["s1"]
    assert any("state_after" in v for v in violations)
    _, violations = smr.build_state_machine(["not-a-mapping"])
    assert any("键值映射" in v for v in violations)


def test_missing_source_violation():
    step = {k: v for k, v in NORMAL_STEPS[0].items()}
    step.pop("source")
    step.pop("evidence_ref")
    _, violations = smr.build_state_machine([step])
    assert any("缺少来源" in v for v in violations)


def test_duplicate_step_id_violation():
    _, violations = smr.build_state_machine([NORMAL_STEPS[0], dict(NORMAL_STEPS[0])])
    assert any("重复" in v for v in violations)


def test_guard_ledger_records_unrecorded():
    machine, violations = smr.build_state_machine(NORMAL_STEPS + [UNGUARDED_STEP])
    assert violations == []
    assert machine["guard_unrecorded_transitions"] == ["t-0004"]
    ledger = smr.guard_ledger(machine)
    assert ledger["recorded"] == ["t-0001", "t-0002", "t-0003"]
    assert ledger["unrecorded"] == ["t-0004"]


def test_empty_steps_violation():
    machine, violations = smr.build_state_machine([])
    assert machine["transitions"] == [] and machine["entry_state"] == ""
    assert any("正常状态序列必须显式给出" in v for v in violations)


def test_check_sequence_normal_ok():
    machine, _ = _build()
    record, violations = smr.check_sequence(machine, ["s1", "s2", "s3"])
    assert violations == []
    assert record["all_ok"] is True
    assert record["final_state"] == "order_redeemed"
    assert [r["result"] for r in record["results"]] == ["ok", "ok", "ok"]


def test_check_sequence_skip_precondition_mismatch():
    """跳过支付直接核销 → state_mismatch（跳过建立前置状态的离线信号）。"""
    machine, _ = _build()
    record, _ = smr.check_sequence(machine, ["s1", "s3"])
    third = record["results"][1]
    assert third["result"] == "state_mismatch"
    assert third["expected_from"] == "order_paid"
    assert third["actual_state"] == "order_pending"
    assert third["server_precondition"] == "订单状态=order_paid 且未核销（一次性消费标记）"
    assert third["endpoint"] == "/api/v1/orders/1001/redeem"
    assert record["all_ok"] is False


def test_check_sequence_completed_state_repeat_mismatch():
    """已核销后重复核销 → state_mismatch（与 batch9_1 重复消费语义衔接）。"""
    machine, _ = _build()
    record, _ = smr.check_sequence(machine, ["s1", "s2", "s3", "s3"])
    assert record["results"][3]["result"] == "state_mismatch"
    assert record["results"][3]["expected_from"] == "order_paid"
    assert record["results"][3]["actual_state"] == "order_redeemed"


def test_check_sequence_unknown_step_stops_walk():
    machine, _ = _build()
    record, _ = smr.check_sequence(machine, ["s1", "sX", "s3"])
    assert record["results"][1]["result"] == "unknown_step"
    assert record["results"][2]["result"] == "not_evaluated"
    assert record["all_ok"] is False


def test_check_sequence_empty_and_invalid_machine():
    machine, _ = _build()
    record, violations = smr.check_sequence(machine, [])
    assert record["results"] == [] and record["all_ok"] is False
    assert any("序列为空" in v for v in violations)
    record, violations = smr.check_sequence({"transitions": []}, ["s1"])
    assert record["all_ok"] is False
    assert any("零转移" in v for v in violations)


def test_extract_mismatch_signals_fields():
    machine, _ = _build()
    signals, violations = smr.extract_mismatch_signals(
        machine,
        [
            {"sequence_ref": "seq-skip-pay", "steps": ["s1", "s3"]},
            {"sequence_ref": "seq-repeat-redeem", "steps": ["s1", "s2", "s3", "s3"]},
            {"sequence_ref": "seq-normal", "steps": ["s1", "s2", "s3"]},
        ],
    )
    assert violations == []
    assert [s["sequence_ref"] for s in signals] == ["seq-skip-pay", "seq-repeat-redeem"]
    skip = signals[0]
    assert skip["kind"] == "state_mismatch"
    assert skip["step_ref"] == "s3"
    assert skip["transition_id"] == "t-0003"
    assert skip["server_precondition"] == "订单状态=order_paid 且未核销（一次性消费标记）"
    assert skip["source"] == "runs/demo/evidence/flow/order-flow.json"
    assert skip["evidence_ref"] == "runs/demo/evidence/flow/order-flow.json:L11"
    repeat = signals[1]
    assert repeat["expected_from"] == "order_paid"
    assert repeat["actual_state"] == "order_redeemed"


def test_extract_mismatch_signals_bare_list_and_empty():
    machine, _ = _build()
    signals, _ = smr.extract_mismatch_signals(machine, [["s1", "s2", "s3"]])
    assert signals == []
    signals, violations = smr.extract_mismatch_signals(machine, [[]])
    assert signals == []
    assert any("序列为空" in v for v in violations)


def test_transition_fields_contract():
    assert smr.TRANSITION_FIELDS == (
        "transition_id",
        "step_id",
        "from_state",
        "event",
        "endpoint",
        "method",
        "server_precondition",
        "to_state",
        "effect",
        "source",
        "evidence_ref",
    )
    assert smr.SEQUENCE_STEP_RESULTS == (
        "ok",
        "state_mismatch",
        "unknown_step",
        "not_evaluated",
    )
    assert "不发任何请求" in smr.NO_CONCURRENT_REQUEST_RULE
    assert "并发请求" in smr.NO_CONCURRENT_REQUEST_RULE


def test_module_has_no_network_or_concurrency_imports():
    """AST 结构负例：模块不得导入网络/并发/子进程库（离线红线，batch8_6 模式）。"""
    source = Path(smr.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    banned_roots = {
        "requests",
        "urllib",
        "urllib3",
        "http",
        "httpx",
        "aiohttp",
        "socket",
        "ssl",
        "asyncio",
        "threading",
        "concurrent",
        "multiprocessing",
        "subprocess",
        "telnetlib",
        "ftplib",
    }
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported += [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)
    violations = [name for name in imported if name.split(".")[0] in banned_roots]
    assert violations == []
