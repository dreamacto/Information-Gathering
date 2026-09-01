"""tests/test_race_hypothesis.py —— 竞态假设离线生成与成立条件校验测试
（batch9_2，规格 5.5 race_hypothesis 子分支 1453-1472 行）。

覆盖：成立条件五条逐项拒绝（正常序列引用/被绕过守卫/影响维度与证明要求/
前端-only/重复点击一次）、确定性 hypothesis_id 与审批信封默认值、生成函数永不
产出 approved、审批信封校验负例（缺端点对象/缺清理计划/缺 approver）、状态
枚举与 status_hint、去重（同 key 标 duplicate + duplicate_of）、batch9_0 mismatch
信号桥接（守卫未记录被条件 2 拦截）、表头契约常量、红线常量、无网络无并发
AST 结构负例。纯离线，不发任何请求、不发并发请求、永不自动执行竞态验证。
"""
from __future__ import annotations

import ast
from pathlib import Path

from authorized_assessment.analysis import race_hypothesis as rh
from authorized_assessment.analysis import state_machine_reconstruction as smr

VALID_SEED = {
    "endpoint": "/api/v1/orders/1001/redeem",
    "method": "POST",
    "object_ref": "order:1001",
    "business_impact": "repeat_consumption",
    "impact_claim": "同一订单核销后再次核销可使权益发放两次，超出单次核销应有次数"
    "（需服务端重复消费记录证明）",
    "normal_sequence_ref": "sm-ab12cd34ef56",
    "bypassed_guard": "订单状态=order_paid 且未核销（一次性消费标记）",
    "source": "runs/demo/evidence/flow/order-flow.json",
    "evidence_ref": "runs/demo/evidence/flow/order-flow.json:L11",
}


def test_build_deterministic_and_default_envelope():
    hyp_a, violations_a = rh.build_race_hypothesis(VALID_SEED)
    hyp_b, violations_b = rh.build_race_hypothesis(VALID_SEED)
    assert violations_a == [] and violations_b == []
    assert hyp_a == hyp_b
    assert hyp_a["hypothesis_id"].startswith("rh-") and len(hyp_a["hypothesis_id"]) == 15
    assert hyp_a["status"] == "hypothesis"
    assert hyp_a["hypothesis_schema_version"] == "1.0"
    # 审批信封默认 not_requested；生成函数永不产出 approved/completed。
    assert hyp_a["validation_approval"]["status"] == "not_requested"
    assert hyp_a["validation_approval"]["endpoint"] == VALID_SEED["endpoint"]
    assert hyp_a["validation_approval"]["object"] == VALID_SEED["object_ref"]
    # canonical key 不含 impact_claim/source → 同端点对象守卫影响的种子同 id。
    variant = {**VALID_SEED, "impact_claim": "另一段证明文本", "source": "另一次复核"}
    hyp_c, _ = rh.build_race_hypothesis(variant)
    assert hyp_c["hypothesis_id"] == hyp_a["hypothesis_id"]


def test_condition_1_empty_normal_sequence_ref_rejected():
    seed = {**VALID_SEED, "normal_sequence_ref": ""}
    hyp, violations = rh.build_race_hypothesis(seed)
    assert any("正常状态序列" in v for v in violations)
    assert hyp is not None  # 违例留痕后记录仍产出，由调用方处置


def test_condition_2_empty_bypassed_guard_rejected():
    seed = {**VALID_SEED, "bypassed_guard": ""}
    _, violations = rh.build_race_hypothesis(seed)
    assert any("被绕过的服务端前置条件" in v for v in violations)


def test_condition_3_impact_dimension_and_claim():
    seed = {**VALID_SEED, "business_impact": "money_free"}
    _, violations = rh.build_race_hypothesis(seed)
    assert any("business_impact 非法" in v for v in violations)
    seed = {**VALID_SEED, "business_impact": ""}
    _, violations = rh.build_race_hypothesis(seed)
    assert any("超出用户应有权限或次数" in v for v in violations)
    seed = {**VALID_SEED, "impact_claim": ""}
    _, violations = rh.build_race_hypothesis(seed)
    assert any("impact_claim 为空" in v for v in violations)


def test_condition_4_frontend_only_rejected():
    seed = {**VALID_SEED, "frontend_only": True}
    _, violations = rh.build_race_hypothesis(seed)
    assert any("前端显示/客户端金额/本地状态" in v for v in violations)


def test_condition_5_single_repeat_click_rejected():
    seed = {**VALID_SEED, "basis": "single_repeat_click"}
    _, violations = rh.build_race_hypothesis(seed)
    assert any("重复点击一次" in v and "竞态" in v for v in violations)


def test_structure_negatives():
    _, violations = rh.build_race_hypothesis("nope")
    assert any("键值映射" in v for v in violations)
    _, violations = rh.build_race_hypothesis({k: v for k, v in VALID_SEED.items() if k != "object_ref"})
    assert any("object_ref" in v for v in violations)
    _, violations = rh.build_race_hypothesis({**VALID_SEED, "status_hint": "confirmed"})
    assert any("status_hint 非法" in v for v in violations)  # confirmed 不属假设状态域
    _, violations = rh.build_race_hypothesis(
        {**VALID_SEED, "source": "", "evidence_ref": ""}
    )
    assert any("缺少来源" in v for v in violations)


def test_status_hint_respected_and_illegal_status():
    hyp, violations = rh.build_race_hypothesis({**VALID_SEED, "status_hint": "rejected"})
    assert violations == [] and hyp["status"] == "rejected"
    violations = rh.validate_race_hypothesis({**VALID_SEED, "status": "approved"})
    assert any("status 非法" in v for v in violations)


def test_validation_approval_envelope_negatives():
    base = {"status": "requested", "approver": "", "endpoint": "/api/v1/x", "object": "o1", "cleanup_plan": "验证后回滚数据"}
    assert rh.validate_validation_approval(base) == []
    violations = rh.validate_validation_approval({**base, "endpoint": "", "object": ""})
    assert any("endpoint/object 未指定" in v for v in violations)
    violations = rh.validate_validation_approval({**base, "cleanup_plan": ""})
    assert any("清理计划" in v for v in violations)
    violations = rh.validate_validation_approval({**base, "status": "approved", "approver": ""})
    assert any("approver 为空" in v for v in violations)
    assert rh.validate_validation_approval({**base, "status": "not_requested"}) == []
    violations = rh.validate_validation_approval({**base, "status": "auto"})
    assert any("status 非法" in v for v in violations)
    assert rh.validate_validation_approval("nope") != []


def test_dedup_marks_duplicates():
    seed_b = {**VALID_SEED, "endpoint": "/api/v1/orders/1002/redeem", "object_ref": "order:1002"}
    hyp_a, _ = rh.build_race_hypothesis(VALID_SEED)
    hyp_a2, _ = rh.build_race_hypothesis(VALID_SEED)
    hyp_b, _ = rh.build_race_hypothesis(seed_b)
    deduped, violations = rh.dedup_race_hypotheses([hyp_a, hyp_a2, hyp_b])
    assert violations == []
    assert [d["status"] for d in deduped] == ["hypothesis", "duplicate", "hypothesis"]
    assert deduped[1]["duplicate_of"] == hyp_a["hypothesis_id"]
    assert deduped[1]["hypothesis_id"] == hyp_a["hypothesis_id"]
    _, violations = rh.dedup_race_hypotheses([{"endpoint": "x"}])
    assert any("缺少 hypothesis_id" in v for v in violations)


def test_seed_from_state_mismatch_pipeline():
    """batch9_0 mismatch 信号 → 种子 → 假设的全离线桥接。"""
    machine, _ = smr.build_state_machine(_flow_steps())
    signals, _ = smr.extract_mismatch_signals(
        machine, [{"sequence_ref": "seq-skip", "steps": ["s1", "s3"]}]
    )
    assert len(signals) == 1
    overrides = {
        "object_ref": "order:1001",
        "business_impact": "repeat_consumption",
        "impact_claim": "核销结果可能重复发放，需服务端重复消费记录证明",
        "normal_sequence_ref": smr.machine_id(machine),
    }
    seed, missing = rh.seed_from_state_mismatch(signals[0], overrides)
    assert missing == []
    assert seed["endpoint"] == "/api/v1/orders/1001/redeem"
    assert seed["bypassed_guard"] == "订单状态=order_paid 且未核销（一次性消费标记）"
    hyp, violations = rh.build_race_hypothesis(seed)
    assert violations == []
    assert hyp["normal_sequence_ref"] == smr.machine_id(machine)
    # 守卫未记录的信号 → 种子缺 bypassed_guard → 建立被拒（成立条件 2 拦截）。
    unguarded_signal = {**signals[0], "server_precondition": ""}
    seed2, missing2 = rh.seed_from_state_mismatch(unguarded_signal, overrides)
    assert seed2["bypassed_guard"] == ""
    _, build_violations = rh.build_race_hypothesis(seed2)
    assert any("bypassed_guard" in v or "被绕过的服务端前置条件" in v for v in build_violations)
    # overrides 缺失字段如实报告。
    _, missing3 = rh.seed_from_state_mismatch(signals[0], {})
    assert set(missing3) >= {"object_ref", "business_impact", "impact_claim", "normal_sequence_ref"}


def _flow_steps():
    return [
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


def test_jsonl_fields_contract_and_constants():
    assert rh.RACE_HYPOTHESIS_JSONL_FIELDS == (
        "hypothesis_id",
        "status",
        "endpoint",
        "method",
        "object_ref",
        "business_impact",
        "impact_claim",
        "normal_sequence_ref",
        "bypassed_guard",
        "state_machine_id",
        "basis",
        "frontend_only",
        "source",
        "evidence_ref",
        "reason",
        "validation_approval",
    )
    assert rh.BUSINESS_IMPACT_DIMENSIONS == (
        "repeat_consumption",
        "repeat_grant",
        "repeat_deduction",
        "repeat_approval",
    )
    assert "hypothesis" in rh.RACE_HYPOTHESIS_STATUSES
    assert "confirmed" not in rh.RACE_HYPOTHESIS_STATUSES  # 确认归五门，不属假设域
    assert "approval_required" not in rh.RACE_HYPOTHESIS_STATUSES  # 审批归信封
    assert "not_requested" in rh.RACE_VALIDATION_APPROVAL_STATUSES
    assert "单独审批" in rh.RACE_VALIDATION_APPROVAL_RULE
    assert "清理计划" in rh.RACE_VALIDATION_APPROVAL_RULE
    assert "永不自动" in rh.NO_CONCURRENT_EXECUTION_RULE


def test_module_has_no_network_or_concurrency_imports():
    """AST 结构负例：模块不得导入网络/并发/子进程库（离线红线，batch8_6 模式）。"""
    source = Path(rh.__file__).read_text(encoding="utf-8")
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
