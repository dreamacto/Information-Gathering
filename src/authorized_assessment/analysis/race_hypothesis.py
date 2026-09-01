"""竞态假设离线生成与成立条件校验（实施规格 5.5 business_logic_testing 子分支
1453-1472 行，race_hypothesis 内部子分支）。

只读离线：本模块只做假设记录的确定性生成、校验与去重，不发任何请求、不发并发
请求、**永不自动执行竞态验证**（规格 1464 行：logic-workshop 只负责离线重建状态机
和生成假设，不发并发请求；race_validation 必须单独审批、指定端点/对象并有清理
计划——审批语义落在本模块的 validation_approval 信封，且本模块只校验信封结构，
不批准、不执行任何验证；写操作与并发测试的 write_risk_ack 人工批准链路归配方 D
既有 L0 引擎链路，本批不触碰）。

业务漏洞成立条件（规格 1466-1472 行）逐条落为 validate_race_hypothesis 校验项：
1. 能明确写出正常状态序列 → normal_sequence_ref 必填（引用 batch9_0 状态机/序列
   记录 id，可追溯）；
2. 能指出被绕过的服务端前置条件 → bypassed_guard 必填（须为 batch9_0 守卫台账中
   已记录的守卫；无守卫记录的转移不得作为绕过引用）；
3. 能证明业务结果超出用户应有权限或次数 → business_impact 属四维枚举（与
   batch9_1 四类别同源：重复消费/发放/扣款/审批）且 impact_claim 必填；
4. 不是仅改变前端显示、客户端金额或本地状态 → frontend_only=True 拒绝；
5. 不能因为重复点击一次就直接称为竞态 → basis="single_repeat_click" 拒绝（必须
   证明服务端状态发生不应有的重复消费/发放/扣款/审批结果——证明责任在升级后的
   候选层，由 batch9_1 确认形态承担）。

规格 3.1 模块清单未列 business_logic 专属新模块（batch9_0 卡片核对留痕）→ 无契约
先例，版本化定义在本 docstring 与模块常量留痕，表头契约用 RACE_HYPOTHESIS_JSONL_
FIELDS 锁定，落盘接线归后续批次。

实现定义留痕（供操作者复核）：
- 假设状态枚举 RACE_HYPOTHESIS_STATUSES 五值（hypothesis/needs_manual_validation/
  duplicate/rejected/blocked）——假设是验证前记录，不是候选：confirmed 不在本域
  出现（确认归 finding_quality_gate 五门），approval_required 不在本域出现（审批
  归 validation_approval 信封，且"approval_required 不自动判定"约定由"生成函数
  永不产出 approved"结构保证）；
- validation_approval 信封状态五值（not_requested/requested/approved/denied/
  completed）——requested/approved 必须指定端点与对象并给出清理计划，approved 还
  须 approver 留痕；生成/去重函数只产出 not_requested，其余状态仅由人工输入。
"""
from __future__ import annotations

import hashlib
import json
from typing import Iterable, Mapping

# 假设结构版本（登记字段增删改必须 bump 并同步卡片留痕）。
RACE_HYPOTHESIS_SCHEMA_VERSION = "1.0"

# 业务影响四维（与 batch9_1 replay_duplicate 四类别同源——竞态假设的最终认定必须
# 回到服务端状态不应有的重复消费/发放/扣款/审批结果，规格 1472 行）。
BUSINESS_IMPACT_DIMENSIONS: tuple[str, ...] = (
    "repeat_consumption",
    "repeat_grant",
    "repeat_deduction",
    "repeat_approval",
)

# 假设状态五值（实现定义留痕：非候选状态模型；见 docstring）。
RACE_HYPOTHESIS_STATUSES: tuple[str, ...] = (
    "hypothesis",
    "needs_manual_validation",
    "duplicate",
    "rejected",
    "blocked",
)

# 审批信封状态五值（race_validation 单独审批语义；生成函数只产出 not_requested）。
RACE_VALIDATION_APPROVAL_STATUSES: tuple[str, ...] = (
    "not_requested",
    "requested",
    "approved",
    "denied",
    "completed",
)

# 种子结构必需字段（最小结构集）。成立条件字段（normal_sequence_ref/
# bypassed_guard/business_impact/impact_claim）缺省不在此列——其缺失由
# validate_race_hypothesis 产出带规格引用的违例，记录仍产出留痕供调用方处置
# （违例留痕语义，同 batch8 各域："缺字段拒绝"仅限记录无法构造的情形）。
SEED_REQUIRED_FIELDS: tuple[str, ...] = (
    "endpoint",
    "method",
    "object_ref",
)

# 假设表头契约（落盘接线归后续批次；字段顺序即 jsonl 表头顺序；validation_approval
# 为嵌套对象按 canonical JSON 序列化）。
RACE_HYPOTHESIS_JSONL_FIELDS: tuple[str, ...] = (
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

# 红线常量（供测试与审计引用；写入假设 reason/precondition 语义）。
NO_CONCURRENT_EXECUTION_RULE: str = (
    "本模块只做假设的离线生成、校验与去重；不发任何请求、不发并发请求、永不自动"
    "执行竞态验证（规格 5.5：logic-workshop 不发并发请求）"
)

RACE_VALIDATION_APPROVAL_RULE: str = (
    "race_validation 必须单独审批、指定端点/对象并有清理计划；本模块仅生成与校验"
    "假设，不批准、不执行任何验证"
)


def _text(record: Mapping[str, object], field: str) -> str:
    return str(record.get(field) or "").strip()


def _canonical_key(seed: Mapping[str, object]) -> str:
    return json.dumps(
        {
            "endpoint": _text(seed, "endpoint"),
            "method": _text(seed, "method"),
            "object_ref": _text(seed, "object_ref"),
            "bypassed_guard": _text(seed, "bypassed_guard"),
            "business_impact": _text(seed, "business_impact"),
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def build_race_hypothesis(
    seed: Mapping[str, object], label: str = "race_hypothesis"
) -> tuple[dict | None, list[str]]:
    """假设种子 → 确定性假设记录 (hypothesis, violations)。

    hypothesis_id 由 canonical key（endpoint/method/object_ref/bypassed_guard/
    business_impact）sha256 前 12 位确定派生；validation_approval 信封默认
    not_requested——本函数永不产出 approved/completed（结构保证"审批不自动判定"）。
    status_hint 尊重人工判定（限 RACE_HYPOTHESIS_STATUSES）。
    """
    violations: list[str] = []
    if not isinstance(seed, Mapping):
        return None, [f"{label}: 种子必须是键值映射"]
    missing = [f for f in SEED_REQUIRED_FIELDS if not _text(seed, f)]
    if missing:
        return None, [f"{label}: 缺少必需字段 {missing}"]
    hypothesis_id = "rh-" + hashlib.sha256(
        _canonical_key(seed).encode("utf-8")
    ).hexdigest()[:12]
    status_hint = _text(seed, "status_hint")
    if status_hint and status_hint not in RACE_HYPOTHESIS_STATUSES:
        return None, [
            f"{label}.status_hint 非法: {status_hint!r}"
            f"（允许值 {list(RACE_HYPOTHESIS_STATUSES)}）"
        ]
    hypothesis = {
        "hypothesis_schema_version": RACE_HYPOTHESIS_SCHEMA_VERSION,
        "hypothesis_id": hypothesis_id,
        "status": status_hint or "hypothesis",
        "endpoint": _text(seed, "endpoint"),
        "method": _text(seed, "method"),
        "object_ref": _text(seed, "object_ref"),
        "business_impact": _text(seed, "business_impact"),
        "impact_claim": _text(seed, "impact_claim"),
        "normal_sequence_ref": _text(seed, "normal_sequence_ref"),
        "bypassed_guard": _text(seed, "bypassed_guard"),
        "state_machine_id": _text(seed, "state_machine_id"),
        "basis": _text(seed, "basis"),
        "frontend_only": bool(seed.get("frontend_only")),
        "source": _text(seed, "source"),
        "evidence_ref": _text(seed, "evidence_ref"),
        "reason": _text(seed, "reason"),
        "validation_approval": {
            "status": "not_requested",
            "approver": "",
            "endpoint": _text(seed, "endpoint"),
            "object": _text(seed, "object_ref"),
            "cleanup_plan": "",
        },
    }
    violations += validate_race_hypothesis(hypothesis, label=label)
    return hypothesis, violations


def validate_race_hypothesis(
    hypothesis: Mapping[str, object], label: str = "race_hypothesis"
) -> list[str]:
    """假设记录校验：成立条件五条（规格 1466-1472 行）+ 结构与审批信封。"""
    violations: list[str] = []
    if not isinstance(hypothesis, Mapping):
        return [f"{label}: 假设必须是键值映射"]
    for field in ("hypothesis_id", "status", "endpoint", "method", "object_ref"):
        if not _text(hypothesis, field):
            violations.append(f"{label}: 缺少必需字段 {field}")
    # 成立条件 1：能明确写出正常状态序列。
    if not _text(hypothesis, "normal_sequence_ref"):
        violations.append(
            f"{label}: normal_sequence_ref 为空——必须能明确写出正常状态序列（规格 1466 行条件 1）"
        )
    # 成立条件 2：能指出被绕过的服务端前置条件。
    if not _text(hypothesis, "bypassed_guard"):
        violations.append(
            f"{label}: bypassed_guard 为空——必须指出被绕过的服务端前置条件（规格 1470 行条件 2）"
        )
    # 成立条件 3：能证明业务结果超出用户应有权限或次数。
    impact = _text(hypothesis, "business_impact")
    if impact and impact not in BUSINESS_IMPACT_DIMENSIONS:
        violations.append(
            f"{label}.business_impact 非法: {impact!r}（允许值 {list(BUSINESS_IMPACT_DIMENSIONS)}）"
        )
    if not impact:
        violations.append(
            f"{label}: business_impact 为空——必须证明业务结果超出用户应有权限或次数"
            "（规格 1470 行条件 3）"
        )
    if not _text(hypothesis, "impact_claim"):
        violations.append(
            f"{label}: impact_claim 为空——超出权限或次数的证明要求必须落盘（规格 1470 行条件 3）"
        )
    # 成立条件 4：不是仅改变前端显示、客户端金额或本地状态。
    if hypothesis.get("frontend_only"):
        violations.append(
            f"{label}: frontend_only=True——仅改变前端显示/客户端金额/本地状态不构成"
            "业务漏洞（规格 1471 行条件 4）"
        )
    # 成立条件 5：重复点击一次≠竞态。
    basis = _text(hypothesis, "basis")
    if basis == "single_repeat_click":
        violations.append(
            f"{label}: basis=single_repeat_click——重复点击一次不构成竞态漏洞认定"
            "（规格 1472 行条件 5）"
        )
    status = _text(hypothesis, "status")
    if status and status not in RACE_HYPOTHESIS_STATUSES:
        violations.append(
            f"{label}.status 非法: {status!r}（允许值 {list(RACE_HYPOTHESIS_STATUSES)}）"
        )
    if status in ("hypothesis", "needs_manual_validation") and not _text(
        hypothesis, "source"
    ) and not _text(hypothesis, "evidence_ref"):
        violations.append(f"{label}: 缺少来源（source/evidence_ref 均为空）")
    approval = hypothesis.get("validation_approval")
    if approval is not None:
        violations += validate_validation_approval(
            approval, label=f"{label}.validation_approval"
        )
    return violations


def validate_validation_approval(
    approval: object, label: str = "validation_approval"
) -> list[str]:
    """审批信封校验（race_validation 单独审批语义，规格 1464 行）。

    requested/approved 必须指定端点与对象并有清理计划；approved 还须 approver
    留痕。本模块任何生成函数都不产出 approved/completed。
    """
    violations: list[str] = []
    if not isinstance(approval, Mapping):
        return [f"{label}: 审批信封必须是键值映射"]
    status = _text(approval, "status")
    if status not in RACE_VALIDATION_APPROVAL_STATUSES:
        return [
            f"{label}.status 非法: {status!r}（允许值 {list(RACE_VALIDATION_APPROVAL_STATUSES)}）"
        ]
    if status in ("requested", "approved"):
        if not _text(approval, "endpoint") or not _text(approval, "object"):
            violations.append(
                f"{label}: status={status} 但 endpoint/object 未指定"
                "（race_validation 必须指定端点/对象，规格 1464 行）"
            )
        if not _text(approval, "cleanup_plan"):
            violations.append(
                f"{label}: status={status} 但 cleanup_plan 为空"
                "（race_validation 必须有清理计划，规格 1464 行）"
            )
    if status == "approved" and not _text(approval, "approver"):
        violations.append(
            f"{label}: status=approved 但 approver 为空（批准必须留痕到人）"
        )
    return violations


def dedup_race_hypotheses(
    hypotheses: Iterable[Mapping[str, object]], label: str = "race_hypotheses"
) -> tuple[list[dict], list[str]]:
    """按 canonical key 去重 → (去重后清单, violations)。

    同 key 后者标 status=duplicate 并写 duplicate_of 指向前者 id；非映射与缺 id
    记违例。去重不改变已批准状态（批准归人工输入，本函数只改 status/duplicate_of）。
    """
    result: list[dict] = []
    violations: list[str] = []
    seen: dict[str, str] = {}
    for index, hypothesis in enumerate(hypotheses, start=1):
        if not isinstance(hypothesis, Mapping):
            violations.append(f"{label}: 第 {index} 条假设必须是键值映射")
            continue
        record = dict(hypothesis)
        hypothesis_id = _text(record, "hypothesis_id")
        if not hypothesis_id:
            violations.append(f"{label}: 第 {index} 条假设缺少 hypothesis_id")
            continue
        key = json.dumps(
            {
                "endpoint": _text(record, "endpoint"),
                "method": _text(record, "method"),
                "object_ref": _text(record, "object_ref"),
                "bypassed_guard": _text(record, "bypassed_guard"),
                "business_impact": _text(record, "business_impact"),
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        first_id = seen.get(key)
        if first_id:
            record["status"] = "duplicate"
            record["duplicate_of"] = first_id
        else:
            seen[key] = hypothesis_id
        result.append(record)
    return result, violations


def seed_from_state_mismatch(
    signal: Mapping[str, object],
    overrides: Mapping[str, object],
    label: str = "race_seed",
) -> tuple[dict | None, list[str]]:
    """batch9_0 state_mismatch 信号 → 假设种子 (seed, missing)。

    信号提供 endpoint/method/source/evidence_ref 与守卫记录；overrides 必须提供
    object_ref/business_impact/impact_claim/normal_sequence_ref（离线信号不含对象
    与影响维度，证明责任在复核会话）。守卫未记录（server_precondition 为空）的
    信号产出缺 bypassed_guard 的种子——build_race_hypothesis 将拒绝（成立条件 2
    拦截），不得绕过守卫台账。missing 为空表示种子可直接投递 build。
    """
    if not isinstance(signal, Mapping):
        return None, [f"{label}: 信号必须是键值映射"]
    endpoint = _text(signal, "endpoint")
    method = _text(signal, "method")
    guard = _text(signal, "server_precondition")
    missing: list[str] = []
    for field in ("object_ref", "business_impact", "impact_claim", "normal_sequence_ref"):
        if not _text(overrides, field):
            missing.append(field)
    if not endpoint:
        missing.append("signal.endpoint")
    seed: dict = {
        "endpoint": endpoint,
        "method": method or "POST",
        "object_ref": _text(overrides, "object_ref"),
        "business_impact": _text(overrides, "business_impact"),
        "impact_claim": _text(overrides, "impact_claim"),
        "normal_sequence_ref": _text(overrides, "normal_sequence_ref"),
        "bypassed_guard": guard,
        "transition_ref": _text(signal, "transition_id"),
        "basis": "state_transition_window",
        "source": _text(signal, "source"),
        "evidence_ref": _text(signal, "evidence_ref"),
        "reason": f"状态机离线回放 mismatch：预期 {_text(signal, 'expected_from') or '?'}，"
        f"实际 {_text(signal, 'actual_state') or '?'}（仅假设信号）",
    }
    return seed, missing
