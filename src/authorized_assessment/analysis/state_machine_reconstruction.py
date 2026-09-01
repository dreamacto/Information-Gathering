"""业务流程状态机离线重建与序列记录（实施规格 5.5 business_logic_testing 子分支
1453-1472 行，state_machine 内部子分支）。

只读离线：纯数据变换，不发任何请求、更不发并发请求（规格 1464 行 logic-workshop
语义：logic-workshop 只负责离线重建状态机和生成假设）。规格 3.1 模块清单未列
business_logic 专属新模块（batch9_0 卡片核对留痕）→ 无契约先例，版本化定义在
本 docstring 与模块常量留痕，表头契约用 TRANSITION_FIELDS 锁定，落盘接线归
后续批次。

职责：
- build_state_machine：从复核会话记录的正常业务流程步骤重建确定性状态机。正常
  状态序列必须显式可写（规格 1466 行成立条件 1）；每个转移记录服务端前置条件
  （server_precondition 守卫，规格 1470 行成立条件 2 的引用基础）。守卫未记录的
  转移入 guard_unrecorded 台账——无守卫记录的转移不得作为竞态/逻辑假设的"被绕过
  服务端前置条件"引用（batch9_2 校验拦截）。
- check_sequence：把记录序列对状态机做离线回放比对（ok/state_mismatch/
  unknown_step/not_evaluated）。state_mismatch 即"跳过建立前置状态的步骤"的离线
  信号——例如未先支付直接调用核销端点、已核销后再次调用核销端点。红线：仅假设
  信号，不构成漏洞认定，不得升级任何候选（confirmed 仍归五门）。
- extract_mismatch_signals：把 mismatch 回放结果整理成可投递 race_hypothesis
  （batch9_2）的假设种子；种子仍须补齐对象/影响维度等字段并通过成立条件校验。
- machine_fingerprint/machine_id：状态机内容确定性指纹（sha256 canonical JSON），
  供假设记录引用（normal_sequence_ref/state_machine_id 可追溯）。

实现定义留痕（供操作者复核；规格仅给"离线重建状态机"方向与成立条件，未给结构）：
- 步骤必需字段取满足条件 1/2 的最小集（STEP_REQUIRED_FIELDS）；server_precondition
  可为空但入守卫台账留痕，不静默丢弃；
- state_mismatch 语义为离线确定性回放比对（无服务端实时状态），只证明"记录序列
  与声明状态机不一致"，不证明服务端实际发生了不应有的状态变更。
"""
from __future__ import annotations

import hashlib
import json
from typing import Iterable, Mapping

# 状态机结构版本（登记字段增删改必须 bump 并同步卡片留痕）。
STATE_MACHINE_SCHEMA_VERSION = "1.0"

# 步骤记录必需字段（正常状态序列的最小显式表示；规格 1466 行成立条件 1）。
STEP_REQUIRED_FIELDS: tuple[str, ...] = (
    "step_id",
    "endpoint",
    "method",
    "event",
    "state_before",
    "state_after",
)

# 转移表头契约（落盘接线归后续批次；字段顺序即 jsonl/CSV 表头顺序）。
TRANSITION_FIELDS: tuple[str, ...] = (
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

# 序列回放逐步结果取值（确定性四态；unknown_step/not_evaluated 属数据与流程问题，
# 只有 state_mismatch 进入假设信号）。
SEQUENCE_STEP_RESULTS: tuple[str, ...] = (
    "ok",
    "state_mismatch",
    "unknown_step",
    "not_evaluated",
)

# 红线常量（写入产物 precondition 语义，供测试与审计引用）。
NO_CONCURRENT_REQUEST_RULE: str = (
    "状态机重建与序列回放均为离线数据变换；本模块不发任何请求，更不发并发请求"
    "（规格 5.5 logic-workshop 语义：logic-workshop 只负责离线重建状态机和生成假设）"
)


def _text(step: Mapping[str, object], field: str) -> str:
    return str(step.get(field) or "").strip()


def build_state_machine(
    steps: Iterable[Mapping[str, object]], label: str = "state_machine"
) -> tuple[dict, list[str]]:
    """正常业务流程步骤 → 确定性状态机 (machine, violations)。

    每步一条转移（transition_id 按输入顺序确定派生）；states 排序去重；
    server_precondition 缺失的转移入 guard_unrecorded_transitions 台账；
    重复 step_id 记违例（序列引用必须无歧义）；同输入两次构建结果逐字段一致。
    """
    violations: list[str] = []
    transitions: list[dict] = []
    states: set[str] = set()
    seen_step_ids: dict[str, int] = {}
    saw_step = False
    for index, step in enumerate(steps, start=1):
        saw_step = True
        if not isinstance(step, Mapping):
            violations.append(f"{label}: 第 {index} 条步骤必须是键值映射")
            continue
        missing = [f for f in STEP_REQUIRED_FIELDS if not _text(step, f)]
        if missing:
            violations.append(f"{label}: 第 {index} 条步骤缺少必需字段 {missing}")
            continue
        step_id = _text(step, "step_id")
        if step_id in seen_step_ids:
            violations.append(
                f"{label}: 第 {index} 条步骤 step_id={step_id!r} 与第 "
                f"{seen_step_ids[step_id]} 条重复（序列引用必须无歧义）"
            )
            continue
        seen_step_ids[step_id] = index
        source = _text(step, "source")
        evidence_ref = _text(step, "evidence_ref")
        if not source and not evidence_ref:
            violations.append(
                f"{label}: 第 {index} 条步骤缺少来源（source/evidence_ref 均为空）"
            )
            continue
        transition = {
            "transition_id": f"t-{index:04d}",
            "step_id": step_id,
            "from_state": _text(step, "state_before"),
            "event": _text(step, "event"),
            "endpoint": _text(step, "endpoint"),
            "method": _text(step, "method"),
            "server_precondition": _text(step, "server_precondition"),
            "to_state": _text(step, "state_after"),
            "effect": _text(step, "effect"),
            "source": source,
            "evidence_ref": evidence_ref,
        }
        transitions.append(transition)
        states.update((transition["from_state"], transition["to_state"]))
    if not transitions:
        if not saw_step:
            violations.append(
                f"{label}: 无有效步骤，状态机为零转移（正常状态序列必须显式给出）"
            )
        elif not violations:
            violations.append(f"{label}: 无有效步骤（全部未通过校验）")
    machine = {
        "machine_schema_version": STATE_MACHINE_SCHEMA_VERSION,
        "entry_state": transitions[0]["from_state"] if transitions else "",
        "states": sorted(states),
        "transitions": transitions,
        "guard_unrecorded_transitions": [
            t["transition_id"] for t in transitions if not t["server_precondition"]
        ],
    }
    return machine, violations


def machine_fingerprint(machine: Mapping[str, object]) -> str:
    """状态机内容确定性指纹（sha256，canonical JSON；与转移 id/顺序绑定）。"""
    payload = json.dumps(
        {
            "entry_state": machine.get("entry_state"),
            "states": machine.get("states"),
            "transitions": machine.get("transitions"),
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def machine_id(machine: Mapping[str, object]) -> str:
    """状态机引用 id（sm- + 指纹前 12 位），供假设记录 normal_sequence_ref 引用。"""
    return f"sm-{machine_fingerprint(machine)[:12]}"


def guard_ledger(machine: Mapping[str, object]) -> dict[str, list[str]]:
    """守卫台账：已记录/未记录服务端前置条件的转移 id（batch9_2 引用校验基础）。"""
    transitions = machine.get("transitions") if isinstance(machine, Mapping) else None
    recorded: list[str] = []
    unrecorded: list[str] = []
    for transition in transitions or ():
        if not isinstance(transition, Mapping):
            continue
        if str(transition.get("server_precondition") or "").strip():
            recorded.append(str(transition["transition_id"]))
        else:
            unrecorded.append(str(transition["transition_id"]))
    return {"recorded": recorded, "unrecorded": unrecorded}


def check_sequence(
    machine: Mapping[str, object],
    step_refs: Iterable[object] | None,
    label: str = "sequence",
) -> tuple[dict, list[str]]:
    """记录序列对状态机离线回放 → (回放记录, violations)。

    step_refs 为 build 时录入的 step_id 有序列表。逐确定性四态（SEQUENCE_STEP_
    RESULTS）：首次非 ok（state_mismatch/unknown_step）后停止游标推进，剩余步骤记
    not_evaluated——mismatch 之后的回放结果不可信，不做猜测性续走。
    state_mismatch = 该转移的 from_state 与当前状态不符，即"跳过建立前置状态的
    步骤"的离线信号；仅假设信号，不构成漏洞认定。
    """
    violations: list[str] = []
    empty_result = {
        "results": [],
        "final_state": "",
        "all_ok": False,
    }
    transitions = machine.get("transitions") if isinstance(machine, Mapping) else None
    if not transitions:
        return dict(empty_result), [f"{label}: 状态机无效或零转移"]
    by_step = {str(t.get("step_id")): t for t in transitions if isinstance(t, Mapping)}
    refs = [str(r) for r in list(step_refs or [])]
    if not refs:
        return dict(empty_result), [f"{label}: 序列为空（正常状态序列必须显式给出）"]
    current = str(machine.get("entry_state") or "")
    results: list[dict] = []
    all_ok = True
    stopped = False
    for position, ref in enumerate(refs, start=1):
        if stopped:
            results.append(
                {
                    "step_ref": ref,
                    "position": position,
                    "result": "not_evaluated",
                    "expected_from": "",
                    "actual_state": "",
                    "to_state": "",
                    "transition_id": "",
                    "endpoint": "",
                    "method": "",
                    "server_precondition": "",
                    "source": "",
                    "evidence_ref": "",
                }
            )
            continue
        transition = by_step.get(ref)
        if transition is None:
            results.append(
                {
                    "step_ref": ref,
                    "position": position,
                    "result": "unknown_step",
                    "expected_from": "",
                    "actual_state": current,
                    "to_state": "",
                    "transition_id": "",
                    "endpoint": "",
                    "method": "",
                    "server_precondition": "",
                    "source": "",
                    "evidence_ref": "",
                }
            )
            all_ok = False
            stopped = True
            continue
        expected_from = str(transition.get("from_state") or "")
        if expected_from != current:
            results.append(
                {
                    "step_ref": ref,
                    "position": position,
                    "result": "state_mismatch",
                    "expected_from": expected_from,
                    "actual_state": current,
                    "to_state": "",
                    "transition_id": str(transition.get("transition_id") or ""),
                    "endpoint": str(transition.get("endpoint") or ""),
                    "method": str(transition.get("method") or ""),
                    "server_precondition": str(
                        transition.get("server_precondition") or ""
                    ),
                    "source": str(transition.get("source") or ""),
                    "evidence_ref": str(transition.get("evidence_ref") or ""),
                }
            )
            all_ok = False
            stopped = True
            continue
        current = str(transition.get("to_state") or "")
        results.append(
            {
                "step_ref": ref,
                "position": position,
                "result": "ok",
                "expected_from": expected_from,
                "actual_state": current,
                "to_state": current,
                "transition_id": str(transition.get("transition_id") or ""),
                "endpoint": str(transition.get("endpoint") or ""),
                "method": str(transition.get("method") or ""),
                "server_precondition": str(transition.get("server_precondition") or ""),
                "source": str(transition.get("source") or ""),
                "evidence_ref": str(transition.get("evidence_ref") or ""),
            }
        )
    return {"results": results, "final_state": current, "all_ok": all_ok}, violations


def extract_mismatch_signals(
    machine: Mapping[str, object],
    sequences: Iterable[object],
    label: str = "state_machine",
) -> tuple[list[dict], list[str]]:
    """回放多组记录序列 → (state_mismatch 假设种子, violations)。

    每组序列可为 {"sequence_ref": str, "steps": [...]} 或裸 step_id 列表。
    种子字段含被跳过转移的端点/方法/服务端前置条件（供 batch9_2 成立条件 2 引用；
    守卫未记录时该字段为空，batch9_2 校验将拒绝该种子升级为假设）。
    红线：仅假设信号，不构成漏洞认定，不得升级任何候选。
    """
    signals: list[dict] = []
    violations: list[str] = []
    for index, sequence in enumerate(sequences, start=1):
        if isinstance(sequence, Mapping):
            refs = sequence.get("steps")
            sequence_ref = str(sequence.get("sequence_ref") or "").strip() or (
                f"seq-{index:04d}"
            )
        else:
            refs = sequence
            sequence_ref = f"seq-{index:04d}"
        record, seq_violations = check_sequence(
            machine, refs, label=f"{label}.{sequence_ref}"
        )
        violations += seq_violations
        for result in record["results"]:
            if result.get("result") != "state_mismatch":
                continue
            signals.append(
                {
                    "kind": "state_mismatch",
                    "sequence_ref": sequence_ref,
                    "step_ref": result["step_ref"],
                    "position": result["position"],
                    "transition_id": result["transition_id"],
                    "endpoint": result["endpoint"],
                    "method": result["method"],
                    "server_precondition": result["server_precondition"],
                    "expected_from": result["expected_from"],
                    "actual_state": result["actual_state"],
                    "source": result["source"],
                    "evidence_ref": result["evidence_ref"],
                }
            )
    return signals, violations
