# 施工表 07 逐文件验收登记

> 基线：v3 `74ab28c`。本表仅实现离线、本地、可注入 worker 的 Supervisor 调度与审批控制面；不启动真实目标工具，不读取凭证、session、HAR/raw 响应或真实运行产物。工作区既有表外脏改动保持不变。

| 文件 | 编译/导入 | 契约 | 直接单测/兼容 | 错误路径与边界 | 结果/证据 |
|---|---|---|---|---|---|
| `src/authorized_assessment/orchestration/supervisor.py` | py_compile；直接 import | Supervisor 生命周期、handoff snapshot、cursor delegation | `tests/test_supervisor.py`；相邻回归 | missing worker、XCX cursor isolation | 通过；`07_code_worker.json` / `07_verifier.json` |
| `src/authorized_assessment/orchestration/scheduler.py` | py_compile；直接 import | GraphSpec/GraphBuilder、dependency/barrier、retry_limit | `tests/test_scheduler.py`；graph/barrier regression | invalid graph、permission denial、timeout/retry、blocked dependency | 通过 |
| `src/authorized_assessment/orchestration/fanout.py` | py_compile；直接 import | stable branch lineage/idempotency、workflow cursor | `tests/test_fanout_fanin.py` | duplicate/empty branch normalization、cross cursor rejection | 通过 |
| `src/authorized_assessment/orchestration/fanin.py` | py_compile；直接 import | `evaluate_barrier` all/any/barrier | `tests/test_fanout_fanin.py`; `test_graph_barriers.py` | missing、failed、timeout、cancelled branch | 通过 |
| `src/authorized_assessment/orchestration/approval_interrupt.py` | py_compile；直接 import | existing two-key approval verifier | `tests/test_approval_interrupt.py`; `test_context_verifier.py` | absent approval、expired/revoked/duplicate、blocked action、stop active | 通过 |
| `src/authorized_assessment/orchestration/kill_switch.py` | py_compile；直接 import | thread-safe stop propagation | `tests/test_kill_switch.py` | invalid reason、idempotent request/clear、child cancellation | 通过 |
| `src/authorized_assessment/orchestration/retry_policy.py` | py_compile；直接 import | worker error retryability and retry_limit | `tests/test_retry_policy.py`; `test_worker_errors.py` | invalid attempt/limit、non-retryable/stop/cancel | 通过 |
| `src/authorized_assessment/orchestration/orchestration_runtime.py` | py_compile；直接 import | TaskEnvelope, EventJournal, Checkpoint, Lease, WorkerExecutor adapters | `tests/test_supervisor.py`; checkpoint/event/lease/recovery regression | invalid journal/checkpoint, cursor mismatch, missing worker, lease conflict | 通过 |
| `tests/test_supervisor.py` | py_compile | runtime contract assertions | 2 passed | WZ/XCX, missing worker | 通过 |
| `tests/test_scheduler.py` | py_compile | scheduler contract assertions | 2 passed | retry and permission failure | 通过 |
| `tests/test_fanout_fanin.py` | py_compile | branch/barrier assertions | 2 passed | timeout and stable IDs | 通过 |
| `tests/test_approval_interrupt.py` | py_compile | approval gate assertions | 2 passed | missing approval and active stop | 通过 |
| `tests/test_retry_policy.py` | py_compile | retry decision assertions | 3 passed | invalid values and stop | 通过 |
| `tests/test_kill_switch.py` | py_compile | cancellation propagation assertions | 1 passed | idempotent request/clear | 通过 |

## Code Worker

- 15 个表 07 文件编译通过；8 个生产模块直接导入通过。
- 表 07 定向测试：`12 passed`。
- 网络请求、真实目标请求、凭证/session/HAR/raw/真实运行产物读取：均为 0。
- 记录：`construction_tables/07_code_worker.json`。

## Analyst Worker（完整游标依据）

- 依据 AGENTS、ROE、RULE_PRECEDENCE、CONTEXT_LOADING_MAP、编排架构/状态事件/Worker 合同、表 06 交接、graph/task/checkpoint/event/recovery/verifier 实现与 Code Worker 结果。
- 已结构化记录 `facts_used`、`reasoning_summary`、`alternative_explanations`、`hypotheses`、`unknowns`、`coverage`、`not_tested`、`next_hints`。
- 记录：`construction_tables/07_analyst_worker.json`。

## Verifier

- 逐文件编译、import、契约、定向单测、相邻兼容、空/非法输入、超时/取消/权限拒绝、敏感字段检查通过。
- 相邻编排回归：`71 passed, 1 warning`；`git diff --check` 通过。
- 唯一 `status: verified` 记录：`construction_tables/07_verifier.json`。

## 汇总与状态

- 状态：`complete`；handoff-ready：`true`。
- WZ 使用 `phase_status.json`；XCX 使用 `phase_status.miniapp.json`，未交叉写入。
- 覆盖：Supervisor、Scheduler、fan-out/fan-in、approval interrupt、kill switch、retry、Runtime、checkpoint/event、lease conflict、双结果控制面接线。
- 未测/后续 operator tasks：跨进程 OS 子进程终止、长任务 lease renewal、live network/真实 engagement、FH 端到端、operator approval UI、完整 specialist Code→Analyst→Verifier 真实适配。
- 审批门：任何未来写端点、主动网络适配器、凭证测试或 ROE 审批门动作仍需脚本审批门与会话内人工确认；本表未执行。
- 证据与结果不含原始 payload、凭证、session、HAR/raw 响应或敏感数据。
