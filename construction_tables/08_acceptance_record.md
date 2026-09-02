# 施工表 08 验收记录：入口迁移与兼容模式

## 结果
- 状态：complete
- handoff_ready：true
- 范围：仅本地离线控制面；未发真实目标请求。

## 新增/修改文件
- `src/authorized_assessment/orchestration/feature_flags.py`
- `src/authorized_assessment/orchestration/compatibility_mode.py`
- `src/authorized_assessment/orchestration/one_click_workflow.py`
- `src/authorized_assessment/orchestration/parallel_flow_runner.py`
- `gov_exercise_runner.py`
- `tests/test_orchestration_compatibility.py`
- `tests/test_launcher_orchestration.py`

根目录 `one_click_workflow.py`、`parallel_flow_runner.py` 保持薄转发，未改动。

## 逐文件测试登记
| 文件 | 编译 | 直接 import | 契约/兼容 | 错误路径 |
|---|---|---|---|---|
| feature_flags.py | pass | pass | 四模式、快照/hash、敏感字段拒绝 | pass |
| compatibility_mode.py | pass | pass | blocked 优先、readonly/active、assessment_id lease | pass |
| src one_click_workflow.py | pass | pass | legacy command shape、显式 graph 传递 | pass |
| src parallel_flow_runner.py | pass | pass | plan/status snapshot、group policy、ownership | pass |
| gov_exercise_runner.py | pass | pass | legacy 默认、shadow/readonly 早退、active gate | pass |
| test_orchestration_compatibility.py | pass | pass | 11 项离线策略测试 | pass |
| test_launcher_orchestration.py | pass | pass | 5 项 launcher/mock 子进程测试 | pass |

命令：
- `.venv/Scripts/python.exe -m py_compile ...`：返回码 0。
- `PYTHONPATH=src .venv/Scripts/python.exe` 直接 import：返回码 0。
- `.venv/Scripts/python.exe -m pytest -q tests/test_orchestration_compatibility.py tests/test_launcher_orchestration.py tests/test_one_click_workflow.py tests/test_launcher_python_unification.py`：`24 passed, 1 warning`。
- `git diff --check`：通过。

## Code Worker
完成四模式、非敏感快照、入口 gate、legacy 兼容、parallel snapshot 和 assessment_id ownership；未触网、未读敏感材料。

## Analyst（完整游标依据）
已读取表 07 phase cursor、acceptance、Code/Analyst/Verifier 记录；结论为表 08 本地控制面契约满足。WZ 使用 `phase_status.json`，XCX 使用 `phase_status.miniapp.json`。

## Verifier
- 结论：verified。
- shadow/readonly 不启动子进程或 live 阶段链。
- active 缺少/畸形双钥匙审批时 fail-closed。
- blocked_actions 规范化并优先。
- legacy 默认不注入新参数；显式 graph 才传递 mode。
- parallel 计划/状态保留 mode snapshot/hash。
- ownership 资源键与 Runtime 一致为 assessment_id。

## 覆盖/未测/blocked/approval_required
- 覆盖：模式解析、快照序列化、敏感字段、blocked action、审批拒绝、ownership 冲突/释放/过期、launcher 兼容、无子进程门控。
- 未测：真实网络、真实运行产物、凭证/session/HAR/raw 响应、operator approval UI、批准后的 active live dispatch、长任务 lease renewal、跨进程监督、FH 端到端 graph。
- blocked：无本地阻断；active 无审批按设计返回 `approval_required`。
- approval_required：仅 active positive dispatch 场景，未自动执行。

## 安全边界检查
未发网络请求；未读凭证、真实 session、HAR/raw 响应或真实运行产物；未修改施工表 08 清单外代码；Worker/Analyst 未改 scope、approval、cursor 或写 confirmed/proven。

## 状态与 handoff
施工表 08 已 complete，`08_phase_status.json` 已写入 `handoff_ready=true`。可交接到后续阶段；后续不得把本地 gate 测试等同于真实目标执行授权。

## 剩余问题
1. 保留 1 个 pytest warning，未影响测试结果。
2. active approved 正向执行与跨进程 lease 竞争待后续明确授权/专门阶段。
3. FH 图游标契约仍由既有层定义，表 08 未扩大范围修复。
