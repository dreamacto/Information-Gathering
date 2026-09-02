# 施工表 06 逐文件验收登记

> 基线：v3 `74ab28c`。本表仅做离线、只读、queue-only 的 XCX 图与 Worker 适配；不包含真实目标请求、凭证、session、HAR/raw 响应或真实运行产物。施工表 05 同波次执行，00–04 已完成后本表可启动；07 仍需等待 05 与 06 均完成并确认。

| 文件 | 编译/导入 | 契约 | 直接单测/兼容 | 错误路径与边界 | 结果/证据 |
|---|---|---|---|---|---|
| `src/authorized_assessment/orchestration/xcx_graph.py` | `py_compile`；直接 import | `xcx_graph_schema.json`；生成 98 节点/136 边图校验 | `tests/test_xcx_graph.py`; `test_xcx_graph_integration.py` | 空图、错误 workflow/cursor、未知边、环、package barrier | 通过；`06_code_worker.json` |
| `src/authorized_assessment/orchestration/xcx_workers.py` | `py_compile`；直接 import | `xcx_worker_result_schema.json`；102 manifests | `tests/test_xcx_worker_context.py`; integration | 敏感字段、错误 cursor、非法 phase、非三角色 handler、queue-only | 通过；`06_code_worker.json` |
| `src/authorized_assessment/orchestration/xcx_routes.py` | `py_compile`；直接 import | XCX workflow/cursor 路由约束 | `tests/test_xcx_graph.py`; integration | 错误 workflow、错误 cursor、未知 phase、前置失败、barrier异常 | 通过；`06_code_worker.json` |
| `src/authorized_assessment/analysis/xcx_worker_plans.py` | `py_compile`；直接 import | 结构化快照字段与 queue-only 输出 | `tests/test_xcx_worker_plans.py` | 空/不完整快照、错误 workflow/cursor、敏感值、空 artifact refs | 通过；`06_code_worker.json` |
| `contracts/xcx_graph_schema.json` | JSON parse；Draft 2020-12 schema check | 生成 XCX graph 通过 | `tests/test_xcx_graph.py` | 非法 cursor、非 XCX workflow、节点/边枚举错误 | 通过；`06_verifier.json` |
| `contracts/xcx_worker_result_schema.json` | JSON parse；Draft 2020-12 schema check | code/analyst/verifier envelope 形状 | `tests/test_xcx_worker_plans.py`; integration | 缺字段、Analyst字段缺失、双结果未满足、敏感字段声明 | 通过；`06_verifier.json` |
| `tests/test_xcx_graph.py` | `py_compile` | graph schema assertions | 定向 pytest | 空/非法图、package/static 顺序 | 通过：定向集合 32 passed |
| `tests/test_xcx_worker_plans.py` | `py_compile` | plan snapshot contract | 定向 pytest | 快照缺失/敏感/错误 cursor | 通过：定向集合 32 passed |
| `tests/test_xcx_worker_context.py` | `py_compile` | WorkerContext cursor isolation | 定向 pytest | WZ/FH cursor混用、敏感字段和值、空phase | 通过：定向集合 32 passed |
| `tests/test_xcx_graph_integration.py` | `py_compile` | graph roundtrip + dual-result integration | 定向 pytest；相邻 verifier 回归 | Code/Analyst/Verifier lineage 与 dual gate | 通过：定向集合 32 passed；兼容 49 passed |
| `tests/test_xcx_graph_phase_status_isolation.py` | `py_compile` | XCX cursor-only | 定向 pytest | phase_status.json/run_status.json 混入 | 通过：定向集合 32 passed |
| `tests/test_xcx_graph_package_dependencies.py` | `py_compile` | package barrier dependency | 定向 pytest | 分支缺失、直跳 static_analysis | 通过：定向集合 32 passed |

## 汇总

- 表06专项定向测试：`32 passed, 1 warning`。
- 相邻编排兼容回归：`49 passed, 1 warning`。
- 4 个生产模块：编译、直接导入通过。
- 2 个 XCX schema：解析、Draft 2020-12 schema check、生成工件校验通过。
- 6 个测试文件：编译通过，定向测试通过。
- `git diff --check`：通过。
- 网络请求：0；真实目标请求：0。
- 凭证/session/HAR/raw/真实运行产物读取：0。
- Worker 写权限：全部保持 false；计划默认 `queue_only=true`、`network=none`。
- 工作区既有施工表外脏改动与未跟踪文件未修改、未清理、未纳入本表范围。
- XCX 阶段记录：`construction_tables/06_phase_status.json`，其中 `status_file=phase_status.miniapp.json`、`handoff_ready=true`。
- Code Worker、Analyst Worker、Verifier 三者均已落盘；仅 Verifier 记录授予 `verified`。
