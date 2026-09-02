# 施工表 05 验收登记：WZ 专精 Worker 与图适配

## 基线与边界

- 基线：v3 `74ab28c`；v3 不含本表新增 WZ 专用模块。
- 本表只新增/修改清单中的 12 个文件；未覆盖或清理工作区既有脏改动。
- 全部检查为本地离线检查；未发送真实目标请求，未读取凭证、真实 session、HAR/raw 响应或真实运行产物。

## 逐文件测试登记

| 文件 | 编译 | 直接 import/解析 | 契约 | 定向单测 | 兼容 | 空/非法/取消/超时/权限/敏感 | 证据 |
|---|---:|---:|---:|---:|---:|---:|---|
| `src/authorized_assessment/orchestration/wz_graph.py` | 0 | 0 | 0 | 0 | 0 | 0 | `construction_tables/05_code_worker.json` |
| `src/authorized_assessment/orchestration/wz_workers.py` | 0 | 0 | 0 | 0 | 0 | 0 | `construction_tables/05_code_worker.json` |
| `src/authorized_assessment/orchestration/wz_routes.py` | 0 | 0 | 0 | 0 | 0 | 0 | `construction_tables/05_code_worker.json` |
| `src/authorized_assessment/analysis/wz_worker_plans.py` | 0 | 0 | 0 | 0 | 0 | 0 | `construction_tables/05_code_worker.json` |
| `contracts/wz_graph_schema.json` | n/a | 0 | 0 | 0 | 0 | 0 | `construction_tables/05_code_worker.json` |
| `contracts/wz_worker_result_schema.json` | n/a | 0 | 0 | 0 | 0 | 0 | `construction_tables/05_code_worker.json` |
| `tests/test_wz_graph.py` | 0 | 0 | n/a | 0 | 0 | 0 | `construction_tables/05_code_worker.json` |
| `tests/test_wz_worker_plans.py` | 0 | 0 | n/a | 0 | 0 | 0 | `construction_tables/05_code_worker.json` |
| `tests/test_wz_worker_context.py` | 0 | 0 | n/a | 0 | 0 | 0 | `construction_tables/05_code_worker.json` |
| `tests/test_wz_graph_integration.py` | 0 | 0 | n/a | 0 | 0 | 0 | `construction_tables/05_code_worker.json` |
| `tests/test_wz_graph_phase_boundary.py` | 0 | 0 | n/a | 0 | 0 | 0 | `construction_tables/05_code_worker.json` |
| `tests/test_wz_graph_isolation.py` | 0 | 0 | n/a | 0 | 0 | 0 | `construction_tables/05_code_worker.json` |

返回码约定：0=通过；n/a=不适用。定向测试 16 通过；兼容测试 71 通过；`git diff --check -- <table05 scope>` 返回 0。

## Code Worker

- 事实记录：`construction_tables/05_code_worker.json`
- 结果：模块编译/import、契约解析、定向与兼容回归、错误路径检查均通过。

## Analyst Worker（完整游标依据）

- 结构化分析：`construction_tables/05_analyst_worker.json`
- 依据：施工表 00–04 phase status、当前 WZ 规则/契约、通用 graph/worker/context/phase verifier 约定，以及本表定向/兼容测试事实。
- 已明确 `facts_used`、`reasoning_summary`、`alternative_explanations`、`hypotheses`、`unknowns`、`coverage`、`not_tested`、`next_hints`；历史 lead 不升级为当前 coverage。

## Verifier

- 验证记录：`construction_tables/05_verifier.json`
- 结论：`status=verified`，双结果、五面 fan-out/all-join、串行 approval/verifier、WZ cursor 隔离、敏感字段和只读权限门通过。

## 覆盖 / 未测 / blocked / approval_required

- 覆盖：WZ application mapping 五面、API/product/input/evidence 专精路由、离线 handler、Analyst 八字段、artifact scope、WZ/FH/XCX 隔离、phase boundary 负例。
- 未测：真实目标请求、凭证/session/HAR/raw/真实产物、生产 Supervisor/跨进程调度、FH graph cursor 兼容修复。
- `blocked=[]`；`approval_required=[]`。审批型和写型动作仅保留为路由阻断语义，未执行。

## 安全边界检查

- 网络请求：0。
- 敏感来源读取：0；敏感值输出：0。
- Worker 权限：只读、`network=none`、不可写 scope/approval/cursor/confirmed。
- 未修改共享 FH/XCX 接线；未清理既有脏工作区。

## 状态与 handoff

- `construction_tables/05_phase_status.json`：`status=complete`，游标 `complete/null`，三类 Worker 引用齐全，`handoff_ready=true`。
- 本表完成后可交接给后续串行接线；不得据此释放施工表 07，需等待施工表 06 完成并合并/确认。

## 剩余问题

1. 通用 graph 层已有 FH `run_status.json` cursor 常量兼容缺口，本表未跨表修复。
2. 生产 Supervisor、跨进程调度及真实 engagement phase-status 持久化需后续施工表处理。
