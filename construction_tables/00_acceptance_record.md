# 施工表 00 逐文件验收登记

> 本记录仅引用离线命令摘要和本地文件路径，不包含凭证、session、HAR、raw 响应或真实运行产物。

| 文件 | 命令/检查 | 返回码 | 结果 | 证据 |
|---|---|---:|---|---|
| contracts/assessment_schema.json | `python -m json.tool`；统一校验 | 0 | 通过 | contracts/assessment_schema.json |
| contracts/worker_manifest_schema.json | `python -m json.tool`；权限负例 | 0 | 通过 | tests/test_validate_run_contracts.py |
| contracts/task_envelope_schema.json | `python -m json.tool`；action 负例 | 0 | 通过 | tests/test_validate_run_contracts.py |
| contracts/worker_result_schema.json | `python -m json.tool`；双结果门/Analyst 字段 | 0 | 通过 | tests/test_agent_contracts.py; tests/test_worker_contracts.py |
| contracts/policy_decision_schema.json | `python -m json.tool`；策略枚举/allow 边界 | 0 | 通过 | tests/test_agent_contracts.py |
| contracts/checkpoint_schema.json | `python -m json.tool`；WZ/XCX cursor | 0 | 通过 | tests/test_worker_contracts.py |
| contracts/event_schema.json | `python -m json.tool`；敏感属性负例 | 0 | 通过 | tests/test_validate_run_contracts.py |
| contracts/metric_event_schema.json | `python -m json.tool`；脱敏维度/lineage | 0 | 通过 | tests/test_agent_contracts.py |
| contracts/approval_schema.json | `python -m json.tool`；双钥匙约束 | 0 | 通过 | tests/test_agent_contracts.py |
| contracts/graph_schema.json | `python -m json.tool`；DAG 负例 | 0 | 通过 | tests/test_graph_contracts.py |
| contracts/worker_error_schema.json | `python -m json.tool`；安全错误字段 | 0 | 通过 | tests/test_worker_contracts.py |
| docs/AGENT_ORCHESTRATION_ARCHITECTURE.md | 文档内容审阅 | 0 | 通过 | docs/AGENT_ORCHESTRATION_ARCHITECTURE.md |
| docs/AGENT_WORKER_CONTRACT.md | 文档内容审阅 | 0 | 通过 | docs/AGENT_WORKER_CONTRACT.md |
| docs/AGENT_STATE_AND_EVENT_MODEL.md | 文档内容审阅 | 0 | 通过 | docs/AGENT_STATE_AND_EVENT_MODEL.md |
| tests/test_agent_contracts.py | `.venv/Scripts/python.exe -m py_compile`；pytest | 0 | 通过 | 30 个专项测试的一部分 |
| tests/test_graph_contracts.py | `.venv/Scripts/python.exe -m py_compile`；pytest | 0 | 通过 | 30 个专项测试的一部分 |
| tests/test_worker_contracts.py | `.venv/Scripts/python.exe -m py_compile`；pytest | 0 | 通过 | 30 个专项测试的一部分 |
| scripts/maintenance/validate_run_contracts.py | `py_compile`；统一 pytest；`--json` | 0 | 通过 | `ok=true, violations=[]` |
| tests/test_validate_run_contracts.py | pytest | 0 | 通过 | 统一验收测试包含 85 个测试 |

## 汇总

- 新增契约专项：30 passed。
- 施工表 00 与统一校验器组合：115 passed, 1 warning。
- 统一入口：`ok=true`, `violations=[]`。
- 网络请求：0。
- 敏感资料读取：0。
- 阶段状态：`construction_tables/00_phase_status.json` → `complete`。
