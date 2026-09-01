# 施工表 01 逐文件验收登记

> 本记录仅引用离线命令摘要和本地代码路径，不包含凭证、session、HAR、raw 响应或真实运行产物。

| 文件 | 命令/检查 | 返回码 | 结果 | 证据 |
|---|---|---:|---|---|
| `src/authorized_assessment/orchestration/graph.py` | `py_compile`；直接 import；模型 round-trip/拓扑测试 | 0 | 通过 | `tests/test_graph.py` |
| `src/authorized_assessment/orchestration/graph_validation.py` | `py_compile`；直接 import；非法图/环/cursor/version 测试 | 0 | 通过 | `tests/test_graph_contracts.py`; `tests/test_graph.py` |
| `src/authorized_assessment/orchestration/graph_builder.py` | `py_compile`；直接 import；sequence/condition/fan-out/fan-in/loop 测试 | 0 | 通过 | `tests/test_graph.py` |
| `src/authorized_assessment/orchestration/graph_routes.py` | `py_compile`；直接 import；条件路由/fail-closed 测试 | 0 | 通过 | `tests/test_graph_routes.py` |
| `src/authorized_assessment/orchestration/graph_barriers.py` | `py_compile`；直接 import；all/any/barrier 状态测试 | 0 | 通过 | `tests/test_graph_barriers.py` |
| `src/authorized_assessment/orchestration/stream_graphs.py` | `py_compile`；直接 import；WZ/XCX/FH 工厂和 cursor 隔离测试 | 0 | 通过 | `tests/test_graph.py` |
| `tests/test_graph.py` | `PYTHONPATH=src .venv/Scripts/python.exe -m pytest -q tests/test_graph.py` | 0 | 通过 | 4 个测试 |
| `tests/test_graph_routes.py` | `PYTHONPATH=src .venv/Scripts/python.exe -m pytest -q tests/test_graph_routes.py` | 0 | 通过 | 3 个测试 |
| `tests/test_graph_barriers.py` | `PYTHONPATH=src .venv/Scripts/python.exe -m pytest -q tests/test_graph_barriers.py` | 0 | 通过 | 4 个测试 |
| `tests/test_graph_contracts.py` | 与表01专项测试定向组合执行 | 0 | 通过 | 现有 graph contract 负例/正例 |
| 表01组合验收 | `PYTHONPATH=src .venv/Scripts/python.exe -m pytest -q tests/test_graph.py tests/test_graph_routes.py tests/test_graph_barriers.py tests/test_graph_contracts.py` | 0 | **21 passed, 1 warning** | `construction_tables/01_code_worker.json`; `01_verifier.json` |
| 表01变更 | `git diff --check` | 0 | 通过 | 提交 `80694a4` |

## 汇总

- 实现文件：6 个，均编译并直接导入成功。
- 专项测试：3 个，均通过。
- 现有 graph contract 测试：通过。
- 组合定向验收：21 passed, 1 warning。
- Code Worker：`construction_tables/01_code_worker.json`。
- Analyst Worker：`construction_tables/01_analyst_worker.json`。
- Verifier：`construction_tables/01_verifier.json`，状态 `verified`。
- 阶段状态：`construction_tables/01_phase_status.json` → `complete`。
- 网络请求：0。
- 工具执行：0。
- 敏感资料读取：0。
- 未修改施工表 00、02、03、04 文件或具体 engagement 游标。

## 后续边界

- Runtime 执行期 loop、join readiness、approval 消费和 Supervisor 接线属于后续施工表。
- 施工表 04 仍需等待施工表 03 完成/合并确认，并按其自身门控启动。
