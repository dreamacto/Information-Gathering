# 施工表 04 逐文件验收登记

> 基线：v3 `74ab28c`。本表仅做离线结构化验证；不包含真实目标请求、凭证、session、HAR/raw 响应或真实运行产物。

| 文件 | 命令/检查 | 返回码 | 结果 | 证据 |
|---|---|---:|---|---|
| `src/authorized_assessment/orchestration/verifier.py` | `.venv/Scripts/python.exe -m py_compile`; 直接 import; `tests/test_verifier.py` | 0 | 通过 | `tests/test_verifier.py`; `04_code_worker.json` |
| `src/authorized_assessment/orchestration/phase_verifier.py` | `.venv/Scripts/python.exe -m py_compile`; 直接 import; `tests/test_phase_verifier.py` | 0 | 通过 | `tests/test_phase_verifier.py`; `04_code_worker.json` |
| `src/authorized_assessment/orchestration/worker_output_verifier.py` | `.venv/Scripts/python.exe -m py_compile`; 直接 import; `tests/test_worker_output_verifier.py` | 0 | 通过 | `tests/test_worker_output_verifier.py`; `04_code_worker.json` |
| `src/authorized_assessment/orchestration/evidence_verifier.py` | `.venv/Scripts/python.exe -m py_compile`; 直接 import; 相邻 `tests/test_evidence_gate.py` | 0 | 通过 | `tests/test_evidence_gate.py`; `04_code_worker.json` |
| `src/authorized_assessment/orchestration/approval_verifier.py` | `.venv/Scripts/python.exe -m py_compile`; 直接 import; `tests/test_context_verifier.py` | 0 | 通过 | `tests/test_context_verifier.py`; `04_code_worker.json` |
| `src/authorized_assessment/orchestration/context_verifier.py` | `.venv/Scripts/python.exe -m py_compile`; 直接 import; `tests/test_context_verifier.py` | 0 | 通过 | `tests/test_context_verifier.py`; `04_code_worker.json` |
| `src/authorized_assessment/analysis/performance_metrics.py` | `.venv/Scripts/python.exe -m py_compile`; 直接 import; `tests/test_performance_metrics.py` | 0 | 通过 | `tests/test_performance_metrics.py`; `04_code_worker.json` |
| `tests/test_verifier.py` | pytest 定向 | 0 | 通过 | 4 tests |
| `tests/test_phase_verifier.py` | pytest 定向 | 0 | 通过 | 6 tests |
| `tests/test_worker_output_verifier.py` | pytest 定向 | 0 | 通过 | 5 tests |
| `tests/test_context_verifier.py` | pytest 定向 | 0 | 通过 | 4 tests |
| `tests/test_performance_metrics.py` | pytest 定向 | 0 | 通过 | 4 tests |
| 既有 quality/evidence/context/worker/runtime 测试 | pytest 兼容回归 | 0 | 通过 | 179 tests |

## 汇总

- 表04专属定向测试：`23 passed, 1 warning`。
- 相邻兼容回归：`179 passed, 1 warning`。
- 合并回归：`202 passed, 1 warning`。
- 7 个生产模块：编译通过、直接导入通过。
- `git diff --check`：通过。
- 网络请求：0；真实目标请求：0。
- 凭证/session/HAR/raw/真实运行产物读取：0。
- 敏感错误只保留路径，不回显敏感值。
- 工作区已有施工表外脏改动与未跟踪文件未修改、未清理、未纳入本表范围。
- 表01旧 `.zcode/table01_graph_static_handoff.json` 的 `needs_manual_validation` 与正式表01 `verified` 记录冲突已作为剩余风险记录，未静默覆盖。
- 阶段状态：`construction_tables/04_phase_status.json` → `complete`；Verifier → `verified`；`handoff_ready=true`。
