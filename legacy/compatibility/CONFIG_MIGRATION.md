# 配置迁移说明

当前配置采用兼容优先策略：

- `gov_exercise_config.json`：主流程运行时、速率控制、禁用动作和工具候选。
- `gov_exercise_workflow.json`：机器可读阶段定义和输出契约。
- `tool_strategy.json`：阶段主备工具和审批门策略。
- `config.yaml`：旧配置/本地兼容输入。
- `config.py`：历史天狐工具路径注册表，仅供 legacy 模块使用。
- `project_paths.py`：统一路径解析，支持未来将配置移入 `config/` 后平滑切换。

新代码禁止新增 `from config import ...`。需要工具路径时应使用 `project_paths.py` 或 `exercise_runtime.py` 的受控发现逻辑。配置物理迁移前必须更新所有固定引用并通过离线门禁。
