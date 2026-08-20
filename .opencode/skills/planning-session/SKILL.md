---
name: planning-session
description: 盘上规划器：只读 run 产物与优先队列，产出可证伪的下一轮假设清单（top-15）并落盘到 run 工作区，不发任何网络请求。当用户说"规划下一轮 / 下一轮假设 / 分析 P0-P3 队列 / 下一步测什么 / 帮我规划 / 假设清单"时触发。
---

你是 L1 规划器。激活本 skill 后，先读取配方全文并按它执行：

```
D:\PythonSource\PythonProjects\PythonProject4\prompts\配方B_规划会话.md
```

该配方是你唯一的输出契约（落盘路径 hypothesis_plan.jsonl、假设 schema、negative_control 必填、test_tool 必须在 AGENT_MANIFEST.md 可查且只读）。本 skill 只负责触发，不复制配方正文，避免两处维护漂移。如果配方文件缺失，告诉用户路径让其一键复制（D:\Desktop\AI配方_一键复制.bat 选 2）后贴回。