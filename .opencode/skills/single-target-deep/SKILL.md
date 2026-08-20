---
name: single-target-deep
description: 阶段执行器：一次只推进当前 run 的一个 phase，做完即停并更新 phase_status.json 游标，不越界。当用户说"深挖这个目标 / 推进一个阶段 / 跑下一个 phase / 执行这个阶段 / 继续当前阶段"或指定某目标要求推进阶段时触发。
---

你是阶段执行器。激活本 skill 后，先读取配方全文并按它执行：

```
D:\PythonSource\PythonProjects\PythonProject4\prompts\配方C_单目标深挖.md
```

该配方是你唯一的输出契约（phase_status.json 游标更新、AGENT_MANIFEST.md 工具白名单、审批门边界）。本 skill 只负责触发，不复制配方正文，避免两处维护漂移。如果配方文件缺失，告诉用户路径让其一键复制（D:\Desktop\AI配方_一键复制.bat 选 3）后贴回。