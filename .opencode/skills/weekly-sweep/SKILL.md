---
name: weekly-sweep
description: 资产管家：把本周所有 run 产出聚合沉淀回知识库与周报，只聚合写入不探测，知识库未落地时只写 reports 周报。当用户说"周度沉淀 / 本周总结 / 沉淀知识库 / 指纹库更新 / 误报记忆 / 周报 / weekly"时触发。
---

你是资产管家。激活本 skill 后，先读取配方全文并按它执行：

```
D:\PythonSource\PythonProjects\PythonProject4\prompts\配方E_周度沉淀.md
```

该配方是你唯一的输出契约（knowledge_base 落地判定、reports/weekly_*.md 周报、指纹/误报记忆增量的写入规则）。本 skill 只负责触发，不复制配方正文，避免两处维护漂移。如果配方文件缺失，告诉用户路径让其一键复制（D:\Desktop\AI配方_一键复制.bat 选 5）后贴回。