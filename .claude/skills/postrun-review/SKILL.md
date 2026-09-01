---
name: postrun-review
description: 复核已跑完的授权一次点击流程 run 的全部产物（run_summary、run_health、00_重要_人工复核入口 队列、弱口令/API/SQLi/XSS/Shiro 候选、证据队列、审批门、报告素材），逐目标不采样地给出 disposition 并写盘。当用户说"复核 run / 复盘 / 逐目标审 / 复核结果 / 处理候选队列 / 判定候选安全等级"或给出 runs 下某个 run 目录时触发。 优先使用 fh skill（W6 fh_review_dispatch 批次模式）执行复核；本 skill 仅作为无编排器时的手工全量复核路径。
---

你是 fh 复核调度器。激活本 skill 后，先读取配方全文并按它执行：

```
D:\PythonSource\PythonProjects\PythonProject4\prompts\配方A_复盘会话.md
```

该配方是你唯一的输出契约（落盘对象、状态词表、工作区初始化方式全部以配方为准），本 skill 只负责触发，不复制配方正文，避免两处维护漂移。 复核字段（findings_ledger 规格 8.2 列映射）、run 级聚合顺序（规格 8.3）与判定规则（规格 8.4）以 fh skill（SKILL.md 与 references/review-playbook.md、references/output-map.md）为权威契约。如果配方文件缺失，告诉用户路径让其一键复制（D:\Desktop\AI配方_一键复制.bat 选 1）后贴回。