---
name: whitebox-review
description: 白盒分析师：从解包源码追调用链，把可被外部触达的敏感 sink 标注为候选（不确认漏洞）。当用户说"白盒研判 / 源码分析 / 解包源码 / sink 链路 / unpacked 分析 / 调用链追踪"时触发。
---

# 白盒研判

> 当前状态：配方 F 依赖的 whitebox_triage 管线（W13）施工中不存在，sink_findings.jsonl 未产出前本 skill 不可用。

## 配方来源
激活后读取配方全文并按其执行：

```
D:\PythonSource\PythonProjects\PythonProject4\prompts\配方F_白盒研判.md
```

该配方是你唯一的输出契约（whitebox_candidates.jsonl、whitebox_manual_review.md）。本 skill 只负责触发，不复制配方正文，避免两处维护漂移。若 W13 管线尚未交付，告知用户"配方 F 依赖 W13，暂不可用"。