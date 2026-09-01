# 小程序 engagement artifact contract

## Required root artifacts

既有 engagement、素材、包清单、hosts/endpoints、阶段游标、review ledger 和 evidence index 等内部产物继续按本契约保存；原始包、原始流量、凭证和 PII 只能留在受限本地目录，报告安全件放在 `evidence/redacted/`。

`reports/攻防成果报告_<engagement>_<日期>.docx` 是主交付物，由 `report_docx.py` 依据模板生成；`reports/final-report.md` 仅为内部工作稿。

## Report contract

报告必须遵循用户 DOCX 模板的固定结构：资产归属证明网址、备案系统证明网址（模板保留时）、目标信息/基本情况表、成果说明、详细复现命令或操作步骤、返回结果/结果解读、存在问题、整改建议。

生成器不得动态生成长标题、团队/日期头部、综述/执行摘要/渗透路径/阶段总结、独立证据截图章节、红色截图语句或证据文件列表。截图由人工插入，生成器只写正常的结果位置。

canonical finding 至少保留 `finding_id`、`title`、`description`、`system`、目标 URL、漏洞类别、风险等级、数据量/影响范围、权限、`commands`、`steps`、`note`、`interpretation`、预期/实际结果、`pagination` 和 `cleanup`。环境准备来自 `meta.env_lines`。完整命令和步骤按原始顺序保留；边界说明归入备注，不能冒充命令；无真实命令时明确显示“【请补充实际复现命令】”。

同一规范化资产 + 同一漏洞类别只生成一个成果并合并多个入口；不同资产、不同类别、candidate/安全观察/未测试项必须分开且不得升级为 confirmed。问题和整改建议各最多 2 条；数据量字段遵循有明确条数才显示、否则回退影响范围、两者都无则省略。

## Sensitive storage and closure

凭证、会话、密钥、原始 PII 和未脱敏响应不得进入 DOCX、日志、台账或交接文本。交付前由报告人员自行插入脱敏截图并人工审计，之后再闭合 reporting 阶段。
