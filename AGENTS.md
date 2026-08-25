# 项目入口（AI 必读）

## 项目定位

- 授权安全演练辅助平台：目标是授权 SRC/护网/演练资产，禁止一切范围外探测。
- 低速、只读、证据导向：默认 delay≥2s、单线程、只读 GET；批量动作全部走确定性脚本，AI 不做原始批量扫描。
- `runs/` 是唯一事实源：每个 run 一个时间戳目录，所有候选/证据/队列结构化落盘；AI 会话无状态、可丢弃、可换模型。

## 安全边界

- 默认只读。写操作（弱口令、上传、SQLMap、ShiroAttack2、竞态写端点等）= 脚本审批门 + 会话内人工显式确认，双钥匙缺一不可。
- 禁止动作（`gov_exercise_config.json` 的 blocked_actions，全表）：password_spray / bruteforce / webshell / c2 / tunnel / data_export / destructive_write / ddos / social_engineering / near_field。
- 凭证纪律：sessions.jsonl / auth_sessions.local.json 只被本地脚本读取；凭证内容永不进对话、不进报告、不进 prompt。
- 停止条件：窗口关闭、服务劣化、出现范围外资产、WAF 告警迹象——立即停手并报告。

## 快速入口

| 入口 | 用途 |
|---|---|
| D:\Desktop\一键完整流程_含弱口令.bat | 主流程：一键跑完整攻击链（含弱口令阶段） |
| D:\Desktop\一键已有子域名后流程_含弱口令.bat | 已有子域名清单，从活性/指纹阶段接着跑 |
| D:\Desktop\一键保守全流程_尽量多信息_避WAF.bat | 保守模式：低速、尽量避开 WAF 触发 |
| D:\Desktop\SQLi会话探测.bat | SQLi 三合一探测（预算 16/参数、基线差分、marker） |
| D:\Desktop\AI配方_一键复制.bat | 菜单 1-7（A-F/P） 复制 prompts/ 配方全文到剪贴板，粘贴给任意 AI 启动对应会话 |
| D:\Desktop\一键IDOR差分_只读.bat | 越权差分：输入 run 目录/会话文件/端点文件，跑 idor_triage.py（只读） |
| D:\Desktop\一键竞态靶场.bat | 本地起竞态靶场（8892）：/claim 漏洞真值 /claim_safe 负例，判据校准教学 |
| D:\Desktop\一键竞态测试_授权目标.bat | 读 race_config.json 对授权目标跑竞态（开场 YES 确认；写端点需 ack） |
| gov_exercise_runner.py --resume-run-dir <run目录> | 断点续跑已有 run（73 个 CLI 参数） |
| runs\last_one_click_run.txt | 记录最近一次一键流程的 run 目录 |
| runs\<ts>\00_重要_人工复核入口\README_先看这里.md | 跑完第一步：读队列说明（01_重要_Cookie、02_业务API只读确认项、04C_XSS反射候选 等编号队列） |
| engagements\<目标名-日期>\ | wz/xcx 深挖工作区：phase_status.json 游标 + review_ledger.csv 台账（L 编号）+ notes\ 各阶段记录 + artifacts\ 证据；复核/规划/度量会话都要读它，别只看 runs\ |
| python run_lifecycle.py runs\<ts> | 查询 run 完成态（scan/复核/规划/轻量穷尽/沉淀），回答"跑完了吗/下一步是什么"；验收用 prompts\配方Z_全流程验收.md |

## 上下文纪律（6 条硬约束）

1. 会话预算窗口（询问式交接）：一个会话可连续推进多个轻量阶段（脚本级阶段连做，如 scope→subdomain→alive_probe→fingerprint），每个阶段完成后依次：更新游标写盘 → 补全阶段记录（必须 handoff-complete：维护累积的目标理解快照——host 地图/技术栈/入口/认证拓扑/每个考虑过的攻击面状态含已排除项及理由，并记录没测什么及为什么；负面空间漏记 = 下个会话漏攻击面） → **询问操作者"继续本会话还是交接新会话"**（要交接就给自包含交接提示词，只导航盘上事实源，不凭对话记忆总结；说继续则原会话续推）。撞到停点即止——审批门阶段（弱口令/漏洞利用/审批门）、重量级阶段（认证态复核/报告生成）或上下文预算线（见第 6 条三档线），三者先到先停。
2. 只读任务明确列出的文件；references 按需加载，不预读。
3. 原始响应/HAR/JS 不进对话，只引用文件路径 + 行号。
4. 工具结果即用即清，不累积在上下文里。
5. 进度游标写盘（phase_status.json 或指定状态文件），不依赖对话记忆。
6. 上下文预算三档线（2026-08-23 起，替代单一 70%；绝对 token，换模型不失效）：① 建议交接线 ~12万 token（重推理阶段：复核判定/规划/复杂调试）或 ~15万（轻量脚本阶段）——在阶段边界推荐交接；② 硬收尾线 min(20万, 窗口70%)——立即收尾写盘并给交接提示词，继续需用户显式确认；③ 70% 仅作小窗口模型的换算兜底。当前 100 万窗口换算：约 12-15% 建议、20% 硬停。

## 运行时（三个 Python，能力不同，务必按用途选）

| 用途 | 路径 | 版本 | 关键库 |
|---|---|---|---|
| 新工具默认 / 竞态工具（唯一 h2） | D:\PythonSource\PythonProjects\PythonProject4\.venv\Scripts\python.exe | 3.14.4 | requests 2.33.1 + h2 4.3.0 |
| 主流程运行时（gov_exercise_config.json 指定） | D:\Desktop\天狐渗透工具箱-社区版V3.0+4.0更新升级包\天狐渗透工具箱-社区版V3.0\python3\python.exe | 3.12.4 | requests 2.28.1（无 h2） |
| 文档生成 | python3（PATH 或 C:\Users\ASUS\AppData\Local\Python\bin\python3.exe） | 3.14.4 | python-docx |

## 深入阅读

- 已存在：
  - GOV_EXERCISE_RUNNER.md —— 主编排器说明
  - gov_exercise_config.json —— rate_control / blocked_actions / 工具路径
  - tool_strategy.json —— 34 个 phase 的主备工具映射 + approval_gated_phases
  - AGENT_MANIFEST.md —— 机器可读工具清单（由 scripts/gen_agent_manifest.py 生成，勿手改）
  - ROE.md —— 交战规则（授权边界/速率/动作分级/凭证纪律）
  - prompts\ —— 会话配方 A-F（AI配方_一键复制.bat 复制到剪贴板）
  - .claude\skills\{wz,xcx,fh}\ —— 三个工作流 skill（单会话单阶段执行）
  - .agents\skills\authorized-pentest-workflow\ —— 授权边界
- 施工中（后续版本挂载）：无（W1-W4 已落地，W5+ 按 CONSTRUCTION_STATUS.md 推进）。