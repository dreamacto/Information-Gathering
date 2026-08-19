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
| gov_exercise_runner.py --resume-run-dir <run目录> | 断点续跑已有 run（73 个 CLI 参数） |
| runs\last_one_click_run.txt | 记录最近一次一键流程的 run 目录 |
| runs\<ts>\00_重要_人工复核入口\README_先看这里.md | 跑完第一步：读队列说明（01_重要_Cookie、02_业务API只读确认项、04C_XSS反射候选 等编号队列） |

## 上下文纪律（6 条硬约束）

1. 单会话单阶段：一个会话只推进一个阶段，做完即停并更新状态文件。
2. 只读任务明确列出的文件；references 按需加载，不预读。
3. 原始响应/HAR/JS 不进对话，只引用文件路径 + 行号。
4. 工具结果即用即清，不累积在上下文里。
5. 进度游标写盘（phase_status.json 或指定状态文件），不依赖对话记忆。
6. 上下文预算到 70% 立即收尾、写盘，并提示用户开新会话续作。

## 运行时（三个 Python，能力不同，务必按用途选）

| 用途 | 路径 | 版本 | 关键库 |
|---|---|---|---|
| 新工具默认 / 竞态工具（唯一 h2） | D:\PythonSource\PythonProjects\PythonProject4\.venv\Scripts\python.exe | 3.14.4 | requests 2.33.1 + h2 4.3.0 |
| 主流程运行时（gov_exercise_config.json 指定） | D:\Desktop\天狐渗透工具箱-社区版V3.0+4.0更新升级包\天狐渗透工具箱-社区版V3.0\python3\python.exe | 3.12.4 | requests 2.28.1（无 h2） |
| 文档生成 | python（PATH） | 3.13.x | python-docx |

## 深入阅读

- 已存在：
  - GOV_EXERCISE_RUNNER.md —— 主编排器说明
  - gov_exercise_config.json —— rate_control / blocked_actions / 工具路径
  - tool_strategy.json —— 30 个 phase 的主备工具映射 + approval_gated_phases
  - .claude\skills\{wz,xcx,fh}\ —— 三个工作流 skill（单会话单阶段执行）
  - .agents\skills\authorized-pentest-workflow\ —— 授权边界
- 施工中（后续版本挂载）：ROE.md（交战规则）、AGENT_MANIFEST.md（工具清单）、prompts/（会话配方）。