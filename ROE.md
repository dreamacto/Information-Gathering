# ROE（交战规则）· 唯一事实源

> 本文件合并三处现有规则：PROJECT_PROMPT.md（执行边界）、.agents/skills/authorized-pentest-workflow/references/authorization-boundaries.md（授权边界）、gov_exercise_config.json（速率红线/禁止动作）。三处源文件仍保留，以本文件为准。后续所有 AI 会话开工前必须读本文件。

## 1. 授权前提

- 本仓库所有活动仅限授权 SRC / 护网 / 攻防演练目标（源：authorization-boundaries.md:17）。
- 范围依据：授权目标清单、授权文档、SRC 范围、开源项目仓库、当前 run 的 targets 快照（源：PROJECT_PROMPT.md:19；targets 快照见 authorization-boundaries.md:11）。
- 新发现的资产（域名/子域/小程序后端/第三方资产/供应链路径）必须先做所有权确认与目标登记，再谈探测（源：authorization-boundaries.md:13,23）。
- 任务开始时按 authorized-pentest-workflow/SKILL.md 的授权备忘机制记录：源文件、目标归属/范围、测试窗口、允许/禁止/审批门动作。
- 攻击资源（VPS / 代理 IP）使用前必须先报备（源：authorization-boundaries.md:19）。

## 2. 速率红线（数字与 gov_exercise_config.json rate_control 完全一致）

| 项 | 值 |
|---|---|
| 默认请求间隔 | ≥2s（jitter ±25%） |
| 单 host 最小间隔 | ≥2s |
| 退避 | 429/500/502/503/504 → 停 10s |
| 并发上限 | 3（跨不同 host 并行；同一 host 内保持串行且 ≥2s/请求——操作者策略 20260823，`max_concurrency_default` 可调回 1） |
| 同 host 连续错误 | 5 次 → 停该 host |

- 对真实生产目标保持低速、可停止、证据导向的流程控制（源：PROJECT_PROMPT.md:20）。

## 3. 动作分级

### 3.1 免批（随时可做）

- 本地解析、离线分析、只读 GET 元数据探测。
- 授权目标的默认 triage：`--sqli-triage`（仅参数化 GET 的 curl 低影响探测，禁时间盲注/UNION/堆叠/枚举/数据导出/写入/上传/webshell/内网扫描）、`--shiro-triage`（仅基线 + 无效 rememberMe cookie 探测，只存元数据/哈希/Set-Cookie 名/队列；源：PROJECT_PROMPT.md:23-35）。
- 复核与报告：审 run 产物、写 verdict、生成报告（本地）。

### 3.2 审批门（脚本审批门 + 会话内人工显式确认，双钥匙缺一不可）

| 动作 | 附加条件 | 来源 |
|---|---|---|
| 弱口令 / 撞库 / 爆破 / 凭证测试 | 走 weak_passwd_scanner.py 等既有脚本的审批门；CAPTCHA/锁定/警告即停 | tool_strategy.json approval_gated_phases: credential_testing；authorization-boundaries.md:39 |
| SQLMap | 仅单授权候选 URL、risk=1、level=1、technique BE、带 delay、无 dump/破坏性选项 | PROJECT_PROMPT.md:28 |
| ShiroAttack2 | 仅单授权候选目标 key/rememberMe 人工验证 | PROJECT_PROMPT.md:35 |
| 上传 / 删除 / 导入导出 / 事务 / 口令账号会话修改 | 逐项显式确认，拒绝"从一般授权推断" | fh output-map 队列门；xcx/wz SKILL write 门 |
| 命令执行 / webshell / 内存马 / 隧道 / C2 / 持久化 / 后渗透 | 禁止为非幂等端点自动执行 | authorization-boundaries.md:40 |
| 内网扫描 / 数据库访问验证 | 需目标授权 + 测试窗口确认 | authorization-boundaries.md:40 |
| 产品验证工具（FastjsonScan/SpringBoot-Scan/Struts2Scan/afrog 等） | 仅单授权候选；产品特定主动模板(RCE/SQLi/反序列化/认证绕过/任意登录/文件上传/敏感文件检索)不自动跑 | authorization-boundaries.md:41；tool_strategy.json approval_gated_phases |
| 竞态写端点（W8） | race_config.write_risk_ack==true + bat 二次确认；并发上限 10 | 施工方案 W8 安全约束 |
| 新下载的攻击工具 | 需先行报备 | authorization-boundaries.md:42 |
| 核心系统 / 核心基础设施 / 供应链攻击 | 需专门批准 | authorization-boundaries.md:37-38 |

### 3.3 禁止（blocked_actions 全表，gov_exercise_config.json:blocked_actions）

`password_spray` / `bruteforce` / `webshell` / `c2` / `tunnel` / `data_export` / `destructive_write` / `ddos` / `social_engineering` / `near_field`

补充禁止（源：authorization-boundaries.md:27-33）：DDoS/CC、ARP/DHCP 欺骗、DNS 劫持、无线干扰、物理入侵、社工/近场、破坏性/自传播/自动删文件恶意软件、篡改/删除业务数据、修改业务系统口令/账号、导出/下载/留存防守方敏感数据、攻击未授权目标/演习平台/其他队伍/范围外设施、未报备的境外基础设施、演习结束后保留后门或恶意软件。

规则：工具具备高风险能力 ≠ 授权使用该能力（源：authorization-boundaries.md:44）。

## 4. 凭证纪律

- sessions.jsonl / auth_sessions.local.json 只被本地脚本读取；AI 只见元数据（源：AGENTS.md:13）。
- 凭证内容永不进对话、不进报告、不进 prompt、不进日志样例。
- 敏感信息可取证但不得导出、下载或留存（源：authorization-boundaries.md:22）。

## 5. 证据分级

| 级别 | 定义 | 升级条件 | 去向 |
|---|---|---|---|
| signal（线索） | 指纹/状态码变化/统计异常，"看起来像" | 需 L0 脚本硬判据确认 | 不写报告（PROJECT_PROMPT.md:27：500/状态变化仅作线索） |
| candidate（候选） | L0 确定性脚本输出，未人工复核 | 复核会话 verdict + 人工确认 | 00_重要_人工复核入口 队列 |
| proven（确认） | L0 硬判据命中 + 人工复核通过 | — | 报告只收 proven（fh review-playbook.md:236：pending/needs_login/approval_required/blocked/out_of_scope 不上报） |

## 6. 停止条件（任一命中立即停手并报告）

- 授权窗口关闭或测试窗口结束。
- 目标服务劣化：同 host 连续 5 次错误、退避后仍 429/5xx。
- 出现范围外资产（立即停止接触并上报）。
- WAF 告警迹象（403 连续命中、验证码弹出、流量被拦截）。
- 操作员（人）要求停止。