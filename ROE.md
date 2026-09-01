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

补充禁止（源：authorization-boundaries.md:27-33）：DDoS/CC、ARP/DHCP 欺骗、DNS 劫持、无线干扰、物理入侵、社工/近场、破坏性/自传播/自动删文件恶意软件、篡改/删除业务数据、修改业务系统口令/账号、全量导出/下载/留存防守方敏感数据、攻击未授权目标/演习平台/其他队伍/范围外设施、未报备的境外基础设施、演习结束后保留后门或恶意软件。

- 漏洞证明例外：仅当漏洞已经满足授权、可触达、可复现和实质影响条件，且**经操作者允许、由操作者在线明确触发/控制**时，可以通过**只读、服务端限定数量/字段的请求**取得 **3–5 条最小必要的未脱敏代表性数据**。取得后立即停止；这不是默认批量读取权限，也不适用于仅为寻找漏洞的探索阶段。
- 操作者允许后可由 AI 代为运行该只读受限请求并采集证据；未获操作者允许、无人值守或仅在探索阶段，AI 不得自行取得上述样本。
- 该只读例外要求请求本身使用最小范围参数（例如单对象、明确字段、明确 page size/limit=3–5）；如果服务端不支持限制、响应包含全集、分页上限无法控制，或返回数量超过 5 条，AI 不得下载后再本地挑样本，必须停止并标记 `sample_bound_unavailable`，由操作者自行决定后续处理。
- 该例外取得的 3–5 条最小必要未脱敏代表性数据，应在报告/证据中以**原始结构与值形态**保留（字段名、实际代表值、顺序、数量、请求/响应骨架）——因为仅脱敏或占位无法区分"操作者/AI 主动脱敏"还是"目标自身防护掩码"，不能证明越权或泄露确已发生，会因证明力不足被驳回；故允许在报告/证据中保留符合条件的原始结构。
- 其余敏感数据仍严格"不流出"：凭证类秘密（Cookie/TOKEN/Authorization/session_key/AppSecret/密码）与全量/批量数据不得进入报告模板、普通日志、prompt、ledger、git、交接提示词或外部服务；同样禁止以"先取全集再挑样本、自动化循环取样、批量分页、dump、heapdump 下载、完整 HAR 导出"规避本条限制。
- 无人值守模式下 AI 不得自动取得上述敏感证明样本；确需取得时只能留下操作者人工复现待办。截图、录屏和最终成果证据由操作者自行完成，AI 不自动生成、整理或审计截图。

规则：工具具备高风险能力 ≠ 授权使用该能力（源：authorization-boundaries.md:44）。

## 4. 凭证纪律

- 凭证文件（auth_sessions.local.json / sessions.jsonl 等 *.local.*）只存本地（.gitignore 已排除），供本地脚本读取与认证态测试使用。
- **操作员在会话中主动提供凭证**（粘贴 cookie/token/Authorization，或要求把凭证写入文件）：AI **应当接收**，写入对应本地凭证文件（按 host 组织进 auth_sessions.local.json），并在授权范围内用该凭证执行认证态测试。回复只确认"已写入 auth_sessions.local.json（host=xxx）"，不复述凭证值。
- AI 不得主动索要凭证；最多提示"如需认证态测试，可在会话中提供该站点 cookie，我会写入本地凭证文件"。
- 凭证内容禁止外泄：不进报告、不进 prompt 模板、不进日志样例、不进截图、不进 findings_ledger / review_ledger、不进交接提示词、不进 git、不进外部服务。
- 敏感信息默认不自动下载、导出或留存；仅在上方漏洞证明例外成立且经操作者允许（在线明确触发/控制）时，才允许取得 3–5 条最小必要的未脱敏代表性数据，亦可由 AI 在操作者允许后代为运行。

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