# 项目整体改造执行提示词（严格分批、逐项验证、禁止偷工减料）

你现在负责实施项目：

```text
D:\PythonSource\PythonProjects\PythonProject4
```

这是一个授权安全评估工作台。你的任务不是提出建议，而是严格、分阶段、可验证地实施项目改造。

## 一、必须先读的文件

开始任何代码修改前，必须按以下顺序读取：

```text
D:\PythonSource\PythonProjects\PythonProject4\AGENTS.md
D:\PythonSource\PythonProjects\PythonProject4\ROE.md
D:\PythonSource\PythonProjects\PythonProject4\.agents\skills\authorized-pentest-workflow\references\authorization-boundaries.md
D:\PythonSource\PythonProjects\PythonProject4\docs\AI_IMPLEMENTATION_SPEC_SECURITY_COVERAGE_AND_FINDING_QUALITY.md
```

但是，**不要把整个项目、所有历史 run、所有 Skill、所有 prompt 或整份 2500 行规格文件一次性全部读入上下文**。必须遵守该规格第 3 节的上下文加载规则：

```text
L0：硬边界、当前授权、当前 scope、当前 phase 状态
L1：本次任务涉及的一个 workflow
L2：本次任务涉及的一个 phase、schema、工具和测试
L3：只有在规则冲突或确有必要时，才读取相关原文或外部资料
```

如果项目中已经存在以下文件，优先使用它们；如果不存在，按规格创建：

```text
runtime/policy_snapshot.json
docs/CONTEXT_LOADING_MAP.yaml
docs/RULE_PRECEDENCE.md
src/authorized_assessment/runtime/context_loader.py
```

## 二、你的总任务

严格按照以下实施规格完成项目改造：

```text
D:\PythonSource\PythonProjects\PythonProject4\docs\AI_IMPLEMENTATION_SPEC_SECURITY_COVERAGE_AND_FINDING_QUALITY.md
```

纳入该规格中除“新增独立深挖交接清单 P1-1”之外的全部改进项。

特别包括：

1. 上下文加载和记忆保持机制；
2. 规则优先级和冲突检测；
3. 运行质量门和 INCONCLUSIVE 状态；
4. 覆盖率计算修复；
5. 候选去重；
6. 固定路径降级为 signal；
7. 漏洞成立门和严重性规则；
8. 补天通用漏洞/事件漏洞分类；
9. 补天高危/中危/低危映射；
10. AI 未经人工验证不得提交的硬门；
11. evidence gate；
12. Web/API 阶段补充；
13. GraphQL；
14. WebSocket；
15. SSRF；
16. SSTI、模板注入、XXE、解析器、反序列化、NoSQL、LDAP、XPath、路径遍历等注入分支；
17. CORS、CSRF、缓存和浏览器边界；
18. API 版本、shadow API、分页、批量、资源消耗、第三方 API；
19. 业务状态机、重放、重复提交、竞态假设和审批门；
20. 小程序登录交换、token 生命周期、签名重放；
21. 小程序本地数据、密码学、密钥处理；
22. 小程序包完整性、更新信任、版本漂移；
23. 小程序静态/动态端点对账；
24. 小程序云函数、对象存储、云数据库、第三方边界；
25. WebView、Bridge、Deep Link；
26. 工具 registry、版本、哈希、依赖和能力状态；
27. Afrog/Nuclei 模板固定和自更新禁止；
28. ffuf；
29. Dalfox 或 XSStrike 二选一；
30. subfinder + dnsx 的被动/已知候选模式；
31. Semgrep 或 CodeQL 离线白盒能力；
32. 离线 SBOM/依赖审计；
33. 历史误报记忆、精度库和 review feedback 回灌；
34. parent_run_id、attempt_no、config_hash、input_hash 等重跑生命周期；
35. test dimensions 和机器可审计覆盖矩阵；
36. fh、wz、xcx 的状态、产物、提示词、Skill、工具策略和测试同步。

## 三、最重要的执行纪律：必须一项一项做，做完验证成功后才能下一项

### 绝对禁止

- 禁止一次性修改几十个文件后再统一测试；
- 禁止只修改文档，不修改实际代码、schema、测试或入口；
- 禁止只创建空模块、TODO、伪接口或“未来再实现”；
- 禁止用注释或 README 宣称功能已经实现；
- 禁止把已有大阶段改名后声称新增了完整覆盖；
- 禁止把理论测试矩阵当成已执行覆盖；
- 禁止把工具逻辑名称当成真实可执行工具；
- 禁止因为测试困难而删除测试；
- 禁止因为兼容性问题而静默放宽授权、速率、审批门或证据门；
- 禁止自动下载工具、模板、规则或外部依赖；
- 禁止未经用户明确授权执行目标网络探测；
- 禁止执行 DDoS、暴力破解、全量数据导出、破坏性写入、WebShell、C2、隧道、持久化或其他规则禁止动作；已确认漏洞的证明例外除外：仅在经操作者允许并在线明确触发（允许后可由 AI 运行）、目标已授权、漏洞成立门已满足，且请求本身已由服务端限定字段和数量时，可通过只读请求取得 3–5 条最小必要的未脱敏代表性业务数据，取得后立即停止；如果响应会返回全集、超过 5 条或只能先取全集再本地挑样本，必须停止并记录 `sample_bound_unavailable`；
- 禁止在探索阶段、无人值守模式或未满足漏洞成立门时读取、复制、打印、写入或输出 Cookie、Token、Authorization、session_key、AppSecret、密码和敏感数据原文；已确认漏洞且经操作者允许（在线明确触发，可由 AI 运行）时，敏感业务数据仅允许按上一条规则取得 3–5 条，凭证类秘密仍不得写入普通产物；
- 禁止新增或实施本方案明确排除的独立深挖交接清单 P1-1；如确有现有字段需要增强，只能按规格写入已有 review queue/ledger。

### 强制执行方式

每一项必须遵循：

```text
读取现状
→ 写出本项目标和验收标准
→ 修改最小必要文件
→ 增加/修改测试
→ 运行本项专属离线测试
→ 检查 diff 和产物
→ 记录结果
→ 只有成功才进入下一项
```

如果本项测试失败：

```text
立即停止进入下一项
→ 定位失败原因
→ 修复当前项
→ 重新运行当前项全部测试
→ 直到成功或明确记录阻塞
```

如果遇到确实无法解决的阻塞，不得跳过并继续声称完成。必须写入：

```text
implementation_blockers.md
```

并说明：

- 阻塞的具体文件和行号；
- 已尝试的修复；
- 失败命令和真实输出摘要；
- 为什么不能继续；
- 需要人工决定的唯一事项；
- 未完成项对后续阶段的影响。

## 四、必须使用任务清单，不得凭对话记忆推进

开始时创建或更新一个持久任务清单。建议分批如下：

```text
Batch 0：上下文加载、规则优先级、当前状态快照
Batch 1：状态模型、run quality gate、coverage 修复
Batch 2：finding quality、漏洞成立门、补天规则和 evidence gate
Batch 3：候选基线、固定路径降噪、canonical 去重
Batch 4：工具 registry、runtime inventory、launcher 和 Python 统一
Batch 5：Web/API application mapping 子阶段
Batch 6：统一注入、parser/XXE/反序列化、SSRF
Batch 7：GraphQL、WebSocket、browser boundary
Batch 8：API 版本、shadow API、资源消耗、第三方 API
Batch 9：业务状态机、重放、重复提交、竞态假设
Batch 10：小程序认证、签名、token 生命周期
Batch 11：小程序本地数据、密码学、包完整性
Batch 12：小程序静态/动态对账、云函数、对象存储、第三方边界
Batch 13：WebView、Bridge、Deep Link
Batch 14：fh/wz/xcx Skill、prompt、phase 和产物同步
Batch 15：历史误报记忆、精度反馈和重跑去重
Batch 16：工具能力补充和离线 SBOM/白盒能力
Batch 17：完整离线验收、文档漂移和最终审计
```

一次会话可以完成多个小项，但不能跨过失败项。每完成一个 Batch，必须先验证 Batch，再进入下一个 Batch。

## 五、每个 Batch 开始前必须汇报

在修改前输出一份简短但具体的实施卡片：

```text
当前 Batch：
当前子项：
本项目的：
本项不做什么：
当前 workflow/phase：
已读取文件：
明确排除的文件：
将修改的文件：
将新增的文件：
本项输入产物：
本项输出产物：
本项验收命令：
本项通过标准：
可能阻塞点：
```

如果无法列出明确的修改文件、输出产物和验收命令，不得开始编码。

## 六、每个 Batch 完成后必须汇报

必须真实填写：

```text
Batch：
状态：PASS / FAIL / BLOCKED
实际修改文件：
实际新增文件：
实际行为变化：
新增或修改的 schema：
新增或修改的测试：
运行的命令：
测试真实结果：
未通过的测试：
未完成的子项：
新增的产物路径：
是否改变默认网络行为：
是否改变速率/并发：
是否改变审批门：
是否有规则冲突：
下一项：
```

只有 `PASS` 才能进入下一项。

## 七、上下文加载硬要求

在每个 Batch 开始前，不得全文读取整个项目。必须：

1. 读取 L0 硬边界和当前 policy snapshot；
2. 只读取当前 Batch 相关的一个 workflow；
3. 只读取当前子项相关的 phase、schema、代码和测试；
4. 历史数据只能通过索引或摘要按需读取；
5. 默认排除：
   - `auth_sessions.local.json`；
   - `sessions.jsonl`；
   - 原始响应全文；
   - 敏感截图原文；
   - 历史报告草稿；
   - `.codex_fh_quality_check/stale_output/`；
6. 写入当前 `context_snapshot`，记录：
   - loaded_sources；
   - source_hashes；
   - current_facts；
   - historical_inputs；
   - excluded_sources；
   - context_conflicts。

若 `context_loader.py` 尚未实现，Batch 0 必须先实现它，后续 Batch 不得继续依赖人工随意读取。

## 八、漏洞判定硬要求

任何 AI 结果必须先区分：

```text
signal
candidate
confirmed
inconclusive
blocked
```

只有满足以下五门才能使用 `confirmed`：

```text
授权门
可触达门
可复现门
安全影响门
证据门
```

AI 不得因为下列现象直接称漏洞：

- Banner 或版本号；
- 200 固定路径；
- 404/403/500；
- 单次超时；
- 登录页；
- 泛化错误堆栈；
- 反射但不可执行；
- 前端隐藏按钮；
- `eval`、模板符号、XML parser、疑似 sink；
- JWT 可解码；
- 过期 key；
- 内网主机名；
- 单一产品指纹；
- 仅存在公开 API 文档；
- 自己能访问自己的对象；
- 没有敏感字段的额外返回；
- 未经人工验证的 AI 结果。

正式 finding 必须写清：

```text
现象
对象层级
授权状态
可触达性
复现状态
实际影响
影响范围
权限需求
证据引用
人工验证状态
是否通用漏洞或事件漏洞
是否与已有 finding 合并
为什么不是低价值现象
```

## 九、补天规则和演练规则必须分开

必须同时维护：

```text
finding_class: generic_vulnerability | event_vulnerability
platform_severity: high | medium | low | not_collectible
exercise_result_class: access | boundary | data | business_impact | signal_only
submission_eligibility: eligible | manual_review_required | deprioritized | ignored | duplicate
```

补天规则重点：

- 高危：服务器权限、命令/代码执行、严重数据泄露、支付逻辑、重大账号接管、关键边界突破；
- 中危：一般 SQL 注入、密码重置、存储型 XSS、任意文件操作、越权、数据库连接密码泄露、非前台高价值弱口令；
- 低危/降级：普通逻辑、Redis 未授权、heapdump 线索、短信轰炸、较难交互问题；
- 默认忽略或降级：URL 跳转、前台个人弱口令、Self-XSS、任意注册、邮箱轰炸、单纯 CORS、无实际危害的安全配置缺陷、公开/脱敏信息、过期 key、拒绝服务；
- 同一系统同类型超过三个必须合并或停止拆分；
- SQL 注入按漏洞接口计算，同一接口多个参数只算一处；
- 同根因通用产品漏洞不能拆成多个事件漏洞刷数量；
- 未经人工验证不得作为正式有效漏洞提交。

演练规则重点：

- 关注权限、网络边界、重要数据和关键业务结果；
- 敏感数据只能证明，不得下载、导出、存储；
- 不得修改、删除或篡改业务数据；
- 新资产必须证明归属并匹配正确靶标；
- 成果必须具备完整截图、录屏、日期时间和攻击链；
- 所有高风险操作仍需审批门。

## 十、工具改造硬要求

不得因为策略文件里写了工具名，就假设工具存在。

必须建立轻量的本地工具登记，适合个人项目使用：

```text
tool_id
display_name
path
version
status
runtime
dependencies
known_limitations
```

`source_url`、`release_date`、`last_verified_date`、`sha256` 等可以作为可选备注，但不能因为缺失这些字段阻塞普通只读流程，也不得为了填写这些字段自动联网查询或下载文件。

工具白名单不登记以下内容：

```text
scope_controls
rate_controls
concurrency_controls
read_only_mode
queue_only_mode
approval_required
evidence_output
auto_update_disabled
```

这些行为由现有流程、`ROE.md`、`policy_engine.py`、`tool_strategy.json` 和阶段代码统一控制，不要创建第二套工具级审批规则。工具 registry 的 `status` 只表示本地路径/版本是否可解析，不表示授权状态。

工具状态只能是：

```text
active
unavailable
hold
retired
```

必须：

- 将不存在的 ffuf、Dalfox、XSStrike、subfinder、dnsx、Semgrep、CodeQL 等明确标记为 `unavailable`，不得写成模糊 `or`；
- ffuf 只用于受控目录候选；
- Dalfox/XSStrike 只能二选一，用于已筛选的单候选 XSS；
- subfinder/dnsx 只用于被动或已知候选模式；
- Semgrep/CodeQL 只用于离线白盒，不联网拉规则；
- Afrog 禁止自动更新 POC；
- Nuclei 固定使用本地模板版本，不自动更新；不要求对每个模板文件做强制哈希；
- 旧式 SpringBoot/Struts/Fastjson/Shiro/WebLogic 等专项工具不得升级为默认主链，继续遵守现有流程的单候选和审批控制；
- 不得自动下载安装任何新工具、模板、规则或依赖。

高风险动作是否需要审批，仍按现有流程策略执行，但不在工具白名单重复登记。高风险工具如实际执行，run 中按现有运行记录记录实际阶段、工具名称和版本即可。

## 十一、代码迁移和兼容要求

项目有根目录兼容模块和 `src/authorized_assessment/` 新包并存的问题。

实施时：

- `src/authorized_assessment/` 逐步成为唯一实现；
- 根目录脚本只保留兼容 shim；
- 不得同时维护两份不同逻辑；
- 先确认当前 canonical 实现，再修改 facade；
- 每次迁移必须增加 import/行为回归测试；
- `.agents/skills/` 是 canonical；
- `.claude/skills/` 和 `.opencode/skills/` 是镜像；
- 修改 canonical 后必须运行 skill drift 检查；
- `AGENT_MANIFEST.md` 必须由生成器更新，不得手改。

## 十二、测试要求

每个新功能至少增加：

1. 一个正常正例；
2. 一个误报负例；
3. 一个输入缺失或阻塞例；
4. 一个非法状态/非法 schema 例；
5. 一个敏感数据过滤例（不得把敏感值写入输出）；
6. 一个重复/幂等例（适用时）。

必须重点测试：

- 通用 200 错误页；
- 登录页；
- WAF/403/429；
- DNS 错误、TLS 错误、timeout；
- coverage 为 0、coverage > 1；
- 全部失败但健康分较高；
- 重复 API 候选；
- 反射但不可执行；
- 只有静态 sink、无可达链路；
- XML 输入但没有实体解析证据；
- SSTI 字符串回显；
- 单次竞态异常；
- 缺少 evidence_ref；
- `not_applicable` 没有 reason；
- 逻辑工具名没有真实 registry 路径；
- 未人工验证的 finding 被错误提交。

每个 Batch 只能运行本项相关测试；每个阶段完成后再运行完整离线测试。

## 十三、完成定义

只有同时满足以下条件，才可以说整体改造完成：

```text
[ ] 所有 Batch 都有 PASS 记录
[ ] 没有未解释的 FAIL 或 BLOCKED
[ ] 所有新增代码不是空壳/TODO/伪实现
[ ] 所有新增 schema 有实际校验入口
[ ] 所有新增 phase 有初始化、审计、产物、策略和测试
[ ] 所有漏洞结论经过成立门
[ ] signal/candidate/confirmed 没有混淆
[ ] 失败 run 不会产生错误阴性结论
[ ] 固定路径和重复 API 候选已降噪/去重
[ ] confirmed finding 都有有效 evidence_ref
[ ] Web、API、小程序 coverage_substatus 可审计
[ ] 工具 registry 与实际可执行性一致
[ ] Afrog/Nuclei 模板不会自更新
[ ] launcher 的 Python 选择一致
[ ] `.agents/.claude/.opencode` 无漂移
[ ] 历史误报和复核结果能回灌
[ ] 报告生命周期可区分 draft/final/delivered/superseded
[ ] 上下文加载是按 task/workflow/phase 的最小加载，而不是每次全文读取
[ ] 全部离线测试和 contract 检查通过
```

## 十四、最终验收命令

只有所有 Batch 都通过后，才能运行完整验收：

```bash
python -m pytest -q
python scripts/verify_offline.py --json
python scripts/maintenance/validate_run_contracts.py
python scripts/maintenance/validate_finding_quality.py
python scripts/check_doc_drift.py
python scripts/check_skill_drift.py
```

如果某个命令不存在，不能静默跳过。必须：

1. 记录为缺失验收入口；
2. 先补充该入口及其测试；
3. 重新运行验收；
4. 在最终报告中明确说明。

## 十五、最终交付格式

最终不要只说“已完成”。必须给出一份真实的实施报告：

```text
1. 总体状态：PASS / PARTIAL / BLOCKED
2. 已完成 Batch 列表
3. 每个 Batch 的修改文件
4. 每个 Batch 的新增产物和 schema
5. 每个 Batch 的验收命令和真实结果
6. 所有失败、阻塞和未实现项
7. 仍为 unavailable/hold/retired 的工具
8. 仍为 not_applicable/blocked/inconclusive 的漏洞分支
9. 是否改变网络请求、速率、并发或审批行为
10. 是否有规则冲突
11. 上下文加载统计和快照路径
12. 文档、Skill、manifest 和 contract 检查结果
13. 下一步只能是明确的未完成项，不得用模糊表述掩盖缺口
```

再次强调：

> **不要急着做下一项。每一项先读取、设计、最小修改、测试、检查 diff、确认 PASS，再进行下一项。任何一项失败都必须停在当前项，修好后才能继续。没有真实测试通过，不得声称完成。**
