# 授权安全评估工作台：覆盖扩展、漏洞成立门与 AI 复核规则实施规格

**文档用途**：本文件不是泛泛的改进建议，而是给后续实现 AI 使用的施工规格。新的 AI 会话应只根据本文件、项目当前文件和 `AGENTS.md/ROE.md` 执行，明确知道：改哪些文件、增加什么目录、每项功能解决什么问题、输入输出是什么、怎样判断完成、怎样避免把细微现象误报成漏洞。

**适用项目**：`D:\PythonSource\PythonProjects\PythonProject4`

**编写日期**：2026-08-29

**本次范围说明**：

- 纳入此前方案中除“深挖交接清单（P1-1）”之外的全部改进项。
- 不把此前列为“不建议作为默认主链”的旧式专项/高风险工具升级为默认主链；它们仍保持现有审批门、单候选、人工确认和 queue-only 约束。
- 本文件重点解决两个问题：
  1. 现有 AI 阶段是否覆盖完整、为什么大多数结果集中在未授权访问和 XSS、怎样补足可执行覆盖；
  2. 怎样让 AI 只有在达到实质影响和证据门槛时才称为“漏洞”，减少细微发现、信息提示和通用异常造成的误报。

---

## 0. 绝对前置约束

任何实现 AI 在修改代码前必须先阅读：

```text
AGENTS.md
ROE.md
.agents/skills/authorized-pentest-workflow/references/authorization-boundaries.md
```

所有新增阶段都必须继承以下项目约束：

- 只在已授权目标、已确认时间窗口内工作；
- 默认低速、只读、最小请求、低并发；
- 新资产、第三方资产、供应链路径、核心系统和高风险验证需要单独确认；
- 禁止 DDoS/CC、社会工程、近源、无线/物理攻击、DNS 劫持、ARP/DHCP 欺骗、破坏性操作、数据篡改、密码修改、WebShell/C2/隧道/持久化和数据导出；
- 敏感数据默认以最小化、脱敏、哈希或字段级证明保留；仅当漏洞证明例外成立（ROE §3.3）时可取得并允许保留 3–5 条最小必要未脱敏代表性数据，取得的样本以原始结构与值形态供报告取证（若仅脱敏/占位无法区分主动脱敏与目标防护掩码），其余仍禁止下载、导出、保存原文；
- 工具能力存在不代表获得使用授权；
- 指纹、Banner、状态码、错误信息和单一规则命中只能形成 `signal` 或 `candidate`，不能自动形成 `confirmed`；
- 如果探测失败、被 WAF/限速拦截、没有有效响应或覆盖率不足，必须标记 `inconclusive`，不得输出“未发现漏洞”。

---

# 1. 现状结论：当前阶段不是“完整执行覆盖”

## 1.1 三类流程的结构覆盖情况

### fh/postrun 复核流程

`fh` 的覆盖对象很广，能够读取固定路径、API、认证态、SQLi、XSS、Shiro、产品专项、小程序候选、证据和报告产物。但是它当前更像“已有结果的候选处置流程”，不是一个完整的主动测试框架。

主要问题：

- 复核输入很多，但不同候选族的成立条件不统一；
- 复核完成不一定代表所有候选来源都被映射；
- `review_aggregated` 不能仅由“没有 pending”推导；
- 失败 run 和低覆盖率 run 仍可能被看成“无漏洞”；
- fh 到 wz/xcx 的跳转依赖 Markdown 或 AI 自行判断，缺少本次不新增的机器交接清单，因此本方案只要求在现有复核记录中增加明确的 `recommended_workflow/recommended_phase` 字段，不新增独立 handoff 文件。

### wz 单站流程

当前 19 个顶级阶段在生命周期上是合理的：

```text
authorization
scope
preflight
passive_discovery
active_discovery
application_mapping
unauthenticated_testing
authenticated_testing
api_testing
authorization_testing
input_testing
business_logic_testing
client_side_testing
infrastructure_testing
candidate_validation
evidence
cleanup
retest
reporting
```

但这些阶段中有大量内容只写在测试矩阵或 playbook 中，没有对应：

- 独立的子阶段状态；
- 机器可读的 `tested/blocked/not_applicable/inconclusive`；
- 稳定产物；
- 工具策略；
- 覆盖率统计；
- 与候选、证据和复核台账的对应关系。

因此当前真实状态是：**文档覆盖面较广，执行覆盖面和可证明覆盖面不足**。

### xcx 小程序流程

当前 27 个阶段在材料、解包、源码重建、动态流量、认证、后端 API、访问控制、文件、业务逻辑、存储、密码学、WebView、云能力和第三方边界方面比普通 Web 流程更完整。

主要问题是阶段过度聚合：

- `authentication_session` 同时承担平台登录交换、token 生命周期和签名重放；
- `client_storage_crypto` 同时承担本地存储、日志、剪贴板、敏感数据和密码学；
- `plugins_cloud_third_party` 同时承担云函数、对象存储、云数据库和第三方服务；
- `static_analysis` 没有明确对账静态端点和动态端点；
- 包完整性、更新信任、版本漂移和调试配置没有独立状态。

因此 `phase complete` 不能证明小程序的每个安全分支都测试过。

## 1.2 为什么历史上主要挖到未授权访问和 XSS

根据历史 `runs/` 分析，44 个可汇总 run 的加权误报率约为 **95.36%**，API 候选确认率约为 **1.49%**。这不是因为 SQLi、SSRF、模板注入、XXE 等漏洞不存在，而是因为当前系统存在以下结构性原因：

1. 自动化入口重点集中在可低成本执行的 IDOR/访问差分和反射型 XSS；
2. 许多其他漏洞只在 Markdown 测试矩阵中出现，没有独立 phase 和产物；
3. 输入点、XML/文件解析点、URL 回调点、GraphQL、WebSocket、云函数和版本 API 没有被稳定地建模；
4. AI 容易把“看起来有风险”当作“漏洞”，导致高噪音，复核队列被大量固定路径、统一 200 页面和 API 猜测候选占满；
5. SQLi、SSTI、XXE、反序列化等需要明确前置技术条件和最小验证，不应对所有参数盲目尝试；
6. 业务逻辑、竞态、资源消耗和认证生命周期需要状态机、账户、对象、租户和版本维度，不能仅靠单个 GET 请求；
7. 工具策略中有逻辑名称但本地没有可执行副本，某些阶段实际没有运行任何工具，却可能被看成已覆盖。

因此改进目标不是“对所有目标增加更多 payload”，而是：**先建立攻击面适用性，再按低风险候选、证据门和人工审批门推进。**

---

# 2. 漏洞成立总规则：AI 不得把细微发现直接称为漏洞

## 2.1 三种对象必须严格区分

### A. 现象/信号 `signal`

仅表示发现了值得记录的现象，不表示存在漏洞。

典型例子：

- Server Banner 暴露版本；
- 某固定路径返回 200；
- 响应中出现 `debug`、`admin`、`swagger` 等关键词；
- 某参数原样反射；
- 发现一个 API 路径；
- 发现旧版本接口；
- 发现一个可能的 XML、URL、文件或模板输入点；
- 某组件名称与漏洞库产品名称相似；
- 某次请求返回 403、500、302 或超时；
- 前端代码存在疑似危险 sink，但尚无外部可达数据流证明。

`signal` 只能进入低优先级线索库，不得进入最终漏洞报告。

### B. 候选 `candidate`

满足“有一定可复现性和技术关联”，但还没有证明企业实质影响。

候选必须记录：

- 资产和授权范围；
- 输入点/端点/功能；
- 触发条件；
- 基线和差异；
- 影响假设；
- 当前阻塞点；
- 所需人工动作；
- 证据路径；
- `confidence`；
- `next_action`。

候选可以进入人工复核队列，但不得写成“已存在漏洞”。

### C. 已确认漏洞 `confirmed`

只有同时满足下列五类门槛才允许使用：

```text
授权门 + 可触达门 + 可复现门 + 安全影响门 + 证据门
```

缺一项都只能是 `candidate`、`needs_manual_validation`、`blocked` 或 `inconclusive`。

## 2.2 五类成立门

### 1. 授权门

必须能证明：

- 目标属于当前 engagement 或已批准 target；
- 资产归属和 scope state 已确认；
- 使用的凭证、账户、代理、VPS 或 OOB 资源符合当前授权；
- 如属于写操作、弱口令、SQLMap、上传、命令执行、竞态或高风险 POC，存在审批记录。

没有授权证明不能称漏洞，即使技术现象真实，也只能记录 `blocked_authorization`。

### 2. 可触达门

必须证明外部攻击者或当前授权低权限角色可以到达相关功能：

- URL、接口、页面、消息、文件、GraphQL operation、WebSocket channel 或小程序后端端点真实存在；
- 不是纯前端死代码、未部署文件、示例代码、注释或不可达分支；
- 不是仅由内部管理员、内部网络、特殊调试开关或未授权资源才能触达；
- 如果只有静态代码证据而没有可触达链路，状态最多为 `whitebox_candidate`。

### 3. 可复现门

至少满足：

- 正常基线请求和异常请求均已记录；
- 触发方式在低请求预算内可重复；
- 结果不是一次性网络波动、缓存偶然命中或 WAF 错误页；
- 已记录时间、目标、端点、方法、必要参数、响应摘要和判据；
- 能由另一名复核人员按最小步骤重现。

### 4. 安全影响门

漏洞必须对企业造成可说明、非琐碎的安全影响。影响至少落入下列一项：

- 未授权读取、修改或删除其他用户、租户、部门或业务对象；
- 获取普通用户之外的管理、运维、数据库、服务器、云平台、网络设备或关键应用权限；
- 突破认证、会话、租户或功能边界；
- 泄露敏感个人信息、业务生产数据、运行管理数据、源代码、密钥、令牌、网络拓扑、远程接入凭证或其他重要数据；
- 可稳定执行服务端命令、模板/表达式/代码、SQL/NoSQL 操作或取得等价高危能力；
- 能进入新的网络区域、逻辑隔离区、运维区、核心生产区或跨边界访问内部资源；
- 能影响支付、订单、库存、审批、积分、优惠、退款、身份绑定等关键业务状态；
- 能造成批量资源消耗、批量数据暴露、关键服务不可用或高概率业务中断；
- 能形成清晰、可审计的攻击链，最终达到上述高影响结果。

以下通常不足以单独构成漏洞：

- 单一 Banner/版本信息；
- 没有敏感内容的目录列表；
- 404/403/500 页面；
- 单个无敏感字段的异常堆栈；
- 自己的输入在页面中原样出现但无法执行、无法跨用户或无法产生安全后果；
- 公开文档、robots、sitemap 或 API 路径本身；
- 前端隐藏按钮；
- 只说明“可能存在”的产品漏洞指纹；
- 仅能在本地源码中看到 sink，但没有外部可达和影响证据；
- 只能证明服务端使用了某个组件，但没有证明版本、配置和漏洞触发条件。

### 5. 证据门

确认漏洞至少需要：

```text
finding_id
source_run
engagement_id
target
asset_identity
vulnerability_family
precondition
minimal_reproduction
observed_result
impact_statement
evidence_ref
validation_result
reviewer
reviewed_at
```

敏感数据证明规则（方案 A）：

- 默认不自动下载、导出或留存敏感数据；
- 仅当漏洞已满足授权、可触达、可复现和实质影响条件，且操作者在线明确触发/控制时，允许通过**只读、服务端限定数量/字段的请求**取得 **3–5 条最小必要的未脱敏代表性数据**，用于证明未授权访问、SQL 注入、信息泄露等漏洞确实影响真实数据；
- 请求本身必须限制在单对象、明确字段、明确 `page size/limit=3–5` 等最小范围；如果服务端不支持限制、响应包含全集、数量超过 5 条或只能先下载再本地筛选，必须停止并标记 `sample_bound_unavailable`，不得继续读取；
- 取得 3–5 条后立即停止，不得继续分页、遍历、dump 或扩大样本；
- 无人值守 AI 不得自动取得该样本，只能生成操作者人工复现待办；
- 截图、录屏和最终证据由操作者自行完成，AI 不自动截图、生成截图队列或审计操作者截图；
- 公共、非敏感、授权范围内的 JS/CSS/Source Map、公开配置和公开文档可按低速只读 GET 获取，用于前端/API 分析；其中出现的凭证、token、AppSecret、密码或敏感数据仍不得写入普通日志、报告、prompt、ledger 或交接材料；
- 任何需要全量查询、批量分页、数据库 dump、heapdump 下载、完整敏感文件下载、完整 HAR 导出、批量用户/租户遍历或自动循环取样的动作，均不属于该例外，必须停止并由操作者按现有规则另行决定。

## 2.3 严重性分层规则

新增 AI 规则必须采用“影响优先、可利用性次之、现象最后”的顺序。

```text
P0 / Critical：
- 直接取得服务器、域控、数据库、云管理、网络设备、核心系统或等价控制权；
- 认证绕过后可访问关键系统；
- 稳定 RCE/代码执行/高权限命令执行；
- 进入核心生产网或获取大规模重要数据；
- 可造成重大业务中断或跨单位/跨网络区域影响。

P1 / High：
- 跨用户/跨租户 BOLA、BFLA、字段级授权绕过；
- 管理功能越权；
- 敏感数据批量读取；
- 高影响 SSRF 可访问内部管理面或云元数据；
- 稳定 SQL/NoSQL/模板/表达式/XXE/反序列化等高危注入；
- 关键业务流程绕过、重复支付/退款/领取、库存或审批状态破坏；
- 高价值凭证、密钥、源代码或远程接入信息泄露。

P2 / Medium：
- 单对象越权但影响范围有限；
- 受限的敏感字段过度暴露；
- 需要特定账户、特定业务状态或较严格条件的可复现安全问题；
- 中等影响的文件读取、下载越权、开放重定向与 CSRF 组合；
- 可证明但范围有限的资源控制缺失。

P3 / Low / Signal：
- 纯信息提示、Banner、无敏感数据的调试信息；
- 无法证明影响或只能推测的漏洞；
- 无法复现、只有一次异常响应；
- 仅客户端可控且服务器端有正确校验；
- 仅理论 sink 或产品指纹。
```

**注意**：P3 不得自动进入“漏洞数量”或正式报告，只能进入改进建议/线索附件。

## 2.4 结果导向规则

本地《攻击方评分规则.docx》明确：

- 评分重点是获取权限、突破网络边界、获取重要数据和高影响结果；
- 获取权限后即可得分，但禁止修改、删除或篡改业务数据；
- 敏感数据证明按方案 A：仅在已确认漏洞且操作者明确触发时取得 3–5 条最小必要未脱敏代表性数据，取得后立即停止，不进行全量导出、批量分页或 dump；
- 截图和录屏由操作者自行完成，AI 不自动生成、整理或审计截图；
- 新发现资产必须证明归属并申请对应靶标；
- 同一系统同类漏洞按首队提交；
- 成果必须有完整截图、详情、录屏和当前系统日期时间；
- 零日/N-day 评分考虑影响范围、网络位置、权限、触发条件、稳定性、利用难度；
- 多个漏洞组合形成最终结果时，评分可以按攻击链结果判定，而不是机械按单一漏洞名称。

因此 AI 的漏洞规则必须从“有没有异常”改为：

```text
是否可触达 → 是否越过边界 → 是否产生非琐碎影响 → 是否稳定复现 → 是否有完整证据
```

## 2.5 补天收录口径：通用漏洞与事件漏洞

操作者补充的补天规则必须作为 AI 的“收录/降级参考层”，但不能替代项目授权规则、演练规则或安全影响门。

### 通用漏洞 `generic_vulnerability`

指第三方软件、应用、系统、开源/闭源产品、开发框架、浏览器、移动应用、路由器、VPN、防火墙等本身存在、可影响多个部署实例的漏洞，例如：

- ECShop、Discuz、PHPCMS 等通用产品的 SQL 注入/XSS；
- 开源系统、CMS、开发框架、中间件或安全设备的已知漏洞；
- 同一产品版本、同一缺陷根因、可在多个实例复现的漏洞。

通用漏洞必须同时记录：

```text
product_or_component
product_version_or_build
vulnerability_family
affected_condition
vendor_or_upstream_reference
affected_instance_count
reproduction_stability
whether_public_or_0day
```

不能因为同一产品在多个企业上出现，就把每个企业实例都当作不同原创漏洞。相同根因应合并为一个通用漏洞，实例只作为受影响资产列表。

### 事件漏洞 `event_vulnerability`

指某个具体网站、应用、接口、租户或业务流程的非通用缺陷，例如：

- 某网站命令执行；
- 某电商订单金额、充值或支付逻辑可被异常修改；
- 某业务接口越权泄露其他用户对象；
- 某具体应用的 SQL 注入导致数据库信息或敏感数据暴露；
- 某单位后台密码重置流程可造成管理员接管。

事件漏洞必须记录具体目标、具体接口/功能、具体前置条件和具体影响，不能只引用产品名称或公开 CVE。

### 漏洞家族基线

默认关注以下家族；如果新增家族满足安全影响门，应补充到 `vulnerability_taxonomy.json`，但不能仅因为存在技术名词就自动报漏洞：

```text
xss
sql_injection
command_execution
code_execution
file_inclusion
arbitrary_file_operation
authorization_bypass
business_logic
information_disclosure
backdoor
ssrf
ssti
template_injection
xxe
parser_deserialization
nosql_injection
ldap_injection
xpath_injection
path_traversal
file_upload_download
csrf
cors_cache_boundary
api_asset_inventory
resource_consumption
websocket_graphql
credential_secret_exposure
```

`backdoor` 只允许在有确凿的后门文件、功能、创建/访问时间、调用记录或控制链证据时使用；可疑文件名、未知脚本或单一字符串不能直接定性为后门。

## 2.6 补天三档危险等级与 AI 判定映射

补天规则将漏洞分为高危、中危、低危，并根据可利用性、影响、攻击复杂度、权限需求、影响范围、机密性和完整性调整。项目内部保留 `P0/P1/P2/P3`，但新增 `platform_severity` 字段映射补天口径：

```text
P0/P1 → platform_severity: high
P2     → platform_severity: medium
P3     → platform_severity: low_or_signal
```

### 高危 `high`

只有在满足漏洞成立五门且至少达到以下一项时，AI 才能建议高危：

1. 直接获得服务器权限，包括任意命令执行、WebShell、任意代码执行；
2. 直接造成严重信息泄露，包括大量个人敏感信息或重要业务数据；
3. 支付/充值/订单等逻辑漏洞影响企业盈利或资金结果；
4. SQL 注入、认证绕过或其他漏洞可直接盗取大量用户身份信息、执行命令或取得高价值权限；
5. 管理员密码重置、账号接管或等价逻辑漏洞导致大量敏感信息泄露；
6. 通过漏洞突破网络边界，进入运维区、核心生产区或取得关键系统控制权；
7. 稳定的组合攻击链达到上述结果。

“可能 RCE”“可能泄露数据库”“看起来可以重置密码”均不能进入高危，必须提供最小、可重复、授权范围内的结果证据。

### 中危 `medium`

可以在满足成立五门且达到以下一项时建议中危：

1. SQL 注入等漏洞已证明可以获得数据库名、用户名或等价数据库信息，但未证明高影响数据/命令执行；
2. 管理员或普通用户密码重置，但影响范围不足以导致大规模敏感信息泄露；
3. 需要用户交互才能利用的存储型 XSS，且能影响其他用户或敏感业务上下文；
4. 任意文件读、写、删、下载或其他任意文件操作，影响明确但尚未达到服务器控制/重大数据影响；
5. 越过认证、角色、对象、租户或功能限制，能够修改资料或代替用户执行业务操作；
6. 泄露数据库连接密码、有效密钥、远程接入信息等相对严重敏感信息；
7. 弱口令导致后台、运维、数据库、服务器或其他非前台高价值系统权限，但必须有口令来源和有效性证据。

前台普通账号弱口令、公共自主注册账号、无法证明口令来源的口令，不得按中危漏洞提交。

### 低危 `low_or_signal`

以下通常只允许记为低危候选、线索或整改建议，不能自动进入有效漏洞数量：

- 普通业务逻辑缺陷；
- Redis 未授权但未证明敏感数据、权限扩大或实际影响；
- heapdump 敏感信息线索但未证明内容有效、未过期且可利用；
- 短信轰炸/资源控制问题，仅在可重复且影响明确时进入低危候选；
- 需要交互且利用难度较高、影响有限的用户身份信息风险。

低危不是“任意异常都能收录”。如果没有实际危害、无法直接利用或只能推测，状态应为 `signal` 或 `rejected`。

## 2.7 补天降级/忽略规则转为 AI 抑制规则

下列情形默认不进入有效漏洞主队列，除非能证明更高影响：

1. URL 跳转、前台个人弱口令、任意用户注册、Self-XSS、邮箱轰炸；
2. 只有 CORS 配置错误、通用 Web 安全配置缺陷或安全加固缺失，没有跨站读取、越权或敏感影响；
3. 内网主机名、IP、路径、Banner、已过期 key、无效 token 等无法直接利用的信息；
4. 脱敏信息、公开文件、无有效信息的 API 接口泄露；
5. 任何需要破坏业务、拒绝服务或数据篡改才能证明的结果；
6. 同一系统同一漏洞类型超过三个的重复结果；
7. SQL 注入按“漏洞接口”合并，同一接口多个参数只计一处；
8. 通用产品同一根因在多个企业重复出现，应合并到通用漏洞，不刷事件漏洞；
9. 未经人工验证的 AI 生成候选，不得进入正式漏洞提交；
10. 网站已停止维护、个人小站、无人维护的低影响建站模板，应标记 `low_value_or_deprioritized`，不得为了数量拆分提交。

### 合并键和限量规则

新增的合并器必须使用：

```text
canonical_target
product_or_component
normalized_endpoint
http_method
vulnerability_family
root_cause_signature
parameter_scope
```

合并规则：

- 同一接口多个参数的 SQL 注入合并为一个 finding；
- 同一路径不同目录、同一参数在相似文件中重复出现，按根因和影响合并；
- 同一系统同类型超过三条时，后续只保留代表性证据和合并引用；
- 同一通用产品缺陷在多个企业实例中出现，生成一个 generic finding，并挂接实例清单；
- 不得因为不同 URL、不同参数名或不同页面标题就人为制造多个漏洞。

## 2.8 演练评分规则与补天收录规则的边界

AI 必须同时维护两个字段，不得混为一谈：

```text
exercise_result_class
platform_submission_class
```

### 演练结果导向

本地《攻击方评分规则.docx》更强调：

- 获取权限；
- 突破网络边界；
- 获取重要数据；
- 获取目标系统之外的业务系统权限；
- 完整的攻击链和可验证成果；
- 当前系统日期时间、截图和全程录屏；
- 新资产归属证明和正确靶标匹配。

敏感数据只按方案 A 取得最小证明样本：已确认漏洞且操作者明确触发时最多 3–5 条，取得后立即停止；禁止全量导出、批量分页、dump、下载或存储超出证明所需范围的数据。拿到权限后禁止修改、删除或篡改业务数据。

### 补天平台收录结果导向

补天规则更强调：

- 漏洞家族和通用/事件分类；
- 可利用性和实际影响；
- 高/中/低危险等级；
- 同系统、同接口、同根因合并；
- 低危、重复、无危害、无效信息和未经人工验证的 AI 结果降级或忽略；
- SQL 注入按接口计算；
- 高危重点是服务器权限、严重数据泄露、支付逻辑、账号接管和重大业务影响。

两套规则共同要求：**不能只凭微小现象声称漏洞，必须有人工验证、可复现链条和实质影响。**

## 2.9 AI 正式结论格式

所有 AI finding 必须增加以下字段：

```text
finding_class: generic_vulnerability|event_vulnerability
platform_severity: high|medium|low|not_collectible
exercise_result_class: access|boundary|data|business_impact|signal_only
submission_eligibility: eligible|manual_review_required|deprioritized|ignored|duplicate
manual_validation_status: not_started|in_progress|verified|rejected
impact_scope: single_object|single_user|tenant|organization|multiple_organizations|critical_network
root_cause_signature
merge_group_id
reason_not_a_vulnerability
```

AI 的最终输出必须采用以下顺序：

```text
1. 现象是什么
2. 属于 signal/candidate/confirmed 哪一层
3. 是 generic 还是 event
4. 哪一项漏洞成立门已满足，哪一项未满足
5. 是否有企业实质影响
6. 影响范围和权限要求
7. 补天危险等级建议及理由
8. 演练结果类别及理由
9. 是否需要人工验证
10. 为什么不是另外一个候选/为什么与已有 finding 合并
11. 最小证据引用
```

如果第 4、5 或 11 项无法完成，AI 不得使用“确认漏洞”“高危漏洞”“有效漏洞”等措辞，只能写“候选/线索/待人工验证”。

---


## 3.1 新增目录和文件

```text
src/authorized_assessment/quality/
  __init__.py
  run_quality_gate.py
  finding_quality_gate.py
  coverage_quality.py

src/authorized_assessment/triage/
  response_baseline.py
  candidate_dedup.py
  canonical_keys.py
  injection_candidates.py
  parser_deserialization.py
  graphql_inventory.py
  graphql_review.py
  websocket_inventory.py
  websocket_review.py
  browser_boundary.py
  api_resource_controls.py
  third_party_api_review.py

src/authorized_assessment/analysis/
  api_inventory_reconcile.py
  coverage_matrix.py
  review_feedback_ingest.py
  precision_model.py

src/authorized_assessment/reporting/
  evidence_gate.py
  report_lifecycle.py

contracts/
  run_quality_schema.json
  finding_evidence_schema.json
  candidate_identity_schema.json
  injection_candidate_schema.json
  test_dimensions_schema.json
  tool_capability_schema.json
  coverage_substatus_schema.json

knowledge_base/
  false_positive_patterns.jsonl
  fingerprint_precision.jsonl
  endpoint_behavior_profiles.jsonl
  review_feedback_schema.json

tools/
  tool_registry.json
  README_tool_registry.md

scripts/maintenance/
  rebuild_tool_inventory.py
  rebuild_review_memory.py
  validate_run_contracts.py
  validate_finding_quality.py
```

## 3.2 运行质量状态

`src/authorized_assessment/quality/run_quality_gate.py` 必须输出：

```json
{
  "quality_status": "VALID|PARTIAL|INCONCLUSIVE|FAILED|BLOCKED",
  "negative_conclusion_allowed": false,
  "unique_in_scope_targets": 10,
  "unique_targets_with_successful_probe": 4,
  "probe_coverage": 0.4,
  "probe_ok_ratio": 0.4,
  "transport_errors": 3,
  "dns_errors": 0,
  "timeouts": 1,
  "waf_blocks": 2,
  "rate_limit_skips": 3,
  "quality_gate_reasons": [
    "probe_coverage_below_threshold",
    "rate_limit_skip_ratio_high"
  ]
}
```

### 强制门控

以下任一条件成立，状态不得为 `VALID`，且禁止“未发现漏洞”结论：

```text
probe_coverage < 0.90
probe_ok_ratio < 0.50
rate_limit_skips / unique_in_scope_targets > 0.20
transport_error_ratio > 0.30
所有目标都没有成功响应
WAF/block 比例超过配置阈值
```

覆盖率必须：

- 只以唯一 in-scope target 为分母；
- 分子为至少一次成功完成有效探测的唯一 target；
- 强制限制在 `[0, 1]`；
- 不允许出现 `2.0` 这类重复计数结果。

### 修改文件

```text
src/authorized_assessment/reporting/run_health.py
run_health.py
run_lifecycle.py
contracts/workflow_schema.json
```

`run_lifecycle.py` 必须补：

```python
from pathlib import Path
```

并且 `review_aggregated` 必须验证：

- batch verdict 已聚合；
- 所有候选来源均已映射；
- ledger 与队列计数一致；
- 没有未处置 pending；
- blocked/needs_login/approval_required 已明确计数；
- confirmed/accepted_risk 有有效证据；
- 当前 run 质量门允许形成结论。

报告生命周期统一为：

```text
report_generated
report_reviewed
report_accepted
report_delivered
report_superseded
```

不再把孤立的 `accepted_report` 作为完整闭环。

---

# 3. 上下文加载和记忆保持规则：禁止每次全文读取项目

这是本项目必须新增的基础能力。当前没有统一的 `context_loader` 来约束 AI 每次只读取相关文件，因此不同 AI/Skill 可能出现两种不一致行为：

- 只读当前阶段，导致遗漏硬边界或共享契约；
- 把全部 Skill、prompt、配置、历史 run 和实施规格全文读入上下文，导致规则稀释、阶段混淆和当前事实被历史产物淹没。

**目标不是减少规则，而是分层加载规则。**完整规则继续保存在磁盘；AI 每次只加载当前任务需要的摘要和相关原文。

## 3.1 当前真实情况

当前项目已经有按需读取的意图：

- `AGENTS.md` 要求 references 按需加载；
- 授权安全 Skill 要求先读授权边界；
- `wz`、`xcx`、`fh` 分别维护自己的流程规则；
- `runs/` 和 `engagements/` 作为事实源。

但目前仍缺少以下机器可执行约束：

- 没有统一的任务类型 → 文件映射表；
- 没有统一的 workflow/phase 上下文加载器；
- 没有加载来源 hash 和上下文快照；
- 没有明确区分当前事实、历史事实、派生模式和过期参考；
- 没有阻止 AI 把全量历史 run、报告草稿、原始响应和凭证材料作为当前事实；
- 没有统一检测规则冲突和版本漂移的入口。

因此后续实现必须把“上下文治理”作为代码和契约，而不是只写在 prompt 里。

## 3.2 规则优先级

新增 `docs/RULE_PRECEDENCE.md`，并在所有 workflow Skill 和 prompt 中引用同一优先级：

```text
1. 系统/开发者指令
2. AGENTS.md
3. ROE.md 与当前授权证据
4. 当前 engagement scope、approval 和 stop 状态
5. 当前 workflow Skill（fh/wz/xcx 等）
6. 当前 phase contract/schema
7. gov_exercise_config.json
8. tool_strategy.json 与 tool registry
9. prompts 和实施规格
10. 当前 run 的历史派生结果与 knowledge_base
11. 外部方法学资料
```

规则冲突处理：

- 高层规则覆盖低层规则；
- 历史 run、知识库和外部资料不能覆盖当前授权、scope、审批和停止条件；
- 冲突不得由 AI 静默选择，必须写入 `context_conflicts`；
- 当前 scope 不明确时只能进入 `confirmation_required` 或 `blocked`，不能继续主动测试。

## 3.3 上下文分层

### L0：始终加载的最小硬边界

每个安全相关任务只加载一份短摘要和当前状态：

```text
AGENTS.md 的项目边界摘要
ROE.md 的授权、速率、禁止动作、审批门和敏感数据摘要
当前 engagement.json
当前 scope.csv/hosts.csv 摘要
当前 phase_status.json
runtime/policy_snapshot.json（新增）
```

L0 必须包含：

- 当前目标和 scope；
- 授权状态和有效时间窗口；
- 允许动作、禁止动作、审批动作；
- 同 host 延迟、host 并发、跨 host worker 上限；
- 敏感数据处理限制；
- 停止条件；
- 当前 workflow、phase 和 terminal 状态。

只有在摘要缺字段、hash 过期、规则冲突或要执行审批动作时，才回读对应原文。

### L1：当前 workflow

每次只加载一个主流程：

```text
fh 或 wz 或 xcx 或 logic-workshop 或 planning-session 或 whitebox-review
```

例如：

- 复核 run 只加载 `fh`；
- 推进单站只加载 `wz`；
- 小程序只加载 `xcx`；
- 逻辑分析只加载 `logic-workshop`。

不能因为项目同时存在 Web 和小程序规则，就默认同时加载两个完整 Skill。只有发生明确的 Web ↔ 小程序资产回流时，才加载另一流程的相关章节。

### L2：当前 phase 和输入

只加载：

```text
当前 phase 规则
当前 phase 的 schema/contract
当前 phase 的 tool_strategy 条目
当前 phase 的输入产物
当前 phase 的测试文件
相关历史误报/精度模式
```

例如 `wz → api_testing → authorization_testing` 不得默认加载：

- 小程序本地存储和 WebView 规则；
- SQLMap、弱口令和高风险 POC 的完整说明；
- 全量历史 run；
- 报告模板全文。

### L3：按需原文和参考资料

仅在以下情况加载原文：

- 当前任务涉及相应漏洞族；
- L0/L1/L2 出现规则冲突；
- 需要新增/修改共享契约；
- 需要审批门判断；
- 需要核对权威资料中的具体判定。

外部 OWASP、CWE、微信和平台规则只作为方法和收录参考，不能覆盖项目授权和安全边界。

## 3.4 新增文件

```text
runtime/policy_snapshot.json
docs/CONTEXT_LOADING_MAP.yaml
docs/RULE_PRECEDENCE.md
docs/implementation_specs/00_READ_FIRST.md
src/authorized_assessment/runtime/context_loader.py
src/authorized_assessment/runtime/context_snapshot.py
contracts/context_snapshot_schema.json
tests/test_context_loader.py
tests/test_rule_precedence.py
tests/test_context_snapshot.py
```

如果项目已有 `runtime/` 目录，应将 `policy_snapshot.json` 放在当前项目约定的 runtime 状态目录，并在 `project_paths.py` 中提供唯一解析函数；不要创建第二套互相独立的运行时路径。

## 3.5 `CONTEXT_LOADING_MAP.yaml` 内容

该文件是机器可读的加载白名单，不是建议文档。至少包含：

```yaml
global:
  always:
    - AGENTS.md#项目定位与安全边界
    - ROE.md#授权范围
    - runtime/policy_snapshot.json
  on_conflict:
    - ROE.md
    - current_engagement_scope
    - current_workflow_skill
    - current_phase_contract

workflows:
  fh:
    - .agents/skills/fh/SKILL.md
    - .agents/skills/fh/references/output-map.md
    - .agents/skills/fh/references/review-playbook.md
  wz:
    - .agents/skills/wz/SKILL.md
    - .agents/skills/wz/references/workflow.md
    - .agents/skills/wz/references/test-matrix.md
  xcx:
    - .agents/skills/xcx/SKILL.md
    - .agents/skills/xcx/references/workflow.md
    - .agents/skills/xcx/references/test-matrix.md

phases:
  graphql:
    - tool_strategy.json#graphql
    - contracts/graphql_schema.json
    - src/authorized_assessment/triage/graphql_inventory.py
    - src/authorized_assessment/triage/graphql_review.py
  injection:
    - contracts/injection_candidate_schema.json
    - docs/implementation_specs/02_finding_definition_and_severity.md
  miniapp_auth:
    - .agents/skills/xcx/references/package-analysis.md
    - contracts/miniapp_auth_schema.json

historical_data:
  only_when:
    - review
    - planning
    - precision_analysis
  never_load_as_current_fact:
    - runs/*/reports/*draft*
    - .codex_fh_quality_check/stale_output/*
    - runs/*/auth_sessions.local.json
    - runs/*/sessions.jsonl
```

实际实现时，映射中的不存在路径不能被静默忽略：如果该路径是当前 phase 的必需输入，应返回 `missing_required_source`；如果是可选工具，应返回 `unavailable` 并继续使用明确的 fallback。

## 3.6 `context_loader.py` 行为

`src/authorized_assessment/runtime/context_loader.py` 必须提供类似接口：

```python
load_context(
    *,
    task_type: str,
    workflow: str | None,
    phase: str | None,
    engagement_dir: Path | None,
    run_dir: Path | None,
    include_history: bool = False,
) -> ContextBundle
```

必须实现：

1. 先加载 L0，再加载一个 L1，再加载 L2；
2. 根据 `CONTEXT_LOADING_MAP.yaml` 只返回白名单文件；
3. 对每个来源记录路径、用途、sha256、读取时间和是否必需；
4. 默认不读取凭证、原始响应、完整截图和敏感数据原文；
5. 历史数据只有在 `review/planning/precision_analysis` 中显式开启时才按索引查询；
6. 把历史输入标记为 `historical_fact`、`derived_pattern` 或 `stale_reference`，不得标为当前事实；
7. 发现规则冲突时返回 `context_conflicts` 并停止需要主动动作的任务；
8. 发现 L0 缺失时 fail-closed；
9. 对当前 phase 不相关的文件不加载，即使它们存在；
10. 输出上下文大小和被排除文件计数，便于后续分析记忆压力。

## 3.7 `policy_snapshot.json`

建议由初始化器/运行器生成，而不是手工长期维护：

```json
{
  "schema_version": "1.0",
  "engagement_id": "...",
  "workflow": "wz",
  "phase": "api_testing",
  "authorization_status": "confirmed",
  "active_testing_authorized": false,
  "allowed_actions": ["offline_analysis", "readonly_get"],
  "blocked_actions": ["password_spray", "bruteforce", "webshell", "c2", "tunnel", "data_export", "destructive_write", "ddos"],
  "approval_required": ["credential_testing", "sqlmap", "upload", "command_execution", "race_write", "oob_callback"],
  "rate_policy": {
    "same_host_delay_seconds": 3,
    "same_host_concurrency": 1,
    "cross_host_worker_limit": 3
  },
  "stop_conditions": ["out_of_scope_asset", "service_degradation", "waf_alarm", "window_closed"],
  "source_hashes": {},
  "generated_at": "..."
}
```

凭证值、Cookie、Token、Authorization、session_key、AppSecret 不得写入 snapshot；只允许保存字段是否存在、不可逆引用或哈希。

## 3.8 `context_snapshot.py` 和新会话恢复

每次执行前生成：

```text
runs/<run>/context_snapshot.json
```

或在长期单目标流程中生成：

```text
engagements/<name>/notes/context_snapshot.md
```

至少记录：

```json
{
  "task_type": "review",
  "workflow": "fh",
  "phase": "authorization_testing",
  "engagement_id": "...",
  "loaded_sources": [],
  "source_hashes": {},
  "policy_digest": {},
  "current_facts": [],
  "historical_inputs": [],
  "excluded_sources": [],
  "context_conflicts": [],
  "created_at": "..."
}
```

`current_facts` 只能来自当前 run/engagement；历史统计和知识库必须放到 `historical_inputs`，不能混入当前事实列表。

## 3.9 长实施规格的拆分

当前本文件约两千多行，作为总规格保存即可，但不应要求每次请求全文读取。实现阶段应拆出：

```text
docs/implementation_specs/
  00_READ_FIRST.md
  01_quality_and_state.md
  02_finding_definition_and_severity.md
  03_web_api_phases.md
  04_miniapp_phases.md
  05_tool_registry_and_runtime.md
  06_history_noise_and_feedback.md
  07_tests_and_acceptance.md
```

`00_READ_FIRST.md` 控制在短篇幅，只包含：

- 本批次目标；
- 绝对边界；
- 文件索引；
- 依赖关系；
- 章节适用场景；
- 完成定义；
- 其他章节的按需读取条件。

在这些拆分文件完成前，后续 AI 可以按本文件的章节标题和 `CONTEXT_LOADING_MAP.yaml` 读取局部内容，不得把总规格全文注入每次任务。

## 3.10 AI 执行前的上下文摘要

任何实现、复核或阶段推进任务，在执行前必须生成以下短摘要：

```text
当前任务类型：
当前目标/engagement：
当前 workflow：
当前 phase：
L0 硬边界来源：
本次允许动作：
本次禁止动作：
本次审批门：
当前输入事实：
本次加载的 phase 规则：
本次排除的无关来源：
规则冲突：
```

摘要写入 `context_snapshot`，用于新会话恢复。它不是替代原始规则，而是告诉下一次 AI 已经加载了什么、没有加载什么以及为什么。

## 3.11 验收标准

上下文治理完成前，不能声称“AI 已按需读取”。必须有离线测试验证：

- 当前 Web phase 不会加载小程序完整规则；
- 当前小程序 phase 不会加载全量历史 runs；
- `include_history=False` 不会读取历史候选原文；
- 凭证文件和原始响应默认被排除；
- 缺少 L0 规则时 fail-closed；
- 规则冲突能被发现并记录；
- source hash 变化会触发重新读取；
- context snapshot 能在新会话恢复 workflow/phase/当前事实；
- 当前事实与历史模式分栏；
- 上下文加载文件数量和字节数可统计；
- 不存在的必需 phase 文件会显式失败，不会静默跳过。

---

# 4. 新增统一数据模型和质量门

## 4.1 固定路径只产生 signal

修改：

```text
readonly_endpoint_confirm.py
deep_readonly_triage.py
src/authorized_assessment/triage/readonly_endpoint_confirm.py
src/authorized_assessment/triage/deep_readonly_triage.py
```

新增：

```text
src/authorized_assessment/triage/response_baseline.py
```

固定路径必须先与目标基线、登录页、统一错误页、CDN/WAF 页比较。默认输出：

```json
{
  "signal_type": "fixed_path",
  "confidence": "low",
  "promotion_status": "not_promoted",
  "baseline_similarity": 0.98,
  "body_semantic_match": false,
  "known_false_positive_pattern": "generic_200_error_page"
}
```

至少同时满足以下证据，才可升级为 candidate：

- 与基线有稳定差异；
- Content-Type 与资源类型一致；
- 页面标题、响应头、body 关键词和路径相互支持；
- 不是登录页、统一错误页、WAF 页或 CDN 页；
- 可低预算复现；
- 有明确影响假设。

## 4.2 统一去重键

新增：

```text
src/authorized_assessment/triage/canonical_keys.py
src/authorized_assessment/triage/candidate_dedup.py
contracts/candidate_identity_schema.json
```

通用键：

```text
canonical_target
endpoint
http_method
parameter_name
input_location
test_family
```

API 键：

```text
canonical_host
normalized_path
http_method
parameter_names
content_type
source_kind
```

小程序键：

```text
miniapp_id
backend_host
normalized_path
http_method
parameter_names
package_version
```

跨 run 只保留：

```text
first_seen
last_seen
seen_count
latest_status
latest_evidence_ref
```

## 4.3 API 来源可信度

API 来源分为：

```text
A = OpenAPI/Swagger/GraphQL schema 明确声明
B = 前端 JS 实际调用
C = 浏览器/Burp 真实流量
D = HTML 表单或链接
E = 猜测路径/固定字典
```

只有 A/B/C 可以进入正常候选队列；D 需要额外响应语义证据；E 默认只能是 `low_confidence_signal`。

## 4.4 证据门

新增：

```text
src/authorized_assessment/reporting/evidence_gate.py
contracts/finding_evidence_schema.json
tests/test_evidence_gate.py
```

报告发布前必须拒绝：

- 缺少 `finding_id`；
- `evidence_ref` 为空或路径不存在；
- 没有 validation result；
- confirmed/accepted_risk 没有 reviewer 和 reviewed_at；
- 报告把 candidate 当 confirmed；
- 报告包含凭证、token、session_key、AppSecret 或敏感数据原文。

---

# 5. Web 单站 wz：新增的完整可执行覆盖

## 5.1 修改阶段定义的文件

```text
.agents/skills/wz/scripts/init_engagement.py
.agents/skills/wz/references/workflow.md
.agents/skills/wz/references/test-matrix.md
.agents/skills/wz/references/data-to-test-playbook.md
.claude/skills/wz/...
.opencode/skills/wz/...
tool_strategy.json
scripts/gen_agent_manifest.py
```

`.agents/skills/` 继续作为 canonical；`.claude` 和 `.opencode` 只做镜像，修改后运行漂移检查。

不建议把所有漏洞类别扩成顶级 phase，保持现有 19 个顶级阶段，在阶段内部增加可审计子阶段。

## 5.2 application_mapping 子阶段

新增：

```text
graphql_mapping
websocket_mapping
file_surface_mapping
auth_surface_mapping
webhook_mapping
```

产物：

```text
engagements/<name>/artifacts/application-map/graphql-manifest.json
engagements/<name>/artifacts/application-map/websocket-inventory.csv
engagements/<name>/artifacts/application-map/file-surface-inventory.csv
engagements/<name>/artifacts/application-map/auth-surface-inventory.csv
engagements/<name>/artifacts/application-map/webhook-inventory.csv
```

每个子阶段至少输出：

```text
applicable
status: tested|not_applicable|blocked|inconclusive
source
asset
endpoint_or_surface
reason
evidence_ref
```

## 5.3 api_testing 子阶段

新增：

```text
api_schema_versions
api_inventory_reconciliation
object_field_authorization
api_resource_controls
graphql_testing
websocket_testing
third_party_api_review
```

### API schema/version

检查：

- OpenAPI 与实际流量差异；
- v1/v2/v3 等旧版本；
- shadow/test/debug API；
- HTTP method 和 Content-Type 差异；
- 文档中存在但实际不可达的接口；
- 实际可达但文档未登记的接口。

新增：

```text
src/authorized_assessment/analysis/api_inventory_reconcile.py
artifacts/api/api-version-inventory.csv
artifacts/api/api-reconciliation.csv
```

### API 资源控制

新增：

```text
src/authorized_assessment/triage/api_resource_controls.py
artifacts/api/resource-control-review.csv
```

默认只读检查：

- page/pageSize 上限；
- 深分页；
- 批量查询数量；
- 复杂过滤器；
- 导出/报表接口的权限和资源成本；
- 单用户、token、IP、租户的速率和配额；
- 重试、超时和缓存放大。

不得使用高并发或造成实际资源压力的方式验证。

### 第三方 API

新增：

```text
src/authorized_assessment/triage/third_party_api_review.py
artifacts/api/third-party-boundary.csv
```

检查：

- 第三方响应是否未经验证直接进入权限/金额/状态决策；
- callback/webhook 是否校验来源、签名、时间戳和重放；
- 第三方资产是否被误计入自有目标；
- 第三方返回是否导致敏感字段、跳转或权限扩大。

## 5.4 input_testing 子阶段

新增：

```text
injection_candidate_screening
parser_deserialization_screening
ssrf_candidate_screening
file_path_candidate_screening
browser_boundary_review
```

### 统一注入候选

新增：

```text
src/authorized_assessment/triage/injection_candidates.py
contracts/injection_candidate_schema.json
tests/test_injection_candidates.py
```

`category`：

```text
sql
nosql
ldap
xpath
ssti
expression_language
os_command
header_injection
template_injection
path_traversal
lfi
xxe
xml_parser
yaml_parser
unsafe_deserialization
```

每个类别都必须输出：

```text
applicable
tested
candidate
blocked
approval_required
not_applicable
inconclusive
reason
source
precondition
```

#### SQL/NoSQL

只有发现真实查询输入点、错误/差分或语义异常时才升级。SQLMap 仍只能在审批门下对单候选使用，禁止 dump、批量、全量扫描和数据导出。

#### SSTI/表达式/模板注入

必须证明：

- 输入进入服务端模板或表达式解释器；
- 最小无破坏性表达式产生可重复、上下文相关的求值结果；
- 结果不是客户端模板、普通字符串回显或错误页；
- 只有在批准后才能进行更高影响验证。

仅看到 `{{ }}`、`${ }`、模板文件名或模板框架名称不算漏洞。

#### XXE/XML 解析

XXE 放在 `parser_deserialization_screening`，不是只放 SQLi。前置条件必须是发现：

- XML API；
- SOAP/SAML/RSS/Atom；
- XML/SVG/Office 文档上传或导入；
- XML 配置导入；
- 后端 XML 解析器。

默认只做解析器和实体处理能力的低风险判定；不读取本地敏感文件、不访问内网、不导出数据。只有经审批的最小 OOB 或证明方式才可进一步验证。

#### 反序列化/YAML/解析器

仅有依赖名称、类名或序列化格式不算漏洞。必须证明：

- 外部可控输入进入危险解析器；
- 存在不安全类型、对象恢复或表达式处理；
- 能产生可复现的安全影响；
- 高风险 payload 需审批门。

### SSRF

新增策略和产物：

```text
src/authorized_assessment/triage/ssrf_candidate_screening.py
artifacts/ssrf/ssrf_candidates.jsonl
artifacts/ssrf/ssrf_review_queue.csv
artifacts/ssrf/oob_token_manifest.json
```

说明：项目已有 `ssrf_triage.py` 和 `oob_listener.py`，新模块可包装现有实现，避免重复造探测器。

默认只分析：

- URL、callback、webhook、image、import、remote file 参数；
- 协议和重定向限制；
- 已有响应证据；
- 是否可能访问内部地址或云元数据；
- OOB token 队列。

不得默认自动对 POST 写入探测值，不使用公共 OAST，不访问内网或云元数据。OOB、内部地址和任何写入验证均为审批门。

### 浏览器边界

新增：

```text
src/authorized_assessment/triage/browser_boundary.py
artifacts/browser-boundary/cors-csrf-cache.jsonl
reports/browser-boundary.md
tests/test_browser_boundary.py
```

覆盖：

- CORS allow-origin 与 credentials；
- preflight；
- CSRF token、SameSite、Origin/Referer；
- 私有响应 Cache-Control；
- 缓存键是否包含认证维度；
- 点击劫持；
- 开放重定向；
- postMessage 来源校验。

只有能导致跨站读取、跨用户操作、敏感数据缓存泄露或权限边界绕过时，才能升级为漏洞。

## 5.5 business_logic_testing

新增内部子分支：

```text
state_machine
replay_duplicate
race_hypothesis
race_validation
```

现有 `logic-workshop` 只负责离线重建状态机和生成假设，不发并发请求。`race_validation` 必须单独审批、指定端点/对象并有清理计划。

业务漏洞成立条件：

- 能明确写出正常状态序列；
- 能指出被绕过的服务端前置条件；
- 能证明业务结果超出用户应有权限或次数；
- 不是仅改变前端显示、客户端金额或本地状态；
- 不能因为重复点击一次就直接称为竞态漏洞，必须证明服务端状态发生不应有的重复消费/发放/扣款/审批结果。

---

# 6. 小程序 xcx：新增的完整可执行覆盖

## 6.1 修改文件

```text
.agents/skills/xcx/scripts/init_miniapp_engagement.py
.agents/skills/xcx/scripts/audit_miniapp_engagement.py
.agents/skills/xcx/references/workflow.md
.agents/skills/xcx/references/test-matrix.md
.agents/skills/xcx/references/package-analysis.md
.claude/skills/xcx/...
.opencode/skills/xcx/...
tool_strategy.json
scripts/gen_agent_manifest.py
```

所有新增分支都必须有 `coverage_substatus`，不能只写一个大阶段 complete。

## 6.2 阶段拆分

在 `source_reconstruction` 后、`static_analysis` 前加入：

```text
package_integrity_update_review
```

在动态映射后加入：

```text
static_dynamic_reconciliation
```

将 `authentication_session` 拆为：

```text
platform_login_exchange
session_token_lifecycle
signature_replay
```

将 `client_storage_crypto` 拆为：

```text
local_data_exposure
crypto_and_secret_handling
```

将 `plugins_cloud_third_party` 拆为：

```text
cloud_function_testing
cloud_storage_acl_testing
third_party_platform_boundary
```

## 6.3 包完整性和更新信任

新增：

```text
src/authorized_assessment/miniapp/package_integrity_update.py
artifacts/miniapp/package/package-integrity-review.json
tests/test_package_integrity_update.py
```

离线检查：

- 主包、子包、插件包版本；
- 清单和资源差异；
- 更新地址和环境切换；
- 调试开关；
- Source Map；
- 版本漂移；
- 前端是否信任可控更新配置。

不做重打包、篡改、绕过 pinning 或设备攻击。

## 6.4 静态/动态端点对账

新增：

```text
src/authorized_assessment/miniapp/static_dynamic_reconciliation.py
artifacts/miniapp/reconciliation/static-dynamic-endpoints.csv
tests/test_static_dynamic_reconciliation.py
```

端点状态：

```text
static_only
dynamic_only
both_seen
feature_gated
stale
version_specific
third_party
platform_shared
unreachable
needs_manual_validation
```

## 6.5 平台登录和会话

新增：

```text
src/authorized_assessment/miniapp/platform_login_exchange.py
src/authorized_assessment/miniapp/session_token_lifecycle.py
src/authorized_assessment/miniapp/signature_replay_review.py
artifacts/miniapp/auth/platform-login-review.json
artifacts/miniapp/auth/session-lifecycle-review.json
artifacts/miniapp/auth/signature-replay-review.json
tests/test_miniapp_auth_lifecycle.py
```

覆盖：

- `wx.login()` code 一次性和过期；
- AppID 绑定；
- `session_key` 是否只由服务端保管；
- OpenID 是否被错误当成授权依据；
- token 轮换、失效、注销；
- 多设备登录；
- 旧 token 对新版本接口；
- nonce/timestamp；
- 签名规范化和重放；
- 设备、用户、租户绑定。

仅在有人工提供的授权材料或本地流量时分析，不自动创建或滥用登录凭证。

## 6.6 本地存储和密码学

新增：

```text
src/authorized_assessment/miniapp/local_data_exposure.py
src/authorized_assessment/miniapp/crypto_secret_review.py
artifacts/miniapp/storage/local-data-review.json
artifacts/miniapp/crypto/secret-review.json
tests/test_miniapp_storage_crypto.py
```

检查：

- token 是否落地；
- logout 是否清理；
- 本地缓存、数据库、日志、剪贴板、截图、临时文件；
- AppSecret、固定 token、密钥硬编码；
- 自定义加密、弱随机数、密钥派生；
- 包中调试配置和环境密钥。

发现密钥字符串但无法证明有效性时只能是 `secret_candidate`，不能直接称为密钥泄露漏洞。

## 6.7 云函数、对象存储和第三方

新增：

```text
src/authorized_assessment/miniapp/cloud_function_review.py
src/authorized_assessment/miniapp/cloud_storage_review.py
src/authorized_assessment/miniapp/third_party_boundary_review.py
artifacts/miniapp/cloud/cloud-function-review.json
artifacts/miniapp/cloud/object-storage-review.json
artifacts/miniapp/cloud/third-party-boundary.csv
tests/test_miniapp_cloud_review.py
```

覆盖：

- 云函数匿名调用；
- 函数参数和角色校验；
- 云环境 ID 混用；
- 云数据库规则；
- 对象存储 ACL；
- 签名 URL 过期、路径绑定和跨对象访问；
- 地图、支付、推送等第三方边界；
- 平台共享资产不得误报为自有资产。

默认只做材料、配置、授权流量和最小读验证，任何写入、批量读取和真实支付必须审批。

## 6.8 WebView、Bridge、Deep Link

在现有 `webview_bridge_links` 阶段增加固定产物：

```text
artifacts/miniapp/webview/webview-origin-inventory.csv
artifacts/miniapp/webview/bridge-method-inventory.csv
artifacts/miniapp/webview/deep-link-review-queue.csv
```

覆盖：

- WebView 允许域名；
- JS bridge 方法暴露；
- postMessage origin；
- 自定义 scheme；
- 深链中的对象 ID、tenant ID、scene 参数；
- 外部 App/浏览器跳转；
- Cookie/token 共享边界。

只有能造成跨域数据读取、越权、敏感 token 暴露或外部控制时才升级。

---

# 7. 工具和运行时纳入方案

本节纳入新增工具能力，但不改变旧式专项工具“非默认主链、审批门、单候选、queue-only”的定位。

## 7.1 轻量工具登记文件

新增：

```text
tools/tool_registry.json
tools/README_tool_registry.md
contracts/tool_capability_schema.json
scripts/maintenance/rebuild_tool_inventory.py
tests/test_tool_registry.py
```

这是个人项目的本地运行登记，不是完整的软件供应链审计系统。目标是让运行器和后续 AI 知道“工具在哪里、是什么版本、当前能不能调用”，而不是为每个工具建立签名、来源和逐文件完整性证明。

每个工具默认只记录：

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

可选记录（不作为普通流程阻塞条件）：

```text
source_url
release_date
sha256
notes
```

以下字段从工具白名单中移除，不再要求登记：

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

说明：

- 速率、并发、只读模式、queue-only、审批门和证据要求由现有流程规则、`ROE.md`、`policy_engine.py`、`tool_strategy.json` 和阶段代码统一控制；
- 工具 registry 不重复维护审批逻辑，避免产生两套可能冲突的审批来源；
- `status` 只表示本地工具是否可被解析和调用，不表示安全授权；
- `dependencies` 只用于运行前能力提示，不承担完整依赖供应链审计；
- `known_limitations` 用于防止 AI 把工具输出误认为完整漏洞确认。

状态：

```text
active
unavailable
hold
retired
```

`conditional` 不作为工具白名单状态；如果某工具只能在特定阶段使用，由 `tool_strategy.json` 和现有审批门控制，而不是在 registry 中再次登记。

`tool_strategy.json` 只能引用 registry 中真实存在且状态不是 `unavailable` 的 `tool_id`。逻辑候选名和不存在的路径必须显式标记为 `unavailable`，不能伪装成可执行工具。

## 7.2 纳入的新工具能力

### ffuf

接入：

```text
file_surface_mapping
directory_candidate_discovery
```

要求：

- 固定小词表；
- 单目标；
- 低速；
- 禁止默认递归；
- 只产生 signal/candidate；
- 200 不等于存在敏感资源；
- 必须结合 baseline 和语义证据。

### Dalfox 或 XSStrike

二选一，不同时引入。接入：

```text
single_candidate_xss_validation
```

要求：

- 只处理已筛选的反射/DOM 候选；
- 不做全量自动扫描；
- reflection/DOM-safe 模式；
- 单目标、单参数、低速；
- 结果必须能回到原始请求、响应、浏览器上下文和证据索引。

### subfinder + dnsx

接入：

```text
passive_discovery
known_candidate_dns_resolution
```

限制：

- 被动源或本地缓存导入；
- 不默认进行公网主动枚举；
- CT 结果人工/缓存导入；
- 新发现域名先 `confirmation_required`，不能直接纳入扫描。

### Semgrep 或 CodeQL

接入：

```text
static_analysis
whitebox_triage
```

要求：

- 规则固定在本地；
- 不联网拉规则；
- 只输出 sink、source、路径和上下文；
- 静态命中不能自动变成漏洞；
- 需要后续可触达和影响验证。

### 离线 SBOM/依赖审计

接入：

```text
preflight
infrastructure_testing
reporting
```

优先输出 lockfile、版本、依赖关系和本地 advisory cache 结果。无 advisory 数据库时只能报告“依赖清单”和“需要人工复核”，不能伪造漏洞结论。

## 7.3 Afrog 和固定模板

个人项目不要求对每个工具或每个模板文件做完整 SHA-256 供应链审计。工具管理只需保持轻量可复现：

- run 中记录实际使用的工具名称、版本和路径；
- `runtime_inventory.json` 记录实际 Python/Node/Java 和关键依赖版本；
- Nuclei 记录引擎版本、模板版本或模板目录标识；
- Afrog 记录本地 POC 目录和版本/目录标识；
- 关键 run 产物仍可使用现有 artifact manifest 做完整性记录；
- 工具 registry 中的 `sha256/release_date/source_url` 如果保留，只是可选信息，缺失不能阻塞普通只读流程。

Afrog 仍必须禁止自更新：

- 固定本地 POC 目录；
- 禁止运行时联网下载或更新 POC；
- 如果工具发现需要更新，只记录提示并继续使用固定本地版本，或将相关阶段标为 `unavailable`；
- 不因为没有模板哈希就阻塞整个项目。

Nuclei 同样只需记录：

```text
engine_version
template_version_or_directory
last_used_at
```

`template_manifest_hash` 可以保留为可选字段，不再是普通流程的强制门。

## 7.4 统一 Python 和 launcher

修改：

```text
launchers/一键保守全流程_尽量多信息_避WAF.bat
launchers/一键完整流程_含弱口令.bat
launchers/一键已有子域名后流程_含弱口令.bat
launchers/一键并行分批流程.bat
gov_exercise_config.json
```

统一顺序：

```text
项目 .venv
→ 明确登记的兼容 Python
→ PATH python
```

外部 Tianhu/Codex runtime 只能作为兼容回退。

每次 run 的 `runtime_inventory.json` 至少记录：

```text
python_path
python_version
requests_version
urllib3_version
pytest_available
docx_available
playwright_available
crypto_available
node_available
java_available
```

修复：

- `launchers/一键完整流程_含弱口令.bat` 第 29 行附近孤立 `)`；
- “已有子域名后流程”和“并行分批流程”与其他 launcher 的 Python 选择顺序不一致；
- DNS 并发、HTTP host 并发、跨 host worker 并发必须分别配置；
- `--subdomain-concurrency 6` 必须明确是 DNS 专项预算，不能与 HTTP 并发混淆。

---

# 8. fh/postrun 复核流程改造

本次不新增独立深挖交接文件，但必须让现有 fh 结果具备明确的下游字段。

## 8.1 修改文件

```text
.agents/skills/fh/SKILL.md
.agents/skills/fh/references/review-playbook.md
.agents/skills/fh/references/output-map.md
.agents/skills/postrun-review/SKILL.md
scripts/init_postrun_review.py
```

## 8.2 每条候选必须补充

```text
finding_id
candidate_id
asset_type
vulnerability_family
impact_class
quality_status
recommended_workflow
recommended_phase
blocked_reason
next_action
owner
sla
last_seen
evidence_ref
```

`recommended_workflow/recommended_phase` 直接写在现有 review queue/ledger 中，不创建额外 handoff 产物。

## 8.3 复核顺序

```text
run_quality_gate
scope_reconciliation
candidate_deduplication
source_coverage_check
authentication_queue_review
authorization_queue_review
injection_queue_review
ssrf_queue_review
product_queue_review
miniapp_queue_review
evidence_gate
report_lifecycle
cleanup_audit
```

## 8.4 复核判定规则

- `INCONCLUSIVE` run 不得得出阴性结论；
- fixed-path signal 不进入主漏洞队列；
- 缺证据的 confirmed 自动退回 `needs_manual_validation`；
- 重复候选合并为一个 finding，保留首次发现和最近验证时间；
- 不能因为同一现象在多个 run 出现就提高严重性；
- 只有影响、权限边界或业务结果被证明时，才提高优先级。

---

# 9. 历史产物降噪和复利机制

## 9.1 新增知识库

```text
knowledge_base/false_positive_patterns.jsonl
knowledge_base/fingerprint_precision.jsonl
knowledge_base/endpoint_behavior_profiles.jsonl
knowledge_base/review_feedback_schema.json
src/authorized_assessment/analysis/review_feedback_ingest.py
src/authorized_assessment/analysis/precision_model.py
scripts/maintenance/rebuild_review_memory.py
tests/test_review_feedback_ingest.py
```

误报模式字段：

```text
pattern_id
product_family
server_fingerprint
response_status
content_type
body_similarity
path_pattern
negative_context
suppression_rule
first_seen
last_seen
sample_count
candidate_count
confirmed_count
rejected_count
precision
review_notes
```

重点学习：

- 通用 200 错误页；
- 登录页；
- CDN/WAF 伪装页；
- 特定框架默认页；
- 状态码组合和限速模式；
- 需要登录才有意义的 API；
- 与 confirmed finding 相关的 JS/API 特征。

## 9.2 复核反馈回灌

每次 ledger 从 candidate 变为 confirmed/rejected/accepted_risk/duplicate 时，自动更新：

- 产品指纹精度；
- 规则 precision；
- 固定路径抑制模式；
- API 来源可靠性；
- WAF/网络异常特征；
- 需要人工登录的目标类型。

下一次候选排序：

```text
known_false_positive → 降权或不入队
known_high_precision_signal → 提升优先级
unknown_pattern → 保留候选但不直接升级
```

## 9.3 重跑生命周期

修改：

```text
exercise_runtime.py
src/authorized_assessment/runtime/...
src/authorized_assessment/orchestration/...
run_lifecycle.py
contracts/workflow_schema.json
```

每个 run 增加：

```text
parent_run_id
attempt_no
retry_of
engagement_id
phase
config_hash
input_hash
started_at
finished_at
terminal_state
```

重复键：

```text
engagement_id
+ canonical_target
+ phase
+ config_hash
+ input_hash
```

冷却窗口内相同输入优先 resume/delta，不重复全量运行。并行批次建立父 run，子批次只保留分片索引和结果引用。

---

# 10. 覆盖矩阵：让“阶段完成”可证明

## 10.1 新增文件

```text
engagements/<name>/artifacts/test-dimensions.csv
contracts/test_dimensions_schema.json
contracts/coverage_substatus_schema.json
src/authorized_assessment/analysis/coverage_matrix.py
tests/test_coverage_matrix.py
```

字段：

```text
role
account_ref_hash
tenant
object_ref_hash
api_version
client_version
device
workflow_state
http_method
content_type
feature_flag
authentication_state
branch
status
reason
evidence_ref
```

`account_ref_hash/object_ref_hash` 只能保存不可逆引用，不保存凭证和敏感对象原文。

## 10.2 聚合阶段的子状态

例如：

```yaml
api_testing:
  api_schema_versions: tested
  object_authorization: tested
  field_authorization: needs_manual_validation
  graphql: not_applicable
  websocket: blocked
  pagination: tested
  third_party_api: inconclusive
```

每个子分支只能取：

```text
tested
not_applicable
blocked
approval_required
needs_manual_validation
inconclusive
```

`not_applicable` 必须有理由，不能空填。

## 10.3 适用性优先

AI 必须先回答：

```text
该攻击面是否存在？
是否已知输入点/端点？
是否有授权材料？
是否允许低风险验证？
当前是否有成功响应？
```

只有 `applicable` 才进入测试；不适用必须落盘为 `not_applicable`，不是静默跳过。

---

# 11. AI 专用漏洞判定提示词规则

以下规则应写入：

```text
prompts/配方A_复盘会话.md
prompts/配方B_规划会话.md
prompts/配方C_单目标深挖.md
prompts/配方D_逻辑漏洞工作坊.md
prompts/配方F_白盒研判.md
prompts/配方Z_全流程验收.md
.agents/skills/fh/SKILL.md
.agents/skills/wz/SKILL.md
.agents/skills/xcx/SKILL.md
```

并同步 `.claude/skills/`、`.opencode/skills/` 镜像。

## 11.1 强制使用的结论模板

AI 不得直接写：

```text
发现漏洞：XXX
```

必须先写：

```text
对象类型：signal | candidate | confirmed | inconclusive
授权状态：confirmed | confirmation_required | blocked
可触达性：reachable | unverified | unreachable
复现状态：reproducible | partial | not_reproduced
影响类别：none | low | medium | high | critical
影响对象：用户/租户/业务对象/权限/数据/网络边界/服务可用性
证据完整性：complete | partial | missing
结论：
下一步：
```

只有所有成立门满足时才能使用 `confirmed`。

## 11.2 四问否决规则

以下任一问题回答“否”，不得称 confirmed：

1. 是否有明确的授权资产和允许的测试动作？
2. 是否有真实可触达的端点、功能或数据流？
3. 是否有可重复的异常行为或越权结果？
4. 是否能说明对企业造成了非琐碎的安全影响并提供证据？

## 11.3 细微发现的处置

以下统一为 `signal` 或 `candidate`：

- Banner、版本、框架名称；
- robots、sitemap、OpenAPI 文档存在；
- 目录/文件名猜测命中；
- 500 错误、异常堆栈但无敏感信息；
- 反射但未执行；
- 前端隐藏功能；
- 代码中出现 `eval`、模板语法、XML parser、危险 sink；
- JWT 看起来可解码；
- 响应中有内部主机名但不能访问；
- 单次超时或 403；
- 一个用户能看到自己的对象；
- 无敏感数据的字段过多；
- 无法证明有效性的疑似密钥。

AI 必须写清楚：

```text
为什么不升级为漏洞：缺少哪一项成立门
```

## 11.4 漏洞成立的最小链条

所有正式 finding 都要形成：

```text
入口/资产
→ 攻击者可控输入或低权限身份
→ 服务端缺陷/边界缺失
→ 可复现结果
→ 对企业的具体影响
→ 最小必要证据
```

如果链条中间只有“推测”，状态不得超过 candidate。

---

# 12. 文档和权威资料映射

## 12.1 OWASP WSTG v4.2

https://owasp.org/www-project-web-security-testing-guide/

用于组织：

- 信息收集；
- 配置与部署；
- 身份认证；
- 授权；
- 输入验证；
- 业务逻辑；
- 客户端；
- API、GraphQL、WebSocket 等现代通信面。

引用时写明 `OWASP WSTG v4.2`，同时注明官方页面显示 v5.0 正在开发，不把未发布版本当作稳定标准。

## 12.2 OWASP API Security Top 10 2023

https://owasp.org/API-Security/editions/2023/en/0x00-header/

必须显式映射：

```text
API1 BOLA → object_authorization
API2 Broken Authentication → platform_login/session_lifecycle
API3 BOPLA → field_authorization
API4 Unrestricted Resource Consumption → api_resource_controls
API5 BFLA → function_authorization
API6 Sensitive Business Flows → state_machine/race/replay
API7 SSRF → ssrf_candidate_screening
API8 Security Misconfiguration → browser_boundary/infrastructure
API9 Inventory Management → api_schema_versions/reconciliation
API10 Unsafe Consumption of APIs → third_party_api_review
```

## 12.3 OWASP MASVS/MASTG 与 Mobile Top 10 2024

https://mas.owasp.org/MASVS/
https://mas.owasp.org/MASTG/
https://owasp.org/www-project-mobile-top-10/

映射到小程序：

- AUTH → 平台登录、token 生命周期；
- STORAGE → 本地数据、日志、剪贴板、退出清理；
- NETWORK → HTTPS/WSS、域名和证书；
- CRYPTO → 密钥、随机数、自定义加密；
- PLATFORM → WebView、Bridge、Deep Link；
- PRIVACY → 敏感数据最小化和权限使用；
- RESILIENCE/二进制保护只对原生组件条件适用，不机械套用小程序。

## 12.4 微信官方文档

```text
https://developers.weixin.qq.com/miniprogram/dev/framework/security.html
https://developers.weixin.qq.com/miniprogram/dev/framework/ability/network.html
https://developers.weixin.qq.com/miniprogram/dev/framework/open-ability/login.html
```

重点映射：

- 前后台鉴权；
- 源码和密钥保护；
- 敏感数据脱敏；
- 注入、上传下载、目录遍历、并发条件竞争；
- HTTPS/WSS、TLS 1.2、服务器域名；
- `wx.login()` code 和 `session_key` 服务端保管。

## 12.5 CWE Top 25 2025

https://cwe.mitre.org/top25/

用于基础覆盖优先级：

- XSS；
- SQL 注入；
- 缺失授权；
- 路径遍历；
- 命令注入；
- 危险文件上传；
- 反序列化；
- SSRF；
- 认证缺失；
- 资源无限制。

## 12.6 PortSwigger Web Security Academy

https://portswigger.net/web-security/all-materials

用于具体测试方法参考：

- GraphQL；
- WebSocket；
- JWT；
- 业务逻辑；
- 竞态；
- 缓存；
- SSRF；
- SSTI；
- XXE；
- 文件上传；
- HTTP/2 等现代协议。

## 12.7 NIST SP 800-115

https://csrc.nist.gov/pubs/sp/800/115/final

用于测试生命周期：

```text
规划 → 实施 → 分析 → 报告 → 复测
```

不把 NIST 当作必须使用某个工具的规定。

## 12.8 布天规则网站的可用性说明

本次访问：

```text
https://www.butian.net/Help/plan
```

页面被重定向到奇安信用户登录页，未能取得规则正文。因此实现 AI **不得声称本文件逐条引用了布天页面的当前内容**，也不得把登录页推断成规则。

布天规则后续如果由操作者提供已授权的 HTML/PDF/截图，应新增：

```text
docs/external_rules/butian_plan_snapshot.md
scripts/maintenance/validate_external_rules.py
```

并记录：

```text
source_url
retrieved_at
provided_by
content_hash
version_or_title
```

在没有快照前，以本地《攻击方评分规则.docx》、`ROE.md`、授权边界、OWASP/CWE/微信官方资料为当前规则依据。

---

# 13. 测试和验收要求

## 13.1 新增离线测试

必须增加：

```text
tests/test_run_quality_gate.py
tests/test_finding_quality_gate.py
tests/test_candidate_dedup.py
tests/test_canonical_keys.py
tests/test_injection_candidates.py
tests/test_graphql_inventory.py
tests/test_graphql_review.py
tests/test_websocket_review.py
tests/test_browser_boundary.py
tests/test_api_inventory_reconcile.py
tests/test_api_resource_controls.py
tests/test_miniapp_auth_lifecycle.py
tests/test_miniapp_storage_crypto.py
tests/test_miniapp_cloud_review.py
tests/test_package_integrity_update.py
tests/test_static_dynamic_reconciliation.py
tests/test_coverage_matrix.py
tests/test_tool_registry.py
tests/test_review_feedback_ingest.py
tests/test_evidence_gate.py
```

## 13.2 必须覆盖的负例

测试不能只验证“命中就报漏洞”，必须覆盖：

- 通用 200 错误页；
- 登录页；
- WAF/403/429；
- 超时和 DNS 错误；
- 重复 API 候选；
- 只有静态 sink、无可达链路；
- 反射但不可执行；
- XML 输入但不是 XML 解析器；
- SSTI 字符串回显；
- 仅有版本指纹；
- 只有一次竞态异常；
- 空 ledger；
- 缺 evidence_ref；
- coverage > 1；
- 全部失败但健康分较高；
- `not_applicable` 没有 reason；
- 工具 registry 中不存在的逻辑工具名。

## 13.3 离线验收命令

在实现修改完成后，其他 AI 必须执行并报告真实结果：

```bash
python -m pytest -q
python scripts/verify_offline.py --json
python scripts/maintenance/validate_run_contracts.py
python scripts/maintenance/validate_finding_quality.py
```

如果命令失败，不能在交付说明中写“已完成验证”，必须给出失败测试和原因。

## 13.4 阶段完成验收

每个新增或修改阶段必须满足：

- 初始化器能生成阶段；
- 审计器能识别阶段和合法状态；
- `tool_strategy.json` 有对应策略；
- `AGENT_MANIFEST.md` 可由生成器更新；
- 至少有一个正常样例和一个负例；
- 产物路径和 schema 已登记；
- run_health 能统计该分支；
- fh 能复核该分支；
- 报告不会把 signal/candidate 自动升级为 confirmed；
- `.agents`、`.claude`、`.opencode` 镜像无漂移。

---

# 14. 推荐实施顺序

## 第一批：质量、上下文和误报门，必须先做

1. 修复 `run_lifecycle.py` 的 `Path` 导入；
2. 统一 scope/review 状态集合；
3. 建立 `CONTEXT_LOADING_MAP.yaml`、`RULE_PRECEDENCE.md` 和 `context_loader.py`；
4. 生成 L0 `policy_snapshot.json`，禁止每次任务全文读取项目配置；
5. 实现 workflow/phase 按需加载、来源 hash、上下文快照和规则冲突检测；
6. 修复 coverage 聚合和健康分；
7. 增加 `INCONCLUSIVE` 质量门；
8. 固定路径降级为 signal；
9. 增加 canonical candidate 去重；
10. 增加 finding/evidence gate；
11. 修复完整流程 launcher 孤立 `)`；
12. 统一 Python fallback；
13. 重建 runtime/tool inventory。

## 第二批：Web/API 显式分支

1. application mapping 的 GraphQL/WebSocket/file/auth/webhook 子阶段；
2. API 版本和 shadow API 对账；
3. API 对象/字段/功能权限维度；
4. API 资源消耗、分页、批量和限速；
5. 第三方 API 边界；
6. 统一注入候选；
7. parser/deserialization/XXE；
8. SSRF candidate screening；
9. CORS/CSRF/cache/browser boundary；
10. state machine/replay/race hypothesis。

## 第三批：小程序显式分支

1. package integrity/update；
2. static_dynamic_reconciliation；
3. platform login exchange；
4. session token lifecycle；
5. signature/replay；
6. local data exposure；
7. crypto/secret handling；
8. cloud function；
9. cloud storage ACL；
10. third-party/platform boundary；
11. WebView/Bridge/Deep Link 固定产物。

## 第四批：工具和长期复利

1. tool registry 和版本/哈希/能力模型；
2. Afrog/Nuclei 固定模板完整性；
3. ffuf 受控目录候选；
4. Dalfox 或 XSStrike 单候选 XSS；
5. subfinder + dnsx 被动/已知候选模式；
6. Semgrep 或 CodeQL 离线白盒；
7. 离线 SBOM/依赖审计；
8. 历史误报模式、精度库和 review feedback 回灌；
9. parent/attempt/config/input 生命周期；
10. test dimensions 和覆盖矩阵。

---

# 15. 交付给后续 AI 的执行清单

后续 AI 开始实现时必须按以下顺序汇报和落盘：

```text
[ ] 1. 阅读 AGENTS.md、ROE.md、授权边界和本规格的 `00_READ_FIRST` 或当前相关章节
[ ] 2. 根据 `docs/CONTEXT_LOADING_MAP.yaml` 确定 task_type、workflow、phase 和最小读取集
[ ] 3. 先生成/读取 L0 `runtime/policy_snapshot.json`，检查来源 hash、授权、scope、停止条件和审批门
[ ] 4. 只加载一个 workflow 和当前 phase 的规则、schema、输入产物及测试；不得全文加载无关 Skill、prompt、历史 run
[ ] 5. 写入 `context_snapshot`，列明 loaded_sources、excluded_sources、current_facts、historical_inputs 和 context_conflicts
[ ] 6. 读取现有目标文件和对应 tests，不凭文件名猜实现
[ ] 7. 列出将修改/新增的完整文件清单
[ ] 8. 先实现 contract/schema 和状态模型
[ ] 9. 再实现 quality/evidence/dedup 门
[ ] 10. 再接入 Web/API 子阶段
[ ] 11. 再接入小程序子阶段
[ ] 12. 再接工具 registry 和新增工具能力
[ ] 13. 更新 canonical skill，再同步镜像
[ ] 14. 更新 tool_strategy 和生成 AGENT_MANIFEST
[ ] 15. 增加正例和负例测试
[ ] 16. 运行离线验收命令
[ ] 17. 检查 git diff、状态契约、产物路径、上下文快照和文档漂移
[ ] 18. 只在全部结果真实通过后写“完成”
```

每次实现 AI 交付时必须说明：

- 改了哪些文件；
- 每个文件解决什么问题；
- 新增阶段如何插入依赖图；
- 新增产物路径和字段；
- 哪些漏洞分支仍是 `blocked/not_applicable/inconclusive`；
- 哪些工具本地不可用；
- 运行了哪些测试；
- 哪些测试失败；
- 是否改变了任何默认网络行为、速率、并发或审批门。

---

# 16. 最终目标

完成本规格后，项目不应再以“候选数量多”“发现了很多异常”“某模板命中”作为质量证明，而应以以下闭环衡量：

```text
资产已授权
→ 攻击面已建模
→ 子分支适用性已记录
→ 低风险测试已完成或明确阻塞
→ 候选经过基线、差异和语义门
→ 候选被 canonical 去重
→ 只有实质影响进入 confirmed
→ confirmed 有完整证据
→ 失败和未覆盖不会伪装成阴性结论
→ 复核结果反馈到下一轮指纹和误报记忆
→ 报告、复测和生命周期状态一致
```

项目最终应从“能发现未授权访问和 XSS 的工具集合”升级为：

> **以授权范围为前提、以攻击面适用性为入口、以影响和证据为结论、以历史复核反馈为复利的 Web/API/小程序安全评估工作台。**
