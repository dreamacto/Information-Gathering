# Web 单站流程与复核流程隔离执行提示词

项目目录：

```text
D:\PythonSource\PythonProjects\PythonProject4
```

请严格执行本提示词，目标是把以下两类工作完全分开：

```text
FH / postrun-review：复核已有 run 产物
WZ / 单一网站流程：对一个网站或 Web/API engagement 重新建立并推进测试
```

核心要求：

> **单一网站流程不得因为存在 FH 复核结果、历史 run 候选、历史报告或 AI 以前的判断而跳过、缩减或假设已经完成任何测试阶段。历史结果最多只能作为线索，不能作为当前单站覆盖证据。**

---

## 一、先确定当前任务类型，不要混流

开始任何工作前，先判断用户当前请求属于哪一种：

### 类型 A：FH / postrun 复核

用户表达类似：

```text
复核这个 run
复盘扫描结果
处理候选队列
判定误报
审核报告素材
关闭 review ledger
```

此时只能做：

- 读取指定 run 的结构化产物；
- 读取对应 `postrun_review/`；
- 读取必要的 engagement 台账；
- 做候选分级、去重、误报判断和状态记录；
- 生成复核结论和人工待办；
- 如果规则允许，生成下游建议，但不能把建议当作单站测试完成。

### 类型 B：WZ / 单一网站流程

用户表达类似：

```text
深挖这个网站
推进单站流程
测试这个目标的下一阶段
继续当前 engagement
做单目标 Web/API 分析
```

此时只能做：

- 读取当前 WZ engagement 的授权、scope、phase cursor、notes、artifacts 和当前阶段输入；
- 以当前网站为中心重新建立资产、入口、技术栈、认证拓扑和攻击面事实；
- 按 WZ 当前阶段推进；
- 历史 FH/run 结果只能作为待验证线索，不能直接转成已测、已确认或已覆盖。

### 类型 C：明确的 FH → WZ 转交

只有用户明确要求：

```text
把这个复核结果转入单站深挖
根据复核结果继续深挖这个网站
```

才允许读取 FH 的指定输出，并且必须将其转换为：

```text
historical_lead / pending_hypothesis
```

而不是：

```text
current_tested / current_confirmed / current_coverage
```

如果用户没有明确要求转交，禁止自动把 FH 结果带入 WZ。

---

## 二、文件加载规则：先加载最小集合

不要把整个项目、全部 Skill、全部 prompt、全部 runs 和全部 reports 一次性读入上下文。

### 1. 所有任务都必须加载的 L0 文件

只读取必要章节或摘要：

```text
AGENTS.md
ROE.md
.agents/skills/authorized-pentest-workflow/references/authorization-boundaries.md
```

如果已经存在，再读取：

```text
runtime/policy_snapshot.json
implementation_progress.json（仅代码改造任务需要）
```

L0 只确认：

- 授权范围；
- 当前目标；
- 测试窗口；
- 允许动作、禁止动作和审批门；
- 速率/并发；
- 敏感数据规则；
- 停止条件。

### 2. FH 任务允许读取的文件

仅在任务明确是 FH/postrun 复核时读取：

```text
.agents/skills/fh/SKILL.md
.agents/skills/fh/references/output-map.md
.agents/skills/fh/references/review-playbook.md
.agents/skills/postrun-review/SKILL.md
prompts/配方A_复盘会话.md
```

然后只读取用户指定的：

```text
runs/<指定run>/run_summary.json
runs/<指定run>/run_health.json
runs/<指定run>/runtime_inventory.json
runs/<指定run>/targets.csv 或 targets.json
runs/<指定run>/candidate_*.jsonl
runs/<指定run>/api_*.jsonl
runs/<指定run>/product_*.jsonl
runs/<指定run>/postrun_review/
engagements/<对应目标>/review_ledger.csv（确有映射时）
```

FH 默认禁止读取：

```text
其他目标的 runs
其他 engagement 的完整内容
全部历史报告
原始响应全文
完整 HAR
凭证文件
auth_sessions.local.json
sessions.jsonl
```

FH 不能修改、删除、移动或覆盖历史成果，除非用户另行明确要求且操作符合项目规则。

### 3. WZ 单站任务允许读取的文件

单站任务只能加载当前 WZ engagement：

```text
.agents/skills/wz/SKILL.md
.agents/skills/wz/references/workflow.md
.agents/skills/wz/references/test-matrix.md
.agents/skills/wz/references/data-to-test-playbook.md
.agents/skills/wz/scripts/audit_engagement.py（需要审计时）
.agents/skills/wz/scripts/init_engagement.py（需要初始化/恢复时）
```

当前 engagement 目录中按当前阶段读取：

```text
engagement.json
scope.csv
hosts.csv
phase_status.json
review_ledger.csv
notes/target-model.md
notes/phase-history/ 当前阶段相关记录
notes/ 当前阶段相关记录
artifacts/ 当前阶段相关产物
```

WZ 默认禁止读取：

```text
runs/*/candidate_*.jsonl
runs/*/verified_exposures.*
runs/*/false_positive_exposures.*
runs/*/reports/*
其他目标的 postrun_review/
其他 engagement 的 review_ledger.csv
FH 的整体统计和历史结论
```

如果当前 WZ 任务确实需要历史线索，必须由用户明确授权“引用哪个 run/哪条候选”，并单独标记为：

```text
source_class: historical_lead
current_status: unverified
```

不能因为历史候选存在，就跳过当前 WZ 的 discovery、mapping、authorization 或 validation 阶段。

### 4. WZ 单站必须读取的当前事实

即使历史 FH 已经写过以下内容，WZ 仍必须基于当前 engagement 重新核对：

```text
授权和资产归属
scope 和 host 分类
DNS/TLS/HTTP 存活
技术栈和产品版本
页面/路由/表单/参数
JS/API/Source Map
认证入口和会话拓扑
角色/租户/对象关系
GraphQL/WebSocket/Webhook
文件上传/下载/导入/导出面
注入、SSRF、解析器、反序列化入口
业务状态机和竞态假设
```

历史结果只能成为：

```text
待验证线索
```

不能成为：

```text
已测试
已排除
已确认
无需再测
```

---

## 三、WZ 与 FH 的硬隔离规则

### 规则 1：历史结果不能替代当前阶段

以下说法均禁止：

```text
历史 run 没有发现 SQLi，所以本次跳过 SQLi
FH 已经确认 XSS，所以 WZ 不需要重新验证
之前 API 候选为空，所以当前 API testing 可以标 complete
历史报告写了没有 GraphQL，所以当前不需要 mapping
```

正确做法是：

```text
历史结果 → historical_lead
当前阶段重新检查 → tested / not_applicable / blocked / inconclusive
```

### 规则 2：FH 的 rejected 不能永久排除 WZ

FH 的 `rejected` 只表示：

```text
某一次 run、某一版本、某一输入、某一上下文下被判定为误报
```

它不能直接证明当前网站永久没有该问题。若当前版本、入口、角色、租户或业务状态变化，WZ 必须重新评估。

### 规则 3：FH 的 confirmed 也不能替代 WZ 当前验证

FH 的 confirmed 可以作为 WZ 的高优先级线索，但必须重新确认：

- 当前目标是否相同；
- 当前 host/path/method 是否相同；
- 当前授权是否覆盖；
- 当前版本和业务状态是否相同；
- 当前漏洞是否仍可复现；
- 当前影响是否仍然存在。

### 规则 4：不得从 runs 自动拼接 WZ 当前资产图

WZ 的当前资产图必须来自：

```text
当前 engagement 的 scope/hosts
当前阶段允许的发现输入
当前授权材料
当前明确导入的材料
```

不能自动把所有历史 run 的 host、API、子域和产品指纹合并进当前 WZ。

### 规则 5：WZ 不读取 FH 的最终证据结论来降低工作量

以下文件即使存在，WZ 默认也不读：

```text
postrun_review/verdicts/
reports/daily_report_draft.md
reports/evidence_index.md
reports/platform_submission_template.json
reports/screenshot_queue.*
```

它们是复核/报告派生物，不是 WZ 当前阶段事实源。

### 规则 6：单站阶段必须留下自己的记录

每个 WZ 阶段必须在当前 engagement 写入：

```text
notes/phase-history/<phase>.md
phase_status.json
当前 phase 的 artifacts/
```

记录：

```text
本阶段当前事实
输入来源
实际执行了什么
没有执行什么
为什么没有执行
发现的线索
排除的线索
当前状态
下一阶段
```

不能只在 FH 的历史日志中留下记录。

---

## 四、WZ 单站推进协议

每次 WZ 任务必须按以下顺序执行：

```text
1. 确认 workflow=wz
2. 确认当前 engagement 名称和目标
3. 读取当前 phase_status.json（双流工作区中只读取 WZ 自己的 phase_status.json）
4. 读取当前 scope/hosts/target-model
5. 读取当前 phase 规则和测试矩阵
6. 只读取当前 phase 所需 artifacts
7. 生成当前 phase 的执行卡片
8. 只推进一个 phase
9. 写入 phase-history 和当前 phase 产物
10. 更新 phase_status.json
11. 做当前 phase 的离线/本地测试或允许的低速验证
12. 记录未测攻击面和原因
13. 再决定是否进入下一 phase
```

### WZ 执行卡片必须包含

```text
workflow: wz
engagement:
target:
current_phase:
loaded_sources:
excluded_fh_sources:
historical_leads_used: none | listed
current_facts:
applicable_branches:
not_applicable_branches:
blocked_branches:
planned_actions:
forbidden_actions:
expected_outputs:
phase_test_command:
pass_criteria:
```

### WZ 阶段完成条件

一个阶段只有同时满足以下条件才可标记 `complete`：

- 当前阶段输入已读取；
- 当前阶段适用性已判断；
- 规定的检查分支已执行或明确记录不适用/阻塞；
- 当前阶段产物已生成；
- 阶段状态已写入当前 WZ 游标；
- 有当前阶段测试或验证结果；
- 未把历史 FH 结果当作当前完成证据；
- 未将未知状态伪装为 negative/clean；
- 没有未说明的跳过项。

如果受到权限、登录、审批、服务状态或资料缺失影响，使用：

```text
needs_login
approval_required
blocked
inconclusive
not_applicable
```

不能使用：

```text
complete
no_issue
clean
```

---

## 五、FH 复核协议

FH 只能复核已有 run，不得伪装成当前 WZ 单站测试。

FH 输出每条结论时必须附：

```text
source_run
source_artifact
historical_target
historical_phase
historical_status
current_scope_verified: yes/no/not_checked
recommended_workflow: fh/wz/none
recommended_phase
```

如果需要交给 WZ，必须注明：

```text
handoff_type: historical_lead_only
current_wz_validation_required: true
```

FH 不得把：

```text
历史 candidate
历史 verified_exposure
历史 confirmed
```

直接写入当前 WZ 的：

```text
tested
confirmed
phase complete
```

---

## 六、文件传递建议

### 如果要启动 FH 复核

传递：

```text
用户指定的 run 目录
prompts/配方A_复盘会话.md（或 postrun-review Skill）
```

不要额外传递整个项目源码和全部历史 run。

### 如果要启动 WZ 单站

传递：

```text
当前 engagement 目录
当前目标授权/范围文件
本提示词
```

不要传递：

```text
完整 FH 历史结果
其他目标 run
完整报告草稿
postrun_review 全部 verdict
```

### 如果要把一个 FH 线索交给 WZ

只传递一条或少量明确线索，并显式写：

```text
以下内容只是 historical_lead，不是当前已验证结果。
请在 WZ 当前阶段重新验证，不得跳过任何前置阶段。
```

---

## 七、禁止偷懒的检查清单

开始 WZ 前必须回答：

```text
[ ] 我是否错误读取了 FH 的最终结论？
[ ] 我是否把历史 candidate 当成当前事实？
[ ] 我是否因为历史没有发现就跳过当前阶段？
[ ] 我是否把历史 rejected 当成永久排除？
[ ] 我是否重新核对了当前 scope/hosts/授权？
[ ] 我是否读取了当前 phase 的实际规则？
[ ] 我是否记录了当前阶段未测什么以及为什么？
[ ] 我是否生成了当前 WZ 自己的 phase-history 和 artifacts？
[ ] 我是否更新了正确的 WZ 游标文件？
[ ] 双流目录中我是否确认没有读取 xcx 的 phase_status.miniapp.json？
```

如果其中任一项答案不确定，停止当前阶段，先核对文件和状态。

---

## 八、最终交付格式

### WZ 交付

```text
workflow: wz
engagement:
target:
本次推进的 phase:
实际读取的文件:
明确排除的 FH 文件:
历史线索（如有）:
当前重新验证的事实:
实际测试/分析:
未测试分支及原因:
当前 phase 状态:
写入的 phase-history:
写入的 artifacts:
下一 phase:
是否存在 inconclusive/blocked/needs_login/approval_required:
```

### FH 交付

```text
workflow: fh
source_run:
复核的产物:
candidate/confirmed/rejected/duplicate 统计:
历史结论:
需要 WZ 重新验证的线索:
不应被 WZ 直接继承的结论:
是否修改历史成果: no
```

## 九、绝对结论

```text
FH = 复核历史 run
WZ = 重新推进当前单站
```

除非用户明确要求转交，否则两者禁止混用。

即使用户明确要求转交，也只能传递：

```text
historical_lead
```

不能传递：

```text
current_tested
current_confirmed
current_coverage
```

单站流程必须自己重新建立事实、自己推进阶段、自己写游标、自己写阶段记录、自己留下未测原因。历史复核结果不能成为偷懒依据。
