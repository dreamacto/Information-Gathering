# 项目改造交接总览（压缩版）

项目目录：

```text
D:\PythonSource\PythonProjects\PythonProject4
```

## 当前背景

本项目是授权安全评估工作台，包含 Web/API/小程序流程、候选筛选、复核、报告和本地运行工具。此前已完成项目结构、历史 run、三类流程、工具和权威资料的审计，并生成了详细实施规格。

## 新会话必须先读取

按以下顺序读取，禁止一次性读取全项目：

```text
AGENTS.md
ROE.md
implementation_progress.json（如果存在）
implementation_log.md（如果存在）
docs/AI_IMPLEMENTATION_SPEC_SECURITY_COVERAGE_AND_FINDING_QUALITY.md（只读当前任务相关章节）
prompts/AI整体改造_无人值守高质量执行.md
prompts/AI整体改造_严格分批逐项验证.md
```

如果存在以下上下文治理文件，也优先读取：

```text
runtime/policy_snapshot.json
docs/CONTEXT_LOADING_MAP.yaml
docs/RULE_PRECEDENCE.md
src/authorized_assessment/runtime/context_loader.py
```

不要全文读取全部 Skill、全部 prompt、全部历史 run、全部报告、原始响应、HAR 或凭证文件。按照当前 Batch 和 workflow 按需读取。

## 已经确定的改造方向

### 1. 必须逐项实施和验证

整个改造分为 Batch 0 到 Batch 17。每个 Batch 内再拆成最小子项：

```text
读取现状
→ 明确本项目标和验收标准
→ 最小修改
→ 增加正例/负例测试
→ 运行本项测试
→ 检查 diff、schema、产物
→ 记录 PASS/FAIL/BLOCKED
→ 只有 PASS 才能进入下一项
```

禁止一次改几十个文件后统一测试；失败必须停在当前项并修复或记录阻塞。

### 2. 三类流程

保留 Web `wz`、小程序 `xcx` 和复核 `fh` 的主生命周期，不因为减少自动证据而删除基本状态阶段。新增漏洞能力优先作为可审计子阶段，不把所有漏洞类型膨胀成顶级阶段。

### 3. 漏洞结论门

严格区分：

```text
signal
candidate
needs_manual_validation
confirmed
inconclusive
blocked
rejected
duplicate
```

只有以下五门全部满足才可使用 `confirmed`：

```text
授权门
可触达门
可复现门
安全影响门
证据/人工确认门
```

Banner、版本号、固定路径 200、403/404/500、一次异常、反射但不可执行、静态 sink、公开文档、JWT 可解码、过期 key、单一产品指纹等不能直接称漏洞。

### 4. 补天与演练规则

同时维护：

```text
finding_class: generic_vulnerability | event_vulnerability
platform_severity: high | medium | low | not_collectible
exercise_result_class: access | boundary | data | business_impact | signal_only
submission_eligibility: eligible | manual_review_required | deprioritized | ignored | duplicate
```

同一接口多个 SQL 注入参数合并为一处；同系统同类型超过三个要合并或停止拆分；通用产品同根因不能刷成多个事件漏洞；未经人工验证的 AI 候选不得作为正式有效漏洞提交。

### 5. 敏感数据证明规则（方案 A，当前硬规则）

默认不自动下载、导出、批量读取或留存敏感数据。

仅在以下条件同时满足时，才允许取得业务数据证明样本：

- 目标已授权；
- 漏洞已满足成立门；
- 操作者在线明确触发和控制；
- 请求是只读；
- 请求本身已经由服务端限制字段和数量；
- 最多取得 3–5 条最小必要、未脱敏的代表性业务数据；
- 取得后立即停止。

严格禁止：

```text
先返回全集再本地挑 3–5 条
全量查询
批量分页
数据库 dump
heapdump 下载
完整敏感文件下载
完整 HAR 导出
批量用户/租户遍历
自动循环取样
```

如果服务端不支持字段/数量限制、返回全集或超过 5 条，立即停止并记录：

```text
sample_bound_unavailable
```

Cookie、Token、Authorization、session_key、AppSecret、密码等凭证类秘密仍不得进入普通日志、报告、prompt、ledger、git 或交接内容。

无人值守模式不能自动取得上述 3–5 条敏感样本，只能留下操作者人工复现待办。

授权范围内公开 JS、CSS、Source Map、公开配置和公开文档，可以低速只读获取用于分析；其中出现的凭证或秘密不得复制到普通产物。

截图、录屏和最终成果证据由操作者自行完成。AI 不自动截图、不生成截图队列、不审计操作者截图，也不得因缺少截图或 evidence_ref 删除、移动、覆盖或降级成果。

### 6. 工具登记采用轻量模式

工具白名单只需要：

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

状态：

```text
active
unavailable
hold
retired
```

不在工具白名单重复登记审批、速率、并发、只读或证据字段；这些仍由 `ROE.md`、`policy_engine.py`、`tool_strategy.json` 和阶段代码控制。哈希、来源、发布日期等可选，不得因此阻塞普通流程或自动联网下载。

Afrog/Nuclei 使用本地固定版本，禁止自更新；不存在的工具必须标记 `unavailable`。

## 之前已修改的规则文件

当前工作区已经包含以下规则更新：

```text
AGENTS.md
ROE.md
```

它们已写入方案 A 的 3–5 条只读、服务端限量证明样本规则。

方案和提示词文件：

```text
docs/AI_IMPLEMENTATION_SPEC_SECURITY_COVERAGE_AND_FINDING_QUALITY.md
prompts/AI整体改造_严格分批逐项验证.md
prompts/AI整体改造_无人值守高质量执行.md
```

以当前工作区版本为准，不要使用旧会话中缓存的附件版本。

## 复核重点

历史审计发现：

- 44 个可汇总 run 的加权候选误报率约 95.36%；
- API 候选确认率约 1.49%；
- 失败 run、WAF/限速和 coverage 指标可能被错误解释为“未发现”；
- 重复 run 缺少清晰的父子、重试和配置关联；
- GraphQL、WebSocket、SSRF、SSTI、XXE/解析器、NoSQL、资源控制、API 版本、第三方 API、小程序认证/云能力等需要更明确的可执行子阶段。

## 新会话工作方式

如果用户只是让你“继续改造”，不要重新审计全部项目，也不要重新讨论已经确定的规则。先读取 `implementation_progress.json`，从最后一个未完成子项继续。

如果 Batch 0–17 都已完成，才进入统一检查模式；不要自动删除历史成果、run、engagement、报告或人工文件。

最终报告必须列出：

```text
已通过 Batch
失败/阻塞 Batch
实际修改文件
实际新增文件
每项测试命令和真实结果
仍未实现的阶段
仍 unavailable 的工具
是否改变网络行为/速率/并发/审批
是否存在 schema/Skill/prompt/manifest 漂移
```
