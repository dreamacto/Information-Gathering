# 无人值守高质量项目改造提示词

你现在负责严格实施项目：

```text
D:\PythonSource\PythonProjects\PythonProject4
```

完整实施规格位于：

```text
D:\PythonSource\PythonProjects\PythonProject4\docs\AI_IMPLEMENTATION_SPEC_SECURITY_COVERAGE_AND_FINDING_QUALITY.md
```

更严格的执行要求位于：

```text
D:\PythonSource\PythonProjects\PythonProject4\prompts\AI整体改造_严格分批逐项验证.md
```

## 一、任务模式：无人值守、质量优先、自动连续推进

操作者接下来可能不在电脑前，也不会及时回复你的问题。你应当在授权范围和项目规则允许的前提下自主推进，不要每完成一个批次就等待操作者确认。

但是，“自主推进”不等于快速批量修改。必须遵循：

```text
慢速实施
→ 每次只处理一个最小可验证子项
→ 立即运行该子项测试
→ 检查 diff、schema、产物和行为
→ 记录 PASS
→ 再处理下一个子项
```

不要为了减少交互次数而：

- 一次修改几十个文件；
- 把多个 Batch 合并修改；
- 等所有代码改完才测试；
- 用静态阅读代替测试；
- 用“应该可以”“理论上完成”代替真实验证；
- 省略失败项；
- 把空模块、TODO、兼容占位或文档描述当作实现。

你的目标是质量和可追溯性，不是速度。宁可只完成一个经过充分验证的子项，也不要完成一批未经验证的伪实现。

## 二、启动时先做只读检查，不要立即大规模编码

开始后先读取：

```text
AGENTS.md
ROE.md
.agents/skills/authorized-pentest-workflow/references/authorization-boundaries.md
docs/AI_IMPLEMENTATION_SPEC_SECURITY_COVERAGE_AND_FINDING_QUALITY.md
prompts/AI整体改造_严格分批逐项验证.md
```

但禁止把整个项目、所有历史 run、所有 Skill、所有 prompt 和全部原始响应一次性读入上下文。必须遵守实施规格第 3 节：

```text
L0：项目边界、授权、scope、审批门、停止条件和当前状态
L1：当前 Batch 所涉及的一个 workflow
L2：当前子项所涉及的 phase、schema、代码、测试和输入产物
L3：只有确有必要时才读取相关历史资料或外部资料
```

如果已经存在，则优先使用：

```text
runtime/policy_snapshot.json
docs/CONTEXT_LOADING_MAP.yaml
docs/RULE_PRECEDENCE.md
src/authorized_assessment/runtime/context_loader.py
```

如果不存在，必须先完成 Batch 0 的上下文治理能力，后续不得继续依赖 AI 随意全文读取。

## 三、不得等待操作者确认；但必须遇到明确阻塞就停

你可以自动进入下一个 Batch，前提是当前 Batch 满足：

```text
当前子项专属测试通过
当前 Batch 测试通过
diff 检查通过
产物/schema 检查通过
没有未解释的失败
没有规则冲突
没有越过授权或审批门
已写入进度和结果记录
```

以下情况必须停在当前子项，不得继续后续实现：

- 专属测试失败；
- 完整离线测试暴露回归；
- schema 与现有产物冲突且未解决；
- 当前 canonical 实现不明确；
- 必需依赖缺失；
- 工具路径或版本无法确认；
- 规则、scope、授权或审批状态冲突；
- 可能改变默认网络行为、速率、并发或审批门；
- 需要用户决定的架构选择；
- 需要下载工具、模板、规则、依赖或外部文件；
- 需要目标网络探测、高风险验证、写操作、弱口令、SQLMap、上传、命令执行、OOB、竞态写入或其他审批门动作；
- 发现范围外资产；
- 服务劣化、WAF 告警、异常流量或其他停止条件。

停下后要继续做离线收尾，不要询问操作者然后空等：

1. 写入 `implementation_blockers.md`；
2. 写入当前 Batch 状态和失败证据；
3. 标记后续受影响 Batch 为 `blocked` 或 `pending`；
4. 运行不依赖阻塞项的只读一致性检查；
5. 结束本轮，不得把 BLOCKED 写成 PASS。

## 四、持久化进度：不能依赖对话记忆

在项目中创建或使用：

```text
implementation_progress.json
implementation_log.md
implementation_blockers.md（只有发生阻塞时创建或更新）
```

建议 `implementation_progress.json` 结构：

```json
{
  "schema_version": "1.0",
  "mode": "unattended_quality_first",
  "current_batch": "batch_0",
  "current_item": "context_loader_contract",
  "completed_items": [],
  "pending_items": [],
  "blocked_items": [],
  "batch_results": [],
  "last_passed_at": null,
  "last_failed_at": null,
  "last_verified_commit_or_tree_hash": null
}
```

每完成一个最小子项就更新一次；每个 Batch 完成后再更新一次。不要等整批或整个项目结束才记录。

如果进程中断，新会话或后续执行必须从 `implementation_progress.json` 的最后一个未完成项继续，不要重复已经 PASS 的子项，也不要跳过未验证项。

## 五、Batch 顺序

必须按顺序执行，不能跳过前置 Batch：

```text
Batch 0：上下文加载、规则优先级、当前状态快照
Batch 1：状态模型、run quality gate、coverage 修复
Batch 2：漏洞成立门、补天规则、finding quality、evidence gate
Batch 3：候选 baseline、固定路径降噪、canonical 去重
Batch 4：工具 registry、runtime inventory、launcher 和 Python 统一
Batch 5：Web/API application mapping 子阶段
Batch 6：统一注入、parser/XXE/反序列化、SSRF
Batch 7：GraphQL、WebSocket、browser boundary
Batch 8：API 版本、shadow API、资源控制、第三方 API
Batch 9：状态机、重放、重复提交、竞态假设
Batch 10：小程序平台登录、token 生命周期、签名重放
Batch 11：小程序本地数据、密码学、包完整性和更新信任
Batch 12：小程序静态/动态端点对账、云函数、对象存储、第三方边界
Batch 13：WebView、Bridge、Deep Link
Batch 14：fh/wz/xcx Skill、prompt、phase、产物和审计同步
Batch 15：历史误报记忆、精度反馈、候选和重跑去重
Batch 16：工具补充、离线白盒和 SBOM
Batch 17：完整离线验收、文档漂移和最终审计
```

每个 Batch 内仍然要拆成最小子项。例如 Batch 0 至少拆成：

```text
0.1 规则优先级和上下文 schema
0.2 CONTEXT_LOADING_MAP
0.3 policy_snapshot 生成/校验
0.4 context_loader
0.5 context_snapshot
0.6 上下文加载测试
0.7 Batch 0 汇总验收
```

一次只做一个子项。

## 六、每个子项的强制执行循环

对每一个子项严格执行下面的循环：

### 1. 读取现状

只读取该子项相关文件，并记录：

```text
现有实现
现有调用方
canonical 文件
兼容 shim
现有 schema
现有测试
输入和输出产物
风险和依赖
```

### 2. 写实施卡片

在 `implementation_log.md` 中记录：

```text
子项编号：
子项名称：
目标：
不做什么：
读取的文件：
明确排除的文件：
将修改的文件：
将新增的文件：
输入产物：
输出产物：
测试命令：
通过标准：
```

### 3. 最小修改

只修改实现该子项所必需的文件。不要顺手重构无关代码，不要在同一个子项中提前实现后续 Batch。

### 4. 立即测试

先运行该子项专属测试，再运行必要的静态检查。例如：

```bash
python -m pytest -q tests/test_context_loader.py
python -m compileall <本项相关模块>
```

不得把未写测试的代码标记为完成。

### 5. 检查行为和 diff

检查：

- 是否真的实现行为，而不是空壳；
- 是否破坏现有调用方；
- 是否引入未登记依赖；
- 是否改变默认网络请求；
- 是否改变速率、并发或审批门；
- 是否读取或输出敏感数据；
- 是否新增了不在 schema 中的状态；
- 是否需要同步 canonical Skill、镜像、manifest 或 launcher。

### 6. 记录结果

只有以下都满足才能写 `PASS`：

```text
专属测试通过
行为符合目标
负例测试通过
schema/产物符合契约
diff 没有无关修改
没有未解释警告
没有违反边界
```

否则写 `FAIL` 或 `BLOCKED`，停在当前子项。

### 7. 再进入下一子项

只有当前子项 PASS，才能执行下一个子项；只有当前 Batch 的所有子项 PASS，才能执行下一个 Batch。

## 七、每个 Batch 结束时自动做汇总验收

不需要等待操作者确认，但必须自动运行：

1. 当前 Batch 全部专属测试；
2. 当前 Batch 相关的已有回归测试；
3. schema/contract 校验；
4. `git diff --check`；
5. 当前 Batch 的文档和路径检查；
6. 当前 Batch 的敏感数据排除检查；
7. 必要时运行对应的 drift/manifest 检查。

Batch 只能标记为：

```text
PASS
FAIL
BLOCKED
```

如果是 `PARTIAL`，只能作为说明文字，不能作为允许进入下一批的状态；必须同时有明确的 pending 或 blocked 子项。

## 八、漏洞判断和误报控制不可放宽

任何候选都必须先分类：

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

只有以下五门全部通过，才能使用 `confirmed`：

```text
授权门
可触达门
可复现门
安全影响门
证据门
```

以下不能直接称为漏洞：

- Banner/版本；
- 固定路径 200；
- 403/404/500；
- 单次 timeout；
- 登录页；
- 泛化堆栈；
- 反射但不可执行；
- 前端隐藏按钮；
- 模板符号、eval、XML parser 或疑似 sink；
- JWT 可以解码；
- 过期 key；
- 内网主机名；
- 单一产品指纹；
- 公开 API 文档；
- 用户访问自己的对象；
- 没有敏感字段的额外返回；
- 未经人工验证的 AI 结果。

补天和演练规则必须分开记录：

```text
finding_class: generic_vulnerability | event_vulnerability
platform_severity: high | medium | low | not_collectible
exercise_result_class: access | boundary | data | business_impact | signal_only
submission_eligibility: eligible | manual_review_required | deprioritized | ignored | duplicate
```

未人工验证的 AI 候选不得作为正式有效漏洞提交。

## 十、工具、依赖和网络行为纪律

- 不得自动下载安装工具、模板、规则、浏览器、依赖或外部资料；
- 不得对目标发起未授权网络探测；
- 不得把新增工具直接接入默认主链而跳过轻量 registry、实际路径/版本检查和测试；
- 不得把旧式专项 POC、弱口令、SQLMap、上传、命令执行、竞态写入或 OOB 变成默认自动动作；
- 不得关闭 TLS、范围校验或速率控制；
- Afrog/Nuclei 模板必须固定使用本地版本，禁止自更新；
- 工具不存在时必须标记 `unavailable`，不得假装可用；
- 任何网络行为变化必须在 Batch 报告中明确列出；
- 授权范围内公开的 JS、CSS、Source Map、公开配置和公开文档，可按低速只读 GET 自动获取用于分析；如果公开资源包含凭证、token、密码或 AppSecret，不得复制到普通日志、报告、prompt、ledger 或交接内容。

无人值守敏感数据规则：

- 无人值守模式下，AI 不得自动取得任何敏感证明样本；
- 只有经操作者允许并在线明确触发（允许后可由 AI 运行）、目标已授权、漏洞成立门已满足，且请求本身已由服务端限定字段和数量时，才允许取得 3–5 条最小必要的未脱敏代表性数据；取得后立即停止；如果响应会返回全集、超过 5 条或只能先取全集再本地挑样本，必须停止并记录 `sample_bound_unavailable`；
- 不得全量查询、批量分页、数据库 dump、heapdump 下载、完整敏感文件下载、完整 HAR 导出、批量用户/租户遍历或自动循环取样；
- 截图、录屏和最终成果证据由操作者自行完成；AI 不自动截图、生成截图队列、生成 evidence_index 或审计操作者截图；
- AI 不得因为缺少 evidence_ref、截图或证据文件而删除、移动、覆盖、降级或重命名成果，只能标记 `waiting_for_operator`。

工具登记采用个人项目的轻量模式，不要实施完整供应链审计。`tools/tool_registry.json` 每个工具默认只登记：

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

`source_url`、`release_date`、`sha256` 等可以作为可选备注，但不能因为缺少这些字段阻塞普通只读流程，也不要为了填写这些字段自动联网查询或下载文件。

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

这些行为由现有流程、`ROE.md`、`policy_engine.py`、`tool_strategy.json` 和阶段代码统一控制，不要创建第二套工具级审批规则。工具 registry 的 `status` 只表示本地路径/版本是否可解析，不表示授权状态。状态使用：

```text
active
unavailable
hold
retired
```

高风险动作是否需要审批，仍按现有流程策略执行，但不在工具白名单重复登记。高风险工具如实际执行，run 中只需按现有运行记录记录实际命令/阶段、工具名称和版本，不要新增一套审批清单。

- 默认不读取全量 `runs/`；
- 默认不读取报告草稿、原始响应和完整截图；
- 默认不读取 `auth_sessions.local.json`、`sessions.jsonl` 或任何凭证文件；
- 历史数据只能用于 review、planning、precision_analysis；
- 历史事实、派生模式和当前事实必须分栏；
- 历史 run 不能证明当前目标状态；
- 生成或更新 `context_snapshot`，记录 loaded/excluded sources 和 source hashes；
- 如果上下文加载机制尚未实现，优先完成 Batch 0，不得通过全文读取绕过。

## 十一、代码和文档同步纪律

每个真正新增的 phase 必须同时具备：

```text
初始化器
phase_status 支持
审计器支持
tool_strategy 条目
产物路径
schema/contract
正例测试
负例测试
fh/wz/xcx 复核支持
run_health 统计
```

只改测试矩阵或 Skill 文档，不算阶段完成。

`.agents/skills/` 是 canonical；`.claude/skills/` 和 `.opencode/skills/` 是镜像。修改后必须运行：

```bash
python scripts/check_skill_drift.py
```

`AGENT_MANIFEST.md` 必须由生成器更新，不得手工伪造。

## 十二、最终验收条件

所有 Batch 都必须 PASS，且没有未解释的 FAIL/BLOCKED，才能标记整体完成。

最终运行：

```bash
python -m pytest -q
python scripts/verify_offline.py --json
python scripts/maintenance/validate_run_contracts.py
python scripts/maintenance/validate_finding_quality.py
python scripts/check_doc_drift.py
python scripts/check_skill_drift.py
git diff --check
```

如果命令不存在：

- 不能跳过；
- 不能伪造通过；
- 必须把缺失入口写入阻塞记录；
- 如果该命令属于当前 Batch 的必需验收，则当前 Batch 必须 BLOCKED；
- 如果属于最终验收，则整体不能标记 PASS。

## 十三、最终报告要求

最终交付必须真实报告：

```text
总体状态：PASS / PARTIAL / BLOCKED
PASS 的 Batch：
未完成的 Batch：
每个 Batch 的实际修改文件：
每个 Batch 的测试命令和真实结果：
失败测试：
阻塞原因：
仍为 unavailable/conditional/hold 的工具：
仍为 blocked/not_applicable/inconclusive 的漏洞分支：
新增产物和 schema：
是否改变网络请求：
是否改变速率/并发：
是否改变审批门：
上下文加载统计：
context_snapshot 路径：
文档、Skill、manifest、contract 检查结果：
未解决问题：
```

禁止用以下措辞掩盖缺口：

```text
基本完成
大致完成
核心已完成
理论上支持
后续可补
测试应该没问题
```

除非所有必需测试真实通过，否则必须明确写 `PARTIAL` 或 `BLOCKED`。

## 十四、最后的自动执行指令

现在开始执行，但遵循以下顺序：

```text
1. 读取最小 L0 上下文和当前项目状态；
2. 检查 implementation_progress.json；
3. 如果没有进度，从 Batch 0 的第一个未完成子项开始；
4. 如果已有 PASS，从最后一个未完成子项继续；
5. 每次只做一个最小可验证子项；
6. 测试通过、diff 检查通过、产物检查通过后记录 PASS；
7. 自动继续下一个子项，不等待操作者；
8. 当前 Batch 全部 PASS 后自动进入下一个 Batch；
9. 任何失败、冲突、缺依赖、范围问题或审批门问题立即停在当前项并落盘；
10. 最终真实报告，不夸大完成度。
```

再次强调：

> **操作者不在电脑前，不代表你可以省略验证。你可以自动继续，但不能跳过；可以无人值守，但不能无记录；可以慢慢做，但不能用未验证结果换取进度。每一项先验证成功，再进行下一项。**
