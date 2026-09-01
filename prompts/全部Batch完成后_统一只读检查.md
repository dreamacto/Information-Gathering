# 全部 Batch 完成后的统一检查提示词

项目目录：

```text
D:\PythonSource\PythonProjects\PythonProject4
```

请对本项目已经完成的 Batch 0–17 做一次**只读、完整、严格的最终检查**。不要修改代码、配置、规则、历史 run、engagement、报告或人工证据文件；不要删除、移动、覆盖或清理任何成果。

先读取：

```text
AGENTS.md
ROE.md
implementation_progress.json
implementation_log.md
implementation_blockers.md（如果存在）
docs/IMPLEMENTATION_HANDOFF_COMPACT.md
docs/AI_IMPLEMENTATION_SPEC_SECURITY_COVERAGE_AND_FINDING_QUALITY.md（按检查项按需读取）
prompts/AI整体改造_无人值守高质量执行.md
```

不要全文读取全部历史 run、原始响应、HAR、凭证文件或完整证据目录。历史检查只读摘要、索引和必要的结构化文件；不要输出 Cookie、Token、Authorization、session_key、AppSecret、密码或敏感数据原文。

## 检查目标

判断 Batch 0–17 是否真的完成，而不是只改了文档、创建了空模块或留下 TODO。检查：

1. `implementation_progress.json` 中的 Batch/子项状态是否真实；
2. 每个 PASS 是否有对应代码、schema、产物和测试；
3. 是否有 FAIL/BLOCKED 被错误标为 PASS；
4. 是否存在空模块、TODO、伪接口或未接线功能；
5. Web/wz、xcx、小程序、fh/postrun 的阶段、状态、产物和审计器是否一致；
6. GraphQL、WebSocket、SSRF、注入、XXE、解析器/反序列化、文件路径、浏览器边界、API 版本/资源/第三方 API、业务状态机等是否真正接线；
7. 上下文加载是否按 task/workflow/phase 运行，是否存在 `context_loader`、policy snapshot、加载白名单和快照；
8. signal/candidate/confirmed 是否严格区分；
9. 漏洞五项成立门是否真正生效；
10. 补天 generic/event、high/medium/low、接口合并和人工验证门是否一致；
11. 3–5 条敏感业务数据证明规则是否正确：只读、经操作者允许并在线明确触发（允许后可由 AI 运行）、漏洞已确认、服务端先限字段/数量；服务端返回全集或超过 5 条时是否停止并记录 `sample_bound_unavailable`；
12. 无人值守模式是否禁止自动取得敏感证明样本；
13. 公开 JS/CSS/Source Map/公开配置是否允许授权范围内低速只读获取；
14. AI 是否已停止自动截图、截图队列、evidence_index 和操作者截图审计；
15. 是否会因为缺少 evidence_ref/截图而删除、移动、覆盖或降级成果；
16. 工具白名单是否采用轻量字段：path/version/status 等，不要要求工具级审批字段、完整 hash 或供应链审计；
17. 工具审批是否仍由现有流程和 `tool_strategy.json` 控制，而不是重复制造第二套审批规则；
18. Afrog/Nuclei 是否禁止自动更新；
19. 历史候选是否去重、误报反馈是否回灌、重跑是否有父子/重试/输入关联；
20. launcher、Python 运行时、schema、Skill 镜像和 manifest 是否一致。

## 检查方式

按以下顺序执行，不要跳过：

### A. 进度真实性

逐个读取实现进度中标为 PASS 的 Batch 和子项，核对：

```text
实际修改文件
实际新增文件
测试命令
测试输出
产物路径
schema/contract
```

发现只有文档、没有代码或测试的，标记为 `FAIL`，不要替用户修复。

### B. 代码和接线

只读检查关键入口和调用关系：

```text
gov_exercise_runner.py
run_lifecycle.py
src/authorized_assessment/
.agents/skills/wz/
.agents/skills/xcx/
.agents/skills/fh/
contracts/
tool_strategy.json
```

确认新增模块不是未调用的孤立文件，阶段不是只在 Markdown 中声明。

### C. 测试和契约

在确认用户允许运行本地检查的前提下，运行：

```bash
python -m pytest -q
python scripts/verify_offline.py --json
python scripts/check_doc_drift.py
python scripts/check_skill_drift.py
git diff --check
```

如果某个命令不存在，只读记录 `missing_check`，不要创建文件、不要修改代码、不要把缺失写成通过。

### D. 安全规则一致性

检查以下规则是否互相矛盾：

```text
AGENTS.md
ROE.md
实施总规格
两个改造提示词
当前 Skill
```

重点检查：

- 3–5 条样本是否必须只读和服务端先限量；
- 是否禁止先取全集再本地挑样本；
- 是否区分业务数据样本和凭证类秘密；
- 无人值守是否禁止敏感样本；
- 公开静态资源是否能按规则获取；
- 截图是否由操作者自行完成；
- AI 是否仍然自动生成/审计证据文件；
- 失败 run 是否禁止形成阴性结论；
- 规则冲突是否记录而非静默选择。

### E. 不得改动成果

最终检查期间严禁：

```text
删除文件
移动文件
覆盖历史 run
清理 evidence/
重命名人工证据
重新生成报告
重跑目标网络流程
读取凭证文件
输出敏感数据
```

## 4. 必须逐个 Batch 检查，不能用全量 pytest 代替

不能只运行一次全量测试，然后声称 Batch 0–17 全部通过。必须为每个 Batch 建立一条独立验收记录：

```text
batch_id
batch_name
progress_status
actual_files_present
implementation_present
wiring_present
schema_present
artifacts_present
tests_present
专属测试命令
专属测试真实结果
回归测试命令
回归测试真实结果
negative_cases_checked
diff_checked
contract_checked
doc_sync_checked
result: PASS | FAIL | BLOCKED | UNVERIFIED
finding
```

### 每个 Batch 的统一检查顺序

对 Batch 0 到 Batch 17，严格按编号逐个执行：

```text
1. 读取该 Batch 的 progress/log 记录；
2. 读取该 Batch 的实施卡片和实际修改文件；
3. 检查每个声明新增文件是否存在且不是空壳；
4. 检查调用方和入口，确认不是孤立模块；
5. 检查该 Batch 对应 schema/contract；
6. 检查该 Batch 对应产物和字段；
7. 检查该 Batch 对应正例、负例和阻塞例测试；
8. 运行该 Batch 专属测试；
9. 运行该 Batch 相关回归测试；
10. 运行 `git diff --check` 或等价文本检查；
11. 检查是否改变默认网络、速率、并发、审批或数据处理行为；
12. 将该 Batch 标记为 PASS、FAIL、BLOCKED 或 UNVERIFIED；
13. 只有当前 Batch PASS，才能检查下一个 Batch。
```

如果 Batch 的专属测试、代码接线、schema、产物或真实结果缺失，该 Batch 不能标记 PASS。全量 pytest 通过只能证明测试集合当前通过，不能替代单个 Batch 的完成证据。

## 5. Batch 0–17 逐 Batch 验收清单

### Batch 0：上下文加载、规则优先级、当前状态快照

必须检查：

```text
runtime/policy_snapshot.json
 docs/CONTEXT_LOADING_MAP.yaml
docs/RULE_PRECEDENCE.md
src/authorized_assessment/runtime/context_loader.py
src/authorized_assessment/runtime/context_snapshot.py
contracts/context_snapshot_schema.json
```

必须验证：

- L0/L1/L2/L3 分层加载真实生效；
- 当前 Web phase 不加载无关小程序全量规则；
- 当前小程序 phase 不加载全量历史 run；
- 凭证文件、原始响应和完整截图默认排除；
- `include_history=False` 不读取历史敏感原文；
- 缺 L0、规则冲突、source hash 变化会正确处理；
- context snapshot 能恢复 workflow、phase、当前事实和排除来源。

必须有专属测试：

```bash
python -m pytest -q tests/test_context_loader.py tests/test_rule_precedence.py tests/test_context_snapshot.py
```

### Batch 1：状态模型、run quality gate、coverage 修复

必须检查：

```text
run_lifecycle.py
src/authorized_assessment/quality/
src/authorized_assessment/reporting/run_health.py
contracts/workflow_schema.json
contracts/run_quality_schema.json
```

必须验证：

- coverage 分母为唯一 in-scope target；
- coverage 被限制在 0–1；
- transport error、DNS error、timeout、WAF、429/5xx 分开；
- coverage < 0.90、ok ratio < 0.50、skip ratio > 0.20 等条件触发 INCONCLUSIVE；
- INCONCLUSIVE 禁止阴性结论；
- `review_aggregated` 不仅依据 pending 数量；
- `Path` 导入问题已修复。

专属测试：

```bash
python -m pytest -q tests/test_run_quality_gate.py tests/test_run_health.py tests/test_run_lifecycle.py
```

### Batch 2：漏洞成立门、补天规则、finding quality、evidence gate

必须检查：

```text
src/authorized_assessment/quality/finding_quality_gate.py
src/authorized_assessment/reporting/evidence_gate.py
contracts/finding_evidence_schema.json
contracts/finding_quality_schema.json（如果已创建）
```

必须验证：

- signal/candidate/needs_manual_validation/confirmed/rejected 等状态不混淆；
- confirmed 必须满足授权、可触达、可复现、安全影响和人工确认门；
- generic/event 分类存在；
- platform severity 与 exercise result 分离；
- Banner、固定路径、反射、静态 sink、单次异常不能直接 confirmed；
- 未人工验证的 AI 候选不能进入正式有效漏洞；
- 缺少人工证据不会删除或覆盖成果，而是等待操作者；
- 凭证类秘密仍禁止进入普通产物。

专属测试：

```bash
python -m pytest -q tests/test_finding_quality_gate.py tests/test_evidence_gate.py tests/test_validate_finding_quality.py tests/test_validate_run_contracts.py
```

### Batch 3：候选 baseline、固定路径降噪、canonical 去重

必须检查：

```text
src/authorized_assessment/triage/response_baseline.py
src/authorized_assessment/triage/canonical_keys.py
src/authorized_assessment/triage/candidate_dedup.py
readonly_endpoint_confirm.py
deep_readonly_triage.py
```

必须验证：

- 固定路径默认只产生 signal；
- 通用 200、登录页、CDN/WAF 页、统一错误页会被识别；
- API 候选按 host/path/method/parameter/source 去重；
- 同一 SQL 注入接口多个参数合并；
- 重复 run 不重复制造 finding；
- 差异、语义和可复现性不足时不能升级。

专属测试：

```bash
python -m pytest -q tests/test_response_baseline.py tests/test_canonical_keys.py tests/test_candidate_dedup.py tests/test_input_testing_pipeline.py
```

### Batch 4：工具 registry、runtime inventory、launcher 和 Python 统一

必须检查：

```text
tools/tool_registry.json
contracts/tool_capability_schema.json
scripts/maintenance/rebuild_tool_inventory.py
gov_exercise_config.json
launchers/*.bat
runtime_inventory 相关代码
```

必须验证：

- registry 采用轻量字段：path/version/status 等；
- 不重复登记工具级审批、速率和并发规则；
- 不存在的工具标记 unavailable；
- launcher Python 选择顺序一致；
- runtime inventory 记录实际解释器和版本；
- Afrog/Nuclei 不自动更新；
- 工具 registry 不要求完整 hash 或供应链审计；
- `verify_offline.py` 使用实际启动它的解释器，pytest 不可用时明确失败。

专属测试/检查：

```bash
python -m pytest -q tests/test_tool_registry.py tests/test_runtime_inventory.py tests/test_launcher_python_unification.py
python scripts/maintenance/rebuild_tool_inventory.py --check
```

### Batch 5：Web/API application mapping 子阶段

必须检查：

```text
.agents/skills/wz/scripts/init_engagement.py
.agents/skills/wz/scripts/audit_engagement.py
.agents/skills/wz/references/workflow.md
.agents/skills/wz/references/test-matrix.md
tool_strategy.json
```

必须验证：

- GraphQL、WebSocket、文件面、认证面、Webhook 五个子阶段有初始化/审计/策略事实；
- 每个子阶段有 tested/not_applicable/blocked/inconclusive 状态；
- `not_applicable` 有 reason；
- 新增子阶段不只是 Markdown 声明；
- `.agents` canonical 与镜像同步。

专属测试：

```bash
python -m pytest -q tests/test_wz_application_mapping.py tests/test_application_mapping_strategy.py tests/test_api_testing_orchestration_strategy.py
```

### Batch 6：统一注入、parser/XXE/反序列化、SSRF

必须检查：

```text
src/authorized_assessment/triage/injection_candidates.py
src/authorized_assessment/triage/parser_deserialization.py
src/authorized_assessment/triage/ssrf_candidate_screening.py
contracts/injection_candidate_schema.json
tool_strategy.json
```

必须验证：

- SQL/NoSQL/LDAP/XPath/SSTI/模板/命令/路径/XXE/解析器/反序列化等类别可区分；
- category_status、applicability_counts、status_counts 不混淆；
- tested_count 语义明确；
- not_applicable 计数合理；
- XXE 只在真实 XML 解析面适用；
- SSRF 默认 queue-only，不自动 POST、不访问内网、不用公共 OAST；
- 服务端返回敏感数据时遵守 3–5 条只读服务端限量规则；
- 超过 5 条、返回全集或无法限量时记录 `sample_bound_unavailable`。

专属测试：

```bash
python -m pytest -q tests/test_injection_candidates.py tests/test_parser_deserialization.py tests/test_ssrf_candidate_screening.py
```

### Batch 7：GraphQL、WebSocket、browser boundary

必须检查：

```text
src/authorized_assessment/triage/graphql_inventory.py
src/authorized_assessment/triage/graphql_review.py
src/authorized_assessment/triage/websocket_inventory.py
src/authorized_assessment/triage/websocket_review.py
src/authorized_assessment/triage/browser_boundary.py
```

必须验证：

- GraphQL schema、operation、字段授权、alias、batching、depth 和错误泄露有状态；
- WebSocket 握手、Origin、channel、消息 schema、重放和断线状态有状态；
- CORS/CSRF/cache/postMessage 有统一产物；
- 观察到配置问题不自动等于漏洞；
- 顶层编排不会重复执行子阶段；
- 测试不会发起高并发或未经授权的真实请求。

专属测试：

```bash
python -m pytest -q tests/test_graphql_inventory.py tests/test_graphql_review.py tests/test_websocket_inventory.py tests/test_websocket_review.py tests/test_browser_boundary.py
```

### Batch 8：API 版本、shadow API、资源消耗、第三方 API

必须检查：

```text
src/authorized_assessment/analysis/api_inventory_reconcile.py
src/authorized_assessment/triage/api_resource_controls.py
src/authorized_assessment/triage/third_party_api_review.py
artifacts/api/
```

必须验证：

- 版本登记、shadow marker、API 对账六状态和优先级进入正式 schema；
- A/B/C 真实来源与 D/E 猜测来源分开；
- method > content_type > version 优先级一致；
- 资源控制观察不自动升级；
- NO_LOAD_VALIDATION_RULE 阻止高负载验证；
- 第三方 webhook 缺防护不直接 confirmed，必须有实际接受/重放证据；
- 四件 API 产物表头和确定性序列化正确；
- CONTEXT_LOADING_MAP 覆盖实际消费模块；
- 环境编码修复不依赖 PYTHONUTF8 才能工作；
- 不重复执行 GraphQL/WebSocket 子阶段。

专属测试：

```bash
python -m pytest -q tests/test_api_inventory_reconcile.py tests/test_api_resource_controls.py tests/test_third_party_api_review.py tests/test_context_loading_map_batch8.py tests/test_validate_run_contracts.py
```

### Batch 9：业务状态机、重放、重复提交、竞态假设

必须检查：

```text
logic-workshop 相关代码
race_triage.py
race_config 相关 schema
business_logic 相关 phase 接线
```

必须验证：

- 正常状态序列、前置条件、动作和结果被结构化记录；
- replay/duplicate 不是单次异常；
- race hypothesis 与 race validation 分离；
- 竞态写入需要现有审批门和清理计划；
- 未授权或未批准的写操作不会被测试；
- 业务影响必须是服务端状态/权限/次数/金额等实际变化，不是前端显示。

专属测试：

```bash
python -m pytest -q tests/test_state_machine_reconstruction.py tests/test_replay_duplicate_screening.py tests/test_race_hypothesis.py tests/test_race_triage.py
```

### Batch 10：小程序平台登录、token 生命周期、签名重放

必须检查：

```text
src/authorized_assessment/miniapp/platform_login_exchange.py
src/authorized_assessment/miniapp/session_token_lifecycle.py
src/authorized_assessment/miniapp/signature_replay_review.py
artifacts/miniapp/auth/
```

必须验证：

- login code 一次性、过期、AppID 绑定有状态；
- session_key 不进入普通产物；
- token 轮换、注销、旧 token、多设备和租户绑定有检查；
- nonce/timestamp/签名规范化/重放分开；
- 凭证值不进入日志、报告、prompt、ledger 或交接。

专属测试：

```bash
python -m pytest -q tests/test_miniapp_auth_lifecycle.py tests/test_miniapp_auth_strategy.py tests/test_wechat_auth_handoff.py
```

### Batch 11：小程序本地数据、密码学、包完整性和更新信任

必须检查：

```text
src/authorized_assessment/miniapp/local_data_exposure.py
src/authorized_assessment/miniapp/crypto_secret_review.py
src/authorized_assessment/miniapp/package_integrity_update.py
artifacts/miniapp/storage/
artifacts/miniapp/crypto/
artifacts/miniapp/package/
```

必须验证：

- token、日志、缓存、剪贴板、截图和临时文件的状态分开；
- 疑似密钥不能直接定性为有效密钥；
- 自定义加密、弱随机数、密钥派生有状态；
- 包版本、子包、插件、Source Map、环境切换和更新地址有对账；
- 不做重打包、篡改或设备攻击。

专属测试：

```bash
python -m pytest -q tests/test_miniapp_storage_crypto.py tests/test_package_integrity_update.py
```

### Batch 12：小程序静态/动态端点对账、云函数、对象存储、第三方边界

必须检查：

```text
src/authorized_assessment/miniapp/static_dynamic_reconciliation.py
src/authorized_assessment/miniapp/cloud_function_review.py
src/authorized_assessment/miniapp/cloud_storage_review.py
src/authorized_assessment/miniapp/third_party_boundary_review.py
artifacts/miniapp/reconciliation/
artifacts/miniapp/cloud/
```

必须验证：

- static_only/dynamic_only/both_seen/feature_gated/stale/version_specific 等状态正确；
- 云函数匿名调用、参数权限、云环境、对象存储 ACL、签名 URL 和跨对象访问有状态；
- 第三方/平台共享资产不误归为自有资产；
- 批量读取、写入、支付和敏感对象访问仍受边界控制。

专属测试：

```bash
python -m pytest -q tests/test_static_dynamic_reconciliation.py tests/test_miniapp_cloud_review.py tests/test_third_party_api_review.py
```

### Batch 13：WebView、Bridge、Deep Link

必须检查：

```text
现有 webview_bridge_links 阶段
artifacts/miniapp/webview/
```

必须验证：

- WebView origin、Bridge method、Deep Link 参数有独立产物；
- postMessage、scheme、Cookie/token 共享边界可审计；
- 仅有 URL 或参数存在不能直接称漏洞；
- 只有造成跨域读取、越权、token 暴露或外部控制才升级。

专属测试：

```bash
python -m pytest -q tests/test_xcx_webview_artifacts.py
```

说明：该测试同时覆盖 webview origin、bridge method 和 deep-link 敏感参数；deep-link 不另列不存在的测试文件，不重复计数。

### Batch 14：fh/wz/xcx Skill、prompt、phase、产物和审计同步

必须检查：

```text
.agents/skills/
.claude/skills/
.opencode/skills/
prompts/
tool_strategy.json
AGENT_MANIFEST.md
```

必须验证：

- `.agents/skills` 是 canonical；
- `.claude`/`.opencode` 与 canonical 无漂移；
- 新 phase 同时有初始化器、审计器、策略、产物、schema 和测试；
- prompt 不要求全文读取无关内容；
- 不自动截图、生成 screenshot queue 或审计操作者截图；
- 不因缺 evidence_ref 删除/移动/覆盖成果；
- `AGENT_MANIFEST.md` 由生成器生成且与策略一致。

专属检查：

```bash
python -m pytest -q tests/test_fh_review_dispatch.py tests/test_skill_sync.py tests/test_manifest_generation.py
python scripts/check_skill_drift.py
```

### Batch 15：历史误报记忆、精度反馈、候选和重跑去重

必须检查：

```text
knowledge_base/false_positive_patterns.jsonl
knowledge_base/fingerprint_precision.jsonl
knowledge_base/endpoint_behavior_profiles.jsonl
src/authorized_assessment/analysis/review_feedback_ingest.py
src/authorized_assessment/analysis/precision_model.py
重跑生命周期相关代码
```

必须验证：

- confirmed/rejected/duplicate 反馈能回灌；
- 通用 200、登录页、WAF/CDN 和固定路径误报可降权；
- parent_run_id、attempt_no、retry_of、config_hash、input_hash 有实际写入；
- 同一目标/phase/config/input 的重复 run 可识别；
- 历史数据不被误当当前事实；
- 不删除历史成果。

专属测试：

```bash
python -m pytest -q tests/test_review_feedback_ingest.py tests/test_precision_model.py tests/test_run_dedup.py
```

### Batch 16：工具补充、离线白盒和 SBOM

必须检查：

```text
ffuf 接线
Dalfox 或 XSStrike 接线
subfinder/dnsx 接线
Semgrep 或 CodeQL 接线
离线 SBOM/依赖审计接线
tools/tool_registry.json
```

必须验证：

- 新工具实际存在才可标 active，否则 unavailable；
- ffuf 不默认递归、不高并发，只产生候选；
- Dalfox/XSStrike 只处理单候选 XSS；
- subfinder/dnsx 为被动/已知候选模式；
- Semgrep/CodeQL 不联网拉规则；
- SBOM 无 advisory 数据时不伪造漏洞；
- 新工具没有绕过现有流程控制。

专属测试：

```bash
python -m pytest -q tests/test_ffuf_directory_candidates.py tests/test_single_candidate_xss_validation.py tests/test_passive_subdomain_candidates.py tests/test_static_analysis_signals.py tests/test_sbom_inventory.py tests/test_tool_registry.py
python scripts/maintenance/rebuild_tool_inventory.py --check
```

### Batch 17：完整实现一致性、离线测试和文档漂移

Batch 17 不得执行成果审计，也不得删除、整理、重命名或覆盖任何历史结果、报告或人工证据。它只检查代码和工程一致性：

必须验证：

- Batch 0–16 每个 Batch 都有独立 PASS 记录；
- 每个 PASS 都有实际代码、schema、产物、专属测试和真实结果；
- 所有离线测试通过；
- contract 校验通过；
- 文档路径和 Skill 镜像无漂移；
- tool strategy、registry、manifest 一致；
- 不自动运行目标网络流程；
- 不读取凭证、原始响应或敏感证据；
- 不检查操作者截图是否充分；
- 不生成 evidence_index 或 screenshot_queue；
- 不因缺 evidence_ref 改动成果。

专属验收：

```bash
python -m pytest -q tests/test_batch17_readonly_acceptance.py
python -m pytest -q
python scripts/verify_offline.py --json
python scripts/maintenance/validate_run_contracts.py
python scripts/maintenance/validate_finding_quality.py
python scripts/check_doc_drift.py
python scripts/check_skill_drift.py
git diff --check
```

## 6. Batch 逐项结果硬门

最终检查报告必须附一张 18 行的 Batch 验收表，不能只列“总体通过”：

```text
Batch 0  PASS/FAIL/BLOCKED/UNVERIFIED  专属测试  代码/产物/schema/接线证据  备注
Batch 1  PASS/FAIL/BLOCKED/UNVERIFIED  专属测试  代码/产物/schema/接线证据  备注
...
Batch 17 PASS/FAIL/BLOCKED/UNVERIFIED  专属测试  代码/产物/schema/接线证据  备注
```

判定规则：

- 任一 Batch 为 FAIL、BLOCKED 或 UNVERIFIED，整体不得为 PASS；
- 任一 Batch 缺少专属测试，整体不得为 PASS；
- 任一 Batch 只有文档没有代码接线，整体为 FAIL；
- 任一 Batch 只有全量 pytest，没有专属测试，整体为 UNVERIFIED；
- 任一 Batch 测试真实失败，必须停在该 Batch 的结论，不得用其他 Batch 的测试覆盖；
- 不允许用“核心完成”“基本完成”“理论支持”等措辞代替状态；
- 检查器发现问题时只报告，不修复。
## 7. 测试数量和复用统计口径

最终报告必须同时给出以下数字，不能把重复引用的测试重复计入独立覆盖：

```text
unique_test_paths：所有 Batch 专属测试集合去重后的测试文件路径数量
per_batch_test_references：每个 Batch 专属测试命令中实际列出的路径数量
cross_batch_reuse_count：同一路径被两个或以上 Batch 专属集合引用的次数减去首次引用次数
regression_test_count：作为回归而非某个 Batch 专属测试运行的测试文件数量
actual_test_runs：实际执行的 pytest/validator/check 命令次数
missing_test_paths：提示词或进度记录引用但仓库不存在的路径数量
replacement_confidence：每个替代路径标记 exact、partial 或 none
```

统计公式：

```text
unique_test_paths = 专属测试路径全集去重后的数量
cross_batch_reuse_count = sum(max(0, 每个路径被 Batch 专属集合引用次数 - 1))
per_batch_test_references = 所有 Batch 专属集合中的路径引用总数
```

`exact` 表示测试直接覆盖该 Batch 的功能；`partial` 表示只能覆盖相邻能力，不能单独满足专属测试硬门；`none` 表示没有可接受替代。测试路径缺失或只有 `partial` 替代时，相关 Batch 必须标记 `UNVERIFIED`，不得自动判定 PASS。

最终检查必须区分：

```text
专属测试：证明某个 Batch 自己的功能
回归测试：证明改动没有破坏已有功能
全量测试：一次性运行全部测试
维护校验：契约、质量、文档和镜像检查
```

全量 pytest、verify_offline 或维护校验通过，不能替代缺失的 Batch 专属测试。

## 8. 完整 18 行 Batch 验收表

最终报告必须实际填写以下全部 18 行，不得使用 `...` 省略：

```text
Batch 0  | 名称：上下文加载与规则优先级 | 状态： | 文件： | 实现： | 接线： | schema： | 产物： | 测试： | 专属结果： | 回归结果： | 负例： | diff： | contract： | doc/sync： | finding：
Batch 1  | 名称：状态模型与 run quality gate | 状态： | 文件： | 实现： | 接线： | schema： | 产物： | 测试： | 专属结果： | 回归结果： | 负例： | diff： | contract： | doc/sync： | finding：
Batch 2  | 名称：漏洞成立门与 finding/evidence gate | 状态： | 文件： | 实现： | 接线： | schema： | 产物： | 测试： | 专属结果： | 回归结果： | 负例： | diff： | contract： | doc/sync： | finding：
Batch 3  | 名称：baseline、降噪与候选去重 | 状态： | 文件： | 实现： | 接线： | schema： | 产物： | 测试： | 专属结果： | 回归结果： | 负例： | diff： | contract： | doc/sync： | finding：
Batch 4  | 名称：工具 registry、runtime 与 launcher | 状态： | 文件： | 实现： | 接线： | schema： | 产物： | 测试： | 专属结果： | 回归结果： | 负例： | diff： | contract： | doc/sync： | finding：
Batch 5  | 名称：Web/API application mapping | 状态： | 文件： | 实现： | 接线： | schema： | 产物： | 测试： | 专属结果： | 回归结果： | 负例： | diff： | contract： | doc/sync： | finding：
Batch 6  | 名称：注入、parser/XXE、反序列化、SSRF | 状态： | 文件： | 实现： | 接线： | schema： | 产物： | 测试： | 专属结果： | 回归结果： | 负例： | diff： | contract： | doc/sync： | finding：
Batch 7  | 名称：GraphQL、WebSocket、browser boundary | 状态： | 文件： | 实现： | 接线： | schema： | 产物： | 测试： | 专属结果： | 回归结果： | 负例： | diff： | contract： | doc/sync： | finding：
Batch 8  | 名称：API 版本、shadow、资源、第三方 API | 状态： | 文件： | 实现： | 接线： | schema： | 产物： | 测试： | 专属结果： | 回归结果： | 负例： | diff： | contract： | doc/sync： | finding：
Batch 9  | 名称：状态机、重放、重复提交、竞态假设 | 状态： | 文件： | 实现： | 接线： | schema： | 产物： | 测试： | 专属结果： | 回归结果： | 负例： | diff： | contract： | doc/sync： | finding：
Batch 10 | 名称：小程序登录、token、签名重放 | 状态： | 文件： | 实现： | 接线： | schema： | 产物： | 测试： | 专属结果： | 回归结果： | 负例： | diff： | contract： | doc/sync： | finding：
Batch 11 | 名称：小程序本地数据、密码学、包完整性 | 状态： | 文件： | 实现： | 接线： | schema： | 产物： | 测试： | 专属结果： | 回归结果： | 负例： | diff： | contract： | doc/sync： | finding：
Batch 12 | 名称：端点对账、云函数、对象存储、第三方边界 | 状态： | 文件： | 实现： | 接线： | schema： | 产物： | 测试： | 专属结果： | 回归结果： | 负例： | diff： | contract： | doc/sync： | finding：
Batch 13 | 名称：WebView、Bridge、Deep Link | 状态： | 文件： | 实现： | 接线： | schema： | 产物： | 测试： | 专属结果： | 回归结果： | 负例： | diff： | contract： | doc/sync： | finding：
Batch 14 | 名称：fh/wz/xcx Skill、prompt、phase、manifest 同步 | 状态： | 文件： | 实现： | 接线： | schema： | 产物： | 测试： | 专属结果： | 回归结果： | 负例： | diff： | contract： | doc/sync： | finding：
Batch 15 | 名称：历史误报、精度反馈、重跑去重 | 状态： | 文件： | 实现： | 接线： | schema： | 产物： | 测试： | 专属结果： | 回归结果： | 负例： | diff： | contract： | doc/sync： | finding：
Batch 16 | 名称：工具补充、离线白盒、SBOM | 状态： | 文件： | 实现： | 接线： | schema： | 产物： | 测试： | 专属结果： | 回归结果： | 负例： | diff： | contract： | doc/sync： | finding：
Batch 17 | 名称：实现一致性、离线测试、文档漂移 | 状态： | 文件： | 实现： | 接线： | schema： | 产物： | 测试： | 专属结果： | 回归结果： | 负例： | diff： | contract： | doc/sync： | finding：
```

真实通过的 Batch：
只有文档完成的 Batch：
测试失败的 Batch：
缺失验收入口：
未接线的阶段：
空模块/TODO/伪实现：
schema/contract 问题：
Skill/prompt/manifest 漂移：
规则冲突：
3–5 条样本规则状态：
公开静态资源规则状态：
截图/证据自动化是否已停用：
历史成果是否完整保留：
工具 registry 问题：
实际运行的检查命令和结果：
不修改代码前提下的返工建议：
```

检查报告中只引用文件路径、行号、状态、计数和摘要，不输出敏感数据原文。

不要使用“基本完成”“大致完成”“应该没问题”等模糊结论。没有真实测试或证据的内容必须标记为 `UNVERIFIED`，不能标记 PASS。
