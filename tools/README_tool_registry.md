# tools/tool_registry.md —— 轻量工具登记说明（实施规格 7.1）

## 这是什么

`tools/tool_registry.json` 是个人项目的**本地运行登记**，不是软件供应链审计系统。它只回答三个问题：

```text
工具在哪里（path）
是什么版本（version，取自盘上事实）
当前能不能调用（status，只表示本地路径可解析性，不表示授权状态）
```

速率、并发、只读模式、queue-only、审批门、证据输出**不在 registry 登记**——它们由 `ROE.md`、`policy_engine.py`、`tool_strategy.json` 和阶段代码统一控制，registry 不建第二套审批规则。`conditional` 不是合法工具状态；某工具只能在特定阶段使用由 `tool_strategy.json` 控制。

## 字段

每个工具默认只登记 8 个字段（`tool_required_fields`）：

| 字段 | 说明 |
|---|---|
| `tool_id` | 全局唯一；与 `tool_strategy.json` 引用名一致（如 `ShiroAttack2`、`FastjsonScan.exe`） |
| `display_name` | 人类可读名 |
| `path` | 绝对路径或项目根相对路径；天狐内工具记绝对路径 |
| `version` | 取自盘上事实（`tools/managed/managed_inventory.json`、路径版本段、压缩包文件名）；不执行工具取版本 |
| `status` | `active` / `unavailable` / `hold` / `retired` |
| `runtime` | `native` / `python` / `java` / `node` / `go` / `data`（advisory） |
| `dependencies` | 字符串数组；仅运行前能力提示 |
| `known_limitations` | 防 AI 把工具输出误认为完整漏洞确认 |

可选字段（缺失不阻塞普通只读流程）：`source_url`、`release_date`、`sha256`、`notes`、`config_key`（关联 `gov_exercise_config.json` tools 键）、`checked_at`（rebuild 写入）。

**禁止登记**（`forbidden_control_fields`，契约不变量）：`scope_controls`、`rate_controls`、`concurrency_controls`、`read_only_mode`、`queue_only_mode`、`approval_required`、`evidence_output`、`auto_update_disabled`。

## status 语义（fail-closed）

- `active`：登记路径当前真实存在；校验时路径不存在即违例。
- `unavailable`：本地不存在或未接线（如规划中的新能力工具）；`tool_strategy.json` 不得精确引用 unavailable 的 `tool_id`。
- `hold`：本地存在但当前不直接调用（如 `dddd` 为无编译产物的 Go 源码树）。
- `retired`：已弃用留档。
- 工具不存在必须标 `unavailable`/`hold`，**不得假装可用**；不自动为填 `sha256`/`source_url` 联网查询或下载。

## 如何加一个工具

1. 编辑 `tools/tool_registry.json`，人工补齐 8 个默认字段（新工具元数据不由脚本凭空生成）；
2. 若它来自 `gov_exercise_config.json` tools 候选表，加 `config_key`；
3. 运行 `python scripts/maintenance/rebuild_tool_inventory.py --check`，退出码 0 才算登记完成；
4. 需要被 AI 选用的外部工具另跑 `python scripts/gen_agent_manifest.py` 再生 AGENT_MANIFEST.md（不手改）。

## rebuild 行为（scripts/maintenance/rebuild_tool_inventory.py）

```bash
python scripts/maintenance/rebuild_tool_inventory.py --check     # 校验，退出码 0/1
python scripts/maintenance/rebuild_tool_inventory.py --rebuild   # fail-closed 再解析并写回
python scripts/maintenance/rebuild_tool_inventory.py --check --json
```

- `--rebuild` 按 config 候选顺序重解析 `config_key` 条目（首个存在的候选胜出）；路径归一化为项目根内相对 posix / 根外绝对 posix；
- `active` 条目路径失配 → 自动降级 `unavailable`（不保留 active 假象）；
- `hold`/`unavailable`/`retired` 为人工状态，**一律不自动改判、不自动升级**；
- 无变化时不写文件（字节级幂等）。

## 契约与校验

- 契约：`contracts/tool_capability_schema.json`（第 6 个 run 契约，纳入 `validate_run_contracts.py`）；
- 实现：`src/authorized_assessment/tools/registry.py`（纯 stdlib、零网络、只读幂等）；
- 测试：`tests/test_tool_registry.py`（含实施规格 13.2 负例：registry 中不存在的逻辑工具名、精确引用 unavailable 工具、行为控制字段禁入等）。

## Batch 16 新增登记（2026-08-31，规格 7.2 工具补充）

七个工具以 `unavailable` 显式登记（本地未下载，**禁止自动下载**；候选路径为操作者将来放置位置，放置并登记 active 前不接入任何 strategy 角色）：

| tool_id | 用途 | 二选一 | 配套离线能力模块 |
|---|---|---|---|
| `ffuf` | 受控目录候选（固定小词表/单目标/-t 1/-delay>=2s/无递归；200 ≠ 敏感资源） | — | `src/authorized_assessment/triage/ffuf_directory_candidates.py` + `wordlists/ffuf_dirs_small.txt` |
| `xsstrike` | 单候选 XSS 验证（已筛选择候选；no_crawl/no_blind/no_update） | **胜出**（Python 运行时匹配） | `src/authorized_assessment/triage/single_candidate_xss_validation.py` |
| `dalfox` | （未选用留档） | 败者 | 无（不接入 strategy） |
| `subfinder` | 被动子域发现（`-active` 计划级禁入；新域 confirmation_required） | — | `src/authorized_assessment/discovery/passive_subdomain_candidates.py` |
| `dnsx` | 已知候选 DNS 解析（`-w` 计划级禁入，仅 `-l` 清单模式） | — | 同上 |
| `semgrep` | 离线白盒（规则固定本地、拒绝 registry/远程配置、`--metrics=off`；静态命中只产 signal） | **胜出**（单二进制 JSON 输出） | `src/authorized_assessment/analysis/static_analysis_signals.py` |
| `codeql` | （未选用留档） | 败者 | 无（不接入 strategy） |

能力模块统一形态：plan（受控调用计划，纯数据零执行）+ ingest（操作者手工产出的工具 JSON 结果解析，负例在场即降级，confirmed 永不自动产生）。registry `status` 仍只表示本地路径可解析性；`executable=false` 是 fail-closed 默认。离线 SBOM/依赖审计无需工具二进制：`src/authorized_assessment/analysis/sbom_inventory.py`（lockfile 清单 + 本地 advisory cache；无 advisory 数据只报清单与人工复核）。

`tool_strategy.json` 中的复合逻辑名（`dirsearch_or_ffuf` / `nuclei_or_dalfox_or_xsstrike`）已按"不得写成模糊 or"清理为诚实可执行引用（`dirsearch` / `nuclei`）；能力接线说明在对应 phase 的 notes 中。
