# 施工状态（CONSTRUCTION_STATUS.md）

> 本文件是 W 编号工单的状态台账。AGENTS.md 在工作开始时引用本文件确定后续推进项。
> 更新约定：每落地一个 W，把"状态"改为 已落地，并把 AGENTS.md「深入阅读 → 施工中」改为"无"（或列出剩余项）。

## 状态速览

| W | 名称 | 状态 | 落地物 | 备注 |
|---|---|---|---|---|
| W1 | 项目入口 | 已落地 | AGENTS.md / CLAUDE.md | 项目定位/安全边界/快速入口/上下文纪律/运行时表 |
| W2 | 交战规则 | 已落地 | ROE.md | 授权前提/速率红线/动作分级(免批・审批门・禁止)/凭证纪律/证据分级/停止条件 |
| W3 | 机器可读工具清单 | 已落地 | AGENT_MANIFEST.md + scripts/gen_agent_manifest.py | 幂等生成器，勿手改 manifest |
| W4 | 会话配方 | 已落地 | prompts/ 配方A-F + tools/copy_prompt.py + 桌面 AI配方_一键复制.bat | 含 skill 注册（.opencode/.claude/.agents 三目录） |
| W5 | 三 skill 硬约束改造 | 已落地 | .claude/.opencode/.agents/skill-deliverables 四目录 {wz,xcx,fh} SKILL.md 顶部硬约束块 + fh 批次复核门（已重打 wz/xcx/fh.zip） | wz/xcx 插 6 条硬约束+阶段门声明；fh 插硬约束+第4步改批次复核(verdicts/<order>.json, 游标=已完成批次)，W6 聚合器未建前用连续 range 续作；**fh 真源=skill-deliverables/fh**，改完须同步 .claude/.opencode/.agents 三处运行时目录（wz/xcx 同理保持四地一致）；**W5b强化(对抗越界指令)**：wz/xcx 的 description 去掉 end-to-end/complete assessment 改写为"每会话一阶段、推完即停"；`## Execute the complete workflow` 整段替换为 `## Execute one phase`（只读 phase_status.json→推一阶段→写状态即停）；硬约束块加第7条"Refuse end-to-end requests"（即使用户要求端到端一次做完也只推一阶段并解释）；`references/workflow.md` 保留作阶段字典不改动 |
| W6 | fh 复核子代理编排 | 未施工 | fh_review_dispatch.py + tests/test_fh_review_dispatch.py | --prepare 切批(默认8) / --aggregate 回写 findings_ledger + fp_memory + TOP_人工复核.md；verdict schema 与配方A一致；零网络 |
| W7 | IDOR 水平越权差分 L0 | 未施工 | idor_triage.py + labs/idor_lab_server.py + tests + 桌面 bat | 基线/B重放/匿名三请求差分；unauth_access / idor_horizontal_candidate 判据；delay≥3s 只读 GET |
| W8 | 竞态双投 L0 | 未施工 | race_triage.py + labs/race_lab_server.py + tests + 桌面 2 bat | h2_single_packet(仅.venv) / h1_last_byte / barrier 三模式；write_risk_ack 审批门 |
| W9 | 三大知识库 | 未施工 | knowledge_base/{fp_memory,vuln_pattern_lib,hypothesis_ledger}.jsonl + README | 每库 schema + ≥1 种子；fp_memory 由 W6 --aggregate 追加 |
| W10 | 度量闭环 | 未施工 | metrics_weekly.py | 五指标聚合；reports/metrics_YYYYMMDD.md + history.jsonl；缺失数据标 N/A |
| W11 | SSRF OOB 探测 | 未施工 | oob_listener.py + ssrf_triage.py + wordlists/ssrf_params.txt + tests | OOB 回调命中=proven / 时间盲 candidate / noise；需 VPS 跑 listener |
| W12 | XSS 执行确认 | 未施工 | xss_verify_headless.py + tests | dalfox 优先 / playwright 兜底；executable / not_executable / context_safe 三态 |
| W13 | 白盒 sink 流水线 | 未施工 | knowledge_base/sink_lib.jsonl + whitebox_triage.py + tests | 七类 sink 种子≥60；sink_findings.jsonl ±3行上下文；配方F输入 |
| W14 | 桌面入口运行时统一 | 未施工 | 桌面 6 个 bat 的 set PY= 段统一 | 探测链 .venv→天狐→codex-runtime→PATH；竞态 bat 写死 .venv |

## 依赖关系（plan_v2.md §4.1）

- W1 → W2 → W3 → W4：入口链，顺序执行。
- W5：独立（三 skill 硬约束改造，依赖 W1 环境就绪）。
- W6 → W9：复核编排 → 知识库（W9 的 fp_memory 由 W6 --aggregate 写入，schema 必须一致）。
- W7 / W8 / W11 / W12 / W13：互相独立，均依赖 W3 的 manifest 登记；判据类工具须先本地靶场验证（第七安全红线"靶场先行"）。
- W10：依赖 W6/W9 的产出数据（findings_ledger / verdicts / hypothesis_ledger）。
- W14：随时（桌面 bat 探测链统一，与其他工单无耦合）。

## 关联的配方/Run 依赖

- 配方 A（复盘）依赖 W6 的批次文件与 verdict schema；配方 B/E 依赖 W9 知识库（未落地时用降级路径）。
- 配方 D（逻辑漏洞）产出 race_config.json → W8 race_triage.py 执行；未落地前只产出 config 不执行。
- 配方 F（白盒研判）依赖 W13 的 sink_findings.jsonl；未产出前 skill 标注不可用。
- W7 输入为现成资产：session_harvest.py 的 sessions.jsonl + browser_xhr_capture 的 replay_requests.local.jsonl。

## 维护规则

- 本文件只由制定方案的会话或人工维护；运行时会话只读它确认"当前推进到哪个 W"。
- 落地一个新 W 后：① 本表状态改"已落地"；② AGENTS.md 深入阅读同步更新；③ AGENT_MANIFEST.md 由生成器重跑（如果涉及新工具/工具路径）。