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
| W5 | 三 skill 硬约束改造 | 已落地 | {wz,xcx,fh} SKILL.md 顶部硬约束块 + 阶段门 + 拒绝一次性指令条款 | 2026-08-21 glut 测试暴露矛盾后完成闭环 |
| W6 | fh 复核子代理编排 | 已落地 | fh_review_dispatch.py + tests/test_fh_review_dispatch.py | 9值枚举对齐配方A；--prepare/--aggregate/--status；对真实 97 目标 run 验收通过 |
| W7 | IDOR 差分 L0 | 已落地 | idor_triage.py + labs/idor_lab_server.py + tests + 桌面bat + runner/workflow/one_click 注册 | 四真值全绿（正确鉴权/IDOR/未授权/200-with-error）；phase idor_diff |
| W8 | 竞态双投 L0 | 已落地 | race_triage.py + labs/race_lab_server.py + tests + 桌面两bat | 三模式(h2单包/h1 last-byte/barrier)全绿；写端点无ack拒绝；--reset-url 支持一次性资源 |
| W9 | 三大知识库 | 已落地 | knowledge_base/{fp_memory,vuln_pattern_lib,hypothesis_ledger}.jsonl + README.md | 种子数据各≥1条；W6 --aggregate 是 fp_memory 写入方 |
| W10 | 度量闭环 | 已落地 | metrics_weekly.py | 五指标；86 run/46158 候选全量验收通过；history 追加式 |
| W11 | SSRF OOB | 已落地 | oob_listener.py + ssrf_triage.py + wordlists/ssrf_params.txt + tests | oob_callback_hit/timing_candidate/noise 三真值绿；VPS 部署说明在 docstring |
| W12 | XSS 执行确认 | 已落地 | xss_verify_headless.py + tests | dalfox 优先→playwright 兜底→stdlib-fetch 三级；executable/context_safe/not_executable 判定 |
| W13 | 白盒 sink 流水线 | 已落地 | knowledge_base/sink_lib.jsonl(62条) + scripts/gen_sink_lib.py + whitebox_triage.py + tests | 对真实 unpacked 小程序扫描命中 9 条；输出供配方F |
| W14 | 桌面运行时统一 | 已落地 | 6 个桌面 bat 探测链统一(.venv→天狐→codex→PATH)；竞态 bat 写死 .venv | AI配方_一键复制.bat 保持 .venv→PATH 原样（仅调 copy_prompt 无重依赖） |

## 全部工单状态：✅ 已落地（2026-08-21）

- 验收基线：新增 6 个测试文件 12 用例全绿；存量 test_one_click_workflow 2 用例修复后全绿；W6/W10/W13 真实数据验收通过。
- 依赖补充：.venv 已安装 pytest 9.1.1（测试基础设施）。
- 待用户执行：git 提交本轮全部改动（建议 message: W5-W14 全量施工：skill硬约束闭环+复核编排+IDOR/竞态/SSRF/XSS/白盒L0+知识库+度量+桌面统一）。
- 配方可用性更新：A/B/C 可用；D 可用（race_triage 已落地，race_config 可执行）；E 升级为全功能（knowledge_base 已落地）；F 可用（whitebox_triage 已落地，sink_findings 有生产者）。
