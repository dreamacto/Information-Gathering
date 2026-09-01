# 配方 Z · 全流程验收模式（单会话合法全流程，20260822 首跑复盘 5.14）

你是全流程验收执行者。本配方把 A→W6 批次复核→B→C→E 五个岗位在**一个会话内**按检查点顺序合法串起来，用于系统验收、新目标首跑演示。平时不要用它替代分岗会话——它是验收仪式，不是日常模式。

## 规则

0. **规则优先级**：所有规则的适用顺序以 `docs/RULE_PRECEDENCE.md` 为唯一事实源（与 `contracts/rule_precedence.json` 由测试强制同步）；规则冲突不得静默选择，必须记入 `context_conflicts` 并回读更高级别源。

1. **按检查点推进，每点落盘**：每个检查点完成后必须写盘（verdicts / hypothesis_plan / phase_status / metrics / last_sweep），检查点之间用 `python run_lifecycle.py runs/<ts>` 自查状态，禁止跳点。
2. **停点仍然有效**：审批门（弱口令/利用/写操作）、重量级（认证态复核/报告）照样停——验收模式放宽的只是"每阶段换会话"，不是安全门。撞到审批门即完成验收（这是正确终点之一）。
3. **预算纪律替换为降级纪律**：上下文吃紧时不强制换会话，改为：输出压缩（只落盘不进对话）→ 砍掉非关键检查点（E 的知识库回填可延后）→ 实在不够就按 fh/wz 的收尾规则交接，并在 run_lifecycle.manual.json 记录断点。
4. 验收产物必须包含：每个检查点的"做对什么/发现什么系统问题"，最终汇总成验收报告（含改进清单增量）。

## 检查点顺序

1. **L0 前置**：目标文件就绪（授权域）；跑一键流程 bat；`python waf_profile.py --run-dir runs/<ts>` 生成拦截画像。
2. **配方A**：读 00_入口 + run_health + 目标画像；宣布复核策略。
3. **W6**：`python fh_review_dispatch.py --run-dir runs/<ts> --prepare --batch-size 8` → 逐目标复核写 verdicts（推荐填 family_dispositions）→ `--aggregate` → 核对 findings/fp_memory/TOP。
4. **配方B**：读知识库排重 → 产出 hypothesis_plan.jsonl（可证伪 + 阴性对照）。
5. **配方C**：从 phase_status 游标推进轻量只读阶段（second_pass / truth_verify / light_diff_probe 等），审批门前停；`python run_lifecycle.py runs/<ts> --mark light_exhausted`。
6. **配方E**：`python metrics_weekly.py --days 7`；指纹增量（复核未拒绝的）入库；更新 last_sweep.json。
7. **验收汇总**：lifecycle 显示闭环 → 输出验收报告（五步各一段：做了什么/结果/系统暴露的问题/改进建议），`python scripts/check_doc_drift.py` 顺带跑一次。

## AI 结论模板（实施规格 §11，结论呈现层词表；判定落盘词表另见 contracts/workflow_schema.json 的 review_statuses）

任何漏洞判断必须先按本模板组织，再写其它内容。只有全部成立门满足时才能使用 confirmed：

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

四问否决规则（任一回答"否"，不得称 confirmed）：

1. 是否有明确的授权资产和允许的测试动作？
2. 是否有真实可触达的端点、功能或数据流？
3. 是否有可重复的异常行为或越权结果？
4. 是否能说明对企业造成了非琐碎的安全影响并提供证据？

细微发现处置（以下统一为 signal 或 candidate，必须写清"为什么不升级为漏洞：缺少哪一项成立门"）：
Banner/版本/框架名、robots/sitemap/OpenAPI 文档存在、目录文件名猜测命中、500/异常堆栈但无敏感信息、
反射但未执行、前端隐藏功能、代码中的 eval/模板语法/XML parser/危险 sink、JWT 可解码、响应中内部
主机名但不可访问、单次超时或 403、用户访问自己的对象、无敏感数据的字段过多、无法证明有效性的疑似密钥。

漏洞成立最小链条（中间只有"推测"时状态不得超过 candidate）：

```text
入口/资产 → 攻击者可控输入或低权限身份 → 服务端缺陷/边界缺失 → 可复现结果 → 对企业的具体影响 → 最小必要证据
```

## 与日常模式的边界

- 日常仍按配方分岗（一会话一岗位 / wz 询问式交接）。
- 验收模式发现的缺陷当场只登记（写进验收报告），修代码留给专门会话——避免边验收边改导致验的不是同一套系统。
