# implementation_blockers.md

阻塞与缺口台账。规则：只有发生阻塞时更新；每条必须写明证据、影响范围、归属 Batch，不得把 BLOCKED 写成 PASS。

## B1：规范引用文件缺失——prompts/AI整体改造_严格分批逐项验证.md【已解决】

- 发现时间：2026-08-29 启动检查。
- 证据：`prompts/AI整体改造_无人值守高质量执行.md` 第 15-19 行引用该文件为"更严格的执行要求"；启动检查时 `prompts/` 无此文件（ls 与 wc 均报缺失）。
- 解决时间：2026-08-29。操作者已将该文件放入 prompts/（16,912 字节，mtime 08:58），AI 已全文读取并逐节对照。
- 对照结论：
  1. 与 Batch 0 已完成工作无冲突——本文件第七节硬性要求的全套（context_loader/policy_snapshot/RULE_PRECEDENCE.md/CONTEXT_LOADING_MAP.yaml）恰为 Batch 0 交付物；
  2. 批次划分与主规范一致（仅措辞差异），无追溯调整；
  3. 漏洞状态枚举：本文件第八节为 5 状态，主规范第八节为 8 状态超集（含 needs_manual_validation/rejected/duplicate）——按操作者指定的主规范取 8 状态，Batch 2+ 实现时以超集为准；
  4. 追溯补齐：第十二节要求六类型测试矩阵，Batch 0 模块缺幂等例——已补 test_write_is_idempotent_bytewise（policy_snapshot）与 test_load_is_deterministic（context_loader），两文件 37 passed、全量 194 passed；
  5. 后续批次流程收紧（自 Batch 1 起生效）：实施卡片增加"可能阻塞点"字段；阻塞记录条目须含具体文件与行号、已尝试修复、失败命令真实输出摘要、为何不能继续、需人工决定的唯一事项、对后续阶段的影响。
- 状态：RESOLVED（2026-08-29）。

## B2：Skill 镜像既有漂移（.claude / .opencode 的 xcx evidence-reporting.md）【2026-08-29 细化诊断：仅换行符差异】

- 发现时间：2026-08-29 Batch 0 汇总验收（第 5 项 drift 检查）。
- 证据：`python scripts/check_skill_drift.py` → status=drift，`.claude` 与 `.opencode` 的 `xcx/references/evidence-reporting.md` 与 canonical（.agents/skills）changed。git status 显示该三处文件工作树干净（漂移存在于已提交状态，最后触碰 commit ba72c50），本改造（Batch 0）未修改任何 Skill 文件。
- 细化诊断（2026-08-29，人工 diff 复核）：`file` 显示 canonical 为 LF、镜像为 CRLF 行尾；`diff <(tr -d '\r' ...)` 剥离 \r 后两个文件内容**完全一致**——漂移为纯格式差异（换行符），无语义差异，不同工具读到的规则内容相同。
- 影响：低。不造成规则不一致，但导致 check_skill_drift.py 永远报 drift，最终验收（第十三节 checklist 要求 `.agents/.claude/.opencode` 无漂移）无法通过。
- 归属：Batch 14（fh/wz/xcx Skill、prompt、phase、产物和审计同步）——修复方式为将镜像行尾规范化为与 canonical 一致（或统一 LF），修复后 check_skill_drift.py 必须 status 干净；Batch 14 完成时此条必须转为已解决，否则 Batch 14 不得 PASS。
- 修复记录（batch14_1，2026-08-30）：.claude/.opencode 两镜像 evidence-reporting.md
  bytes 级 CR LF→LF（52 行全转换），read-back 断言与 canonical sha256 一致
  （04a3a08f826a0b5d…）；修复后 `python scripts/check_skill_drift.py` status=ok（exit 0）。
  tests/test_xcx_auth_phase_split.py 例外随之收口：测试更名
  test_xcx_mirrors_are_byte_identical（删除 b2_file 跳过分支，全量 xcx 镜像字节
  强制、无例外）；test_xcx_webview_artifacts.py 头注/节注同步。
- 状态：RESOLVED（2026-08-30，batch14_1；check_skill_drift 全绿由 batch14_5
  verify_offline 实跑复核确认）。

## B3：最终验收入口缺失——scripts/maintenance/validate_run_contracts.py【已解决】

- 发现时间：2026-08-29 Batch 0 汇总验收（第 6 项入口盘点）。
- 证据：主规范第十二节最终验收命令清单要求 `python scripts/maintenance/validate_run_contracts.py`；`scripts/maintenance/` 下无此文件。`scripts/verify_offline.py` 存在。
- 影响：最终验收（Batch 17）前必须存在；按其名称与主规范第一节（3.2 运行质量状态/强制门控）推断属于 Batch 1（状态模型、run quality gate）的实现范围。
- 归属：Batch 1 必须创建该入口及其测试；否则 Batch 1 不得 PASS，Batch 17 整体不能标记 PASS。
- 解决时间：2026-08-29（Batch 1 子项 batch1_4）。
- 交付：scripts/maintenance/validate_run_contracts.py（校验 contracts/*.json 四文件结构 + 状态模型三层无漂移：契约↔run_lifecycle/quality gate/fh verdict 常量 + 门控阈值 schema↔实现一致；退出码 0/1；--json/--root）+ tests/test_validate_run_contracts.py（13 项，含 4 个篡改负例）。
- 实跑结果：`.venv/Scripts/python.exe scripts/maintenance/validate_run_contracts.py` → 退出码 0，零违例；`--json` → ok=true。全量回归 270 passed。
- 附带发现（校验器首轮实跑真实检出并已修复）：① workflow_schema.review_statuses 缺 "pending"（fh verdict 九值枚举中的初始态未被契约覆盖）→ 已补入；② 校验器自身 conflict_handling 键类型误判（dict 非 list）→ 已修正。
- 状态：RESOLVED（2026-08-29）。

## B4：最终验收入口缺失——scripts/maintenance/validate_finding_quality.py【已解决】

- 发现时间：2026-08-29 Batch 0 汇总验收（第 6 项入口盘点）。
- 证据：主规范第十二节最终验收命令清单要求 `python scripts/maintenance/validate_finding_quality.py`；文件不存在。
- 影响：最终验收（Batch 17）前必须存在；按名称推断属于 Batch 2（漏洞成立门、补天规则、finding quality、evidence gate）的实现范围。
- 归属：Batch 2 必须创建该入口及其测试；否则 Batch 2 不得 PASS，Batch 17 整体不能标记 PASS。
- 解决时间：2026-08-29（Batch 2 子项 batch2_3）。
- 交付：scripts/maintenance/validate_finding_quality.py（两个 finding 契约结构校验 + 实现常量逐项无漂移：
  finding_quality_gate.py 的 8 状态/五门/门 reason 枚举/证据十四字段/影响类别/十判定规则/classification 五枚举/
  P0-P3 映射/类别默认表/抑制规则目录，evidence_gate.py 的门状态/违例码/呈现形式 + 跨契约 8 状态互查；
  行为探针：正例样例过判定与校验器、篡改 confirmed 报告被拒、未验证 eligible 被拒、evidence gate 缺证据路径
  REJECTED、REJECTED 零违例门报告被拒；退出码 0/1，--json/--root）+ tests/test_validate_finding_quality.py（16 项，
  含 7 个篡改负例 + 2 个 CLI 子进程实跑）。
- 同步：validate_run_contracts.py 的 check_state_model_drift 已纳入 finding quality 8 状态三方交叉
  （finding_quality_schema ↔ finding_quality_gate.FINDING_STATUS_STATES ↔ finding_evidence_schema），
  tests/test_validate_run_contracts.py 补 2 个负例（缺 finding 契约被标记、状态篡改被检出）。
- 实跑结果：`.venv/Scripts/python.exe scripts/maintenance/validate_finding_quality.py` → 退出码 0，零违例；
  `--json` → ok=true；`validate_run_contracts.py` → 退出码 0（新交叉校验无违例）。全量回归 360 passed。
- 附带发现（行为探针首轮实跑真实检出）：探针自身一处 bug——对 quality report 误取 submission_eligibility
  字段（该字段在 classification 层），当场修正探针实现；判定器行为本身正确。
- 状态：RESOLVED（2026-08-29）。

## B5：用户 Temp 的 pytest 符号链接 ACL 损坏，裸 pytest 全量命令收尾崩溃【发现于 2026-08-30，Batch 9】

- 发现时间：2026-08-30 Batch 9（batch9_0 全量回归时）。batch8 基线（2026-08-30 01:40，
  813 passed 双态零失败）时尚未出现；batch8 末次 run 时段（01:39-01:40）产生畸形链接，
  推断为该时段某次 pytest 会话崩溃残留，与既有环境已知项".pytest_cache 目录 ACL 损坏"
  同族（本机 ACL 损坏类问题，非项目代码问题）。
- 证据（具体路径与真实输出）：
  1. 畸形链接：`C:\Users\ASUS\AppData\Local\Temp\pytest-of-ASUS\pytest-current` 为
     SYMLINKD 且指向 `..`（父目录，正常应指向 pytest-N 编号目录；cmd dir 输出留痕）；
  2. 收尾崩溃：`.venv/Scripts/python.exe -m pytest -q tests/` 全部测试执行完毕后，
     pytest_sessionfinish → tmpdir.cleanup_dead_symlinks → left_dir.unlink() 抛
     `PermissionError: [WinError 5] 拒绝访问。`（pytest tmpdir.py:357/371），终端汇总行
     不打印、退出码非 0——测试主体结果与收尾崩溃可分离；
  3. 修复尝试三连均被拒（真实输出摘要）：`cmd /c rmdir` → 拒绝访问；Python
     `os.rmdir` → PermissionError WinError 5；PowerShell `Remove-Item -Force` →
     DeleteSymbolicLinkFailed。`icacls` 连读取 ACL 本身也被拒（"拒绝访问。已成功处理
     0 个文件"）——非提权无法修复。
- 已尝试修复：上述三种删除方式；均失败。未尝试提权操作（无人值守不提权）。
- 为何不能继续：不阻塞 Batch 9 实现本身——已采用旁路验证：回归命令加
  `--basetemp=<Temp>\pytest-b9-work`（pytest 自管新目录，ACL 全新），测试主体全量
  可跑通（batch9_0 轮 829 passed）。但**裸 `.venv\Scripts\python.exe -m pytest -q
  tests/` 命令在本机当前 Temp 状态下收尾崩溃**，Batch 17 最终验收（第十二节要求
  裸命令全过）在该链接被清理前无法以原命令形式通过。
- 需人工决定的唯一事项：操作者以提权方式删除该畸形符号链接（或重登/清理用户
  Temp 的 pytest-of-ASUS 目录）；无需 AI 侧代码修改。
- 对后续阶段的影响：Batch 9~16 回归一律用 `--basetemp` 旁路留痕；Batch 17 最终
  验收前必须由操作者清除该链接，否则裸命令验收按环境阻塞处理。
- 清理与复验（batch17_4，2026-08-31）：操作者已提权清理该畸形链接——
  `%TEMP%\pytest-of-ASUS\` 仅剩正常编号子目录（pytest-254~258），`pytest-current`
  不复存在。复验（batch17_4 全部实跑）：裸 `.venv\Scripts\python.exe -m pytest -q`
  原形命令 **1259 passed, 1 warning，退出码 0**（唯一 warning 为既有
  .pytest_cache ACL 环境项）；净进程 `verify_offline.py --json` status=ok 四项
  全绿（此前必失败的 tests 项转绿）；validate_run_contracts / validate_finding_
  quality / check_doc_drift / check_skill_drift / git diff --check 全部 exit 0；
  复验后 Temp 无畸形链接再生。
- 状态：RESOLVED（2026-08-31，操作者提权清理 + batch17_4 复验；总体状态由
  PARTIAL 转 PASS）。
