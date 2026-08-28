# 项目结构与归类说明

本仓库是一个**授权安全演练工作台**。它同时包含生产代码、受控入口、离线分析工具、AI 工作流和本地运行资产。整理原则是：生产代码可复用，入口可追踪，运行产物与敏感数据不进 Git，旧代码与高风险动作明确隔离。

## 一页地图

```text
PythonProject4/
├── gov_exercise_runner.py       主流程兼容入口（生产编排器）
├── exercise_runtime.py          共享运行时兼容入口
├── policy_engine.py             目标范围/动作策略兼容入口
├── launchers/                   Windows 启动器的规范副本
├── scripts/                    维护、导入、浏览器和报告辅助脚本
├── contracts/                  JSON Schema 与流程契约
├── tests/                      pytest 测试
├── prompts/                    AI 会话配方（当前 canonical）
├── skills/                     项目级 Skill（当前 playbook）
├── .agents/skills/             Skill canonical 源；其他客户端为镜像
├── labs/                       本地教学靶场，不连接真实目标
├── knowledge_base/             离线知识库和沉淀数据
├── config*.json / config.yaml  当前流程配置（逐步集中到 config/）
├── runs/                       每次运行的唯一事实源（本地、被忽略）
├── engagements/                按目标的长期工作区（本地、被忽略）
├── reports/、outputs/          生成物（本地、被忽略）
├── tools/                      第三方工具、二进制和本地运行数据（本地、被忽略）
├── unpacked/                   小程序解包输入（本地、被忽略）
└── legacy/                     归档/兼容/高风险代码的隔离区
```

## 入口规则

### 推荐入口

- `launchers/一键保守全流程_尽量多信息_避WAF.bat`：低速、只读、信息收集优先。
- `launchers/一键完整流程_含弱口令.bat`：显式弱口令复核流程，仍受审批门约束。
- `launchers/一键已有子域名后流程_含弱口令.bat`：已有子域名清单的后续流程。
- `launchers/一键并行分批流程.bat`：按根域分组的批次调度。
- `launchers/启动浏览器XHR采集_本地复现版.bat`：人工登录后的浏览器辅助采集。
- `launchers/小程序Burp导入到最近一次流程.bat`：把 Burp 导出导入最近一次 run。

根目录同名 `.bat/.cmd` 文件是**兼容转发器**，用于兼容已有桌面快捷方式和旧文档；新的入口引用应指向 `launchers/`。

主 Python 入口仍是：

```powershell
python .\gov_exercise_runner.py --targets <目标文件> --probe --fingerprint
```

## 代码应该放在哪里

| 类型 | 位置 | 说明 |
|---|---|---|
| 主流程与共享运行时 | 根目录兼容入口；后续迁入 `src/authorized_assessment/` | 暂不机械移动，避免破坏裸导入 |
| 维护脚本 | `scripts/` | drift、manifest、离线验证等固定入口保留在此 |
| 目标/平台导入 | `scripts/` 及其专项子目录 | 新增导入器不要放根目录 |
| 契约 | `contracts/` | JSON Schema、输出契约 |
| 测试 | `tests/` | 当前平铺布局有稳定导入约定，暂不移动 |
| 本地靶场 | `labs/` | 只用于本地教学和判据校准 |
| AI 配方 | `prompts/` | `tools/copy_prompt.py` 依赖该路径 |
| Skill | `.agents/skills/` | canonical；`.claude` 和 `.opencode` 是镜像 |
| 旧兼容代码 | `legacy/compatibility/` | 不作为默认主流程 |
| 高风险/实验代码 | `legacy/unsafe/`、`legacy/archived/` | 必须遵守审批门和授权边界 |

## 第二阶段迁移状态

当前已完成“逻辑归类 + 兼容优先”迁移：

- `launchers/` 保存规范启动器，根目录入口保留兼容转发。
- `src/authorized_assessment/artifacts/` 已迁移 `fingerprint_ingest.py`；它只读本地 run 产物并更新本地指纹库，不访问网络。
- `src/authorized_assessment/analysis/` 已迁移纯离线的 `product_triage.py`、`healthcare_privacy_triage.py`、`fingerprint_deepening.py` 和 `review_intelligence.py`；根目录同名文件是兼容入口。
- `src/authorized_assessment/orchestration/` 已迁移 `one_click_workflow.py` 和 `parallel_flow_runner.py`；两者仍委托根兼容入口对应的主 runner，并保留原授权、限速和审批边界。
- `src/authorized_assessment/orchestration/runner_config.py` 集中主 runner 的配置默认值、工作流/工具策略加载和相对路径解析；`gov_exercise_runner.py` 保留兼容函数名。
- `stage_paths.py` 现在同时记录阶段脚本路径、功能分类、风险级别、是否离线以及是否需要授权；这些元数据只用于归类和审查，不会绕过策略引擎。
- `src/authorized_assessment/triage/` 已迁移 `second_pass_triage.py`；它只对已有候选做有界复测，仍是候选筛选而非利用。
- `src/authorized_assessment/triage/` 现在还提供 `sqli.py`、`xss.py`、`header_reflection.py` 三个包门面；由于测试和调用方会按根模块打补丁，这三类网络阶段暂保根实现为 canonical。
- `src/authorized_assessment/review_auth.py` 和 `triage/shiro.py`、`miniapp/wechat_discovery.py` 是认证/网络阶段的包门面；根实现保持 canonical，避免改变凭证、请求适配和审批边界。
- 根目录逐文件分类清单：[`docs/ROOT_FILE_CLASSIFICATION.json`](ROOT_FILE_CLASSIFICATION.json)。它是导航清单，不是运行时授权白名单。
- `legacy/compatibility/` 和 `legacy/unsafe/` 记录旧入口与高风险模块的边界；由于仍有历史调用，相关根文件暂不物理移动。


- `runs/`、`engagements/`、`reports/`、`outputs/`
- `tools/`、`unpacked/`、`attack/`、`ai_infra_guard/`
- `targets*.txt`、真实目标清单、解包源码、二进制和 payload
- `*.local.json`、`*.local.jsonl`、`*.local.txt`、Cookie、Token、HAR

不要为了“整齐”跨目标批量重命名或移动这些资产。它们可能包含证据、个人信息或本地会话；应以 run/目标为单位管理，并保留来源记录。

## 运行产物约定

- `runs/<timestamp>_<label>/` 是一次流程的事实源。
- `engagements/<target>/` 保存跨 run 的目标级游标、台账和 handoff 记录。
- `reports/`、`outputs/` 是从 run 派生的报告/验证产物，不是新的事实源。
- 根目录 `parallel_flow_batches_*` 是历史兼容位置；新调度器应将批次目录视为运行产物并在计划文件中记录来源 run。

## Skill 与文档同步

- `.agents/skills/` 是 canonical；执行 `python scripts/check_skill_drift.py` 检查客户端镜像。
- `AGENT_MANIFEST.md` 由 `python scripts/gen_agent_manifest.py` 生成，禁止手改。
- `python scripts/check_doc_drift.py` 检查关键文档中的路径引用。
- `skill-deliverables/` 是历史交付/验收材料，不是 canonical Skill。

## 离线验收

```powershell
python -m pytest -q
python scripts/verify_offline.py --json
```

这些命令只做编译、漂移检查和本地测试；不启动真实目标探测、不使用认证凭证、不执行写入动作。

## 整理约束

1. 移动生产模块前先搜索裸 import、BAT、文档和 `__file__` 路径。
2. 兼容入口必须保留，直到所有调用方完成迁移。
3. 不删除或重置现有用户改动，不清空运行目录。
4. 不把运行产物、凭证、响应正文、真实目标或第三方二进制加入提交。
5. 所有网络访问仍须经过授权范围、速率控制和审批门。
