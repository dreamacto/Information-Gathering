# AGENT_MANIFEST.md — 机器可读工具清单

> 由 scripts/gen_agent_manifest.py 生成，勿手改（生成时间：2026-08-23 11:37）

> 用法：AI 选工具前先查本清单；所有新工具/新 phase 由生成器登记，不手写本文件。

## 全局速率红线（gov_exercise_config.json rate_control）

- 默认请求间隔 ≥2.0s（jitter ±25%）；单 host 最小间隔 ≥2.0s
- 退避：[429, 500, 502, 503, 504] → 停 10s；并发上限 3；同 host 连续错误 5 次 → 停该 host

## 禁止动作（blocked_actions 全表）

`password_spray` / `bruteforce` / `webshell` / `c2` / `tunnel` / `data_export` / `destructive_write` / `ddos` / `social_engineering` / `near_field`

## 审批门 phase（tool_strategy.json approval_gated_phases）

- **credential_testing**：primary=`manual_minimal_check` backup=`weak_passwd_scanner.py_or_hydra_only_when_approved`（mode=disabled）。Credential spraying and brute force remain approval-gated. Custom credential scripts are helpers only; they are not default validators and must use tiny dictionaries, low rate, and lockout-safe limits.
- **exploitability**：primary=`manual_minimal_validation` backup=`specialized_mature_tool_or_custom_helper_when_approved`（mode=disabled）。Stop once permission or impact is proven. Custom exploit helpers must not be used full-scope and should only assist one approved candidate at a time.
- **post_exploitation**：primary=`none_by_default` backup=`none_by_default`（mode=disabled）。Webshell, C2, tunnels, internal scanning, and persistence are not default workflow tools.

## 桌面入口（bat）

| 入口 | 场景 | 风险 | 示例 |
|---|---|---|---|
| 一键完整流程_含弱口令.bat | 从零开始完整攻击链（子域→活性→指纹→triage→弱口令复核），需要目标文件；跑完看 runs/last_one_click_run.txt | 审批门内含弱口令复核阶段（会停下等人确认） | `一键完整流程_含弱口令.bat 目标文件.txt` |
| 一键已有子域名后流程_含弱口令.bat | 已有子域名清单，跳过子域爆破，从活性/指纹阶段接着跑（parallel_flow_runner.py，按根域分组） | 审批门内含弱口令复核阶段 | `一键已有子域名后流程_含弱口令.bat 子域名清单.txt` |
| 一键保守全流程_尽量多信息_避WAF.bat | 保守模式：delay=5s、单线程、跳过弱口令与高价值路径，尽量避开 WAF 触发（gov_exercise_runner.py） | 只读 | `一键保守全流程_尽量多信息_避WAF.bat 目标文件.txt` |
| SQLi会话探测.bat | SQLi 三合一探测（请求预算 16/参数、基线差分、marker 确认）；浏览器登录后粘贴 cURL 的会话探测 | 只读探测 | `SQLi会话探测.bat （交互：粘贴 cURL）` |
| 小程序Burp导入到最近一次流程.bat | 把小程序的 Burp 导出导入到最近一次 run 流程（miniapp_burp_import_latest.py） | 离线导入 | `小程序Burp导入到最近一次流程.bat` |
| 无影TscanPlus.bat | 本地 GUI 扫描器入口（手动页面操作，非命令行） | 手动工具，按需 | `无影TscanPlus.bat` |
| 一键IDOR差分_只读.bat | 交互输入 run 目录/会话文件/端点文件，跑 idor_triage.py 只读差分（.venv） | 只读差分 | `一键IDOR差分_只读.bat` |
| 一键竞态靶场.bat | 本地起 race_lab_server.py（8892）：/claim 漏洞真值 /claim_safe 负例 /transfer 超扣；判据校准教学用 | 本地靶场，零外联 | `一键竞态靶场.bat` |
| 一键竞态测试_授权目标.bat | 读配方D 产出的 race_config.json 对授权目标执行竞态；开场强制 YES 确认；必须 .venv | 审批门：写端点需 write_risk_ack | `一键竞态测试_授权目标.bat` |
| AI配方_一键复制.bat | 菜单选 1-6 把 prompts/ 配方A-F 全文复制到剪贴板，粘贴给任意 AI 启动对应会话（copy_prompt.py） | 离线复制，零网络请求 | `AI配方_一键复制.bat` |

## 根目录核心脚本（49 个）

| 工具 | 路径 | 用途 | 输入 | 输出 | 风险 | 示例 |
|---|---|---|---|---|---|---|
| fh_review_dispatch.py | `D:\PythonSource\PythonProjects\PythonProject4\fh_review_dispatch.py` | W6 复核编排：把 postrun_review 工作区切成子代理批次(batch md 自包含) + 聚合 verdict 回台账；零网络 | 见 --help | postrun_review/review_batches/*.md、verdicts/*.json、findings_ledger.csv、fp_memory.jsonl、TOP_人工复核.md | 离线编排 | `python fh_review_dispatch.py --run-dir runs/<ts> --prepare --batch-size 8` |
| idor_triage.py | `D:\PythonSource\PythonProjects\PythonProject4\idor_triage.py` | W7 IDOR 水平越权差分：基线A/B重放/匿名三请求对比结构指纹与 Jaccard，只读 GET/HEAD | 见 --help | <run_dir>/idor_candidates.jsonl、idor_manual_review.md | 只读（需≥2凭证、delay≥3s、每host≤5端点） | `python idor_triage.py --run-dir runs/<ts> --sessions sessions.jsonl --requests api_confirmed.jsonl` |
| report_docx.py | `D:\PythonSource\PythonProjects\PythonProject4\report_docx.py` | 攻防成果报告 docx 生成器（北港网格式）：findings.json+meta.json 渲染 / --from-ledger 台账骨架 / --demo 模板；自动插入红色【需截图】标注 | 见 --help | reports/攻防成果报告_<名>_<日期>.docx | 纯离线渲染 | `python report_docx.py --meta reports/meta.json --findings reports/findings.json` |
| run_lifecycle.py | `D:\PythonSource\PythonProjects\PythonProject4\run_lifecycle.py` | run 完成态查询器：从盘上产物推导 scan/review/planned/light_exhausted/swept 状态，回答'跑完了吗/下一步是什么'；--mark 人工标记 | 见 --help | run_lifecycle.json（run 目录内） | 纯离线 | `python run_lifecycle.py runs/<ts>` |
| waf_profile.py | `D:\PythonSource\PythonProjects\PythonProject4\waf_profile.py` | WAF/拦截画像合成：零请求聚合 candidate_exposures/sqli_candidates/second_pass/light_verify 的 4xx 证据，每 host 出拦截层/统一拦截页判定，防 WAF 差异被误读成业务信号 | 见 --help | waf_profile.jsonl、reports/waf_profile.md | 纯离线 | `python waf_profile.py --run-dir runs/<ts>` |
| light_diff_probe.py | `D:\PythonSource\PythonProjects\PythonProject4\light_diff_probe.py` | 标准化只读差分探针（baseline/quote/dquote/boolean/empty），统一限速/元数据落盘/连续拦截提前停——替代 AI 手搓探测脚本；须 .venv | 见 --help | --out 指定 jsonl（元数据） | 只读 GET；并发1；delay 默认 3s；预算默认 8 请求/URL | `.venv/Scripts/python.exe light_diff_probe.py --url "https://x/api?q=1" --probes baseline,quote` |
| import_run_to_engagement.py | `D:\PythonSource\PythonProjects\PythonProject4\import_run_to_engagement.py` | 一键流程→深挖交接：把 run 的 api_confirmed/interesting/candidates 导入 engagement 的 endpoint-inventory.csv 种子行（去重、全 untested） | 见 --help | engagements/<名>/artifacts/endpoint-inventory.csv 追加 | 纯离线 | `python import_run_to_engagement.py --run-dir runs/<ts> --engagement engagements/<名-日期>` |
| metrics_weekly.py | `D:\PythonSource\PythonProjects\PythonProject4\metrics_weekly.py` | W10 周度度量：扫 runs/*/ 聚五指标（候选数/确认率/FP率/假设命中率），出周报+history | 见 --help | reports/metrics_YYYYMMDD.md、metrics_history.jsonl | 纯离线 | `python metrics_weekly.py --days 7` |
| oob_listener.py | `D:\PythonSource\PythonProjects\PythonProject4\oob_listener.py` | W11 OOB 回调监听（默认8899）：每请求记 {token,src_ip,ts} 到 oob_hits.jsonl；--pull 拉 VPS 命中 | 见 --help | oob_hits.jsonl | 本地监听；VPS 部署需随机前缀 | `python oob_listener.py --port 8899 --prefix ab12cd` |
| race_triage.py | `D:\PythonSource\PythonProjects\PythonProject4\race_triage.py` | W8 竞态执行器：三模式(h2单包/last-byte/barrier)测 check-then-act；矩阵判据只出 limit_overrun 布尔 | 见 --help | race_results.jsonl（基线vs并发矩阵） | 必须 .venv；写端点需 write_risk_ack==true；并发≤30 | `python race_triage.py --config race_config.json` |
| ssrf_triage.py | `D:\PythonSource\PythonProjects\PythonProject4\ssrf_triage.py` | W11 SSRF 探测：可疑参数筛出后 OOB token 注入 + 时间盲双路；POST 只静态候选不自动发 | 见 --help | <run_dir>/ssrf_candidates.jsonl | 只读 GET；delay≥3s；每host≤5端点 | `python ssrf_triage.py --run-dir runs/<ts> --endpoints api_confirmed.jsonl --oob http://vps:8899/xx` |
| whitebox_triage.py | `D:\PythonSource\PythonProjects\PythonProject4\whitebox_triage.py` | W13 白盒 sink 流水线：sink_lib(62条) 正则扫 .js/.wxml/.json，出命中±3行上下文供配方F研判 | 见 --help | sink_findings.jsonl、whitebox_review.md | 纯离线 | `python whitebox_triage.py --source-dir unpacked/<appid> --out-dir <dir> --scan` |
| xss_verify_headless.py | `D:\PythonSource\PythonProjects\PythonProject4\xss_verify_headless.py` | W12 XSS 执行确认：读反射候选，dalfox→playwright→stdlib 三级引擎判 executable/context_safe | 见 --help | <run_dir>/xss_verified.jsonl | 只验证 GET 反射；marker 唯一；403连续即停 | `python xss_verify_headless.py --run-dir runs/<ts>` |
| gov_exercise_runner.py | `D:\PythonSource\PythonProjects\PythonProject4\gov_exercise_runner.py` | 主编排器：73 个 CLI 参数、30+ phase 编排、--resume-run-dir 断点续跑；所有新 phase 的挂载点 | 见 --help | runs/<ts>/ 全套（run_summary.json、00_重要_人工复核入口/、各 *_candidates.jsonl） | 只读编排（含审批门 phase 的显式参数） | `python gov_exercise_runner.py --targets targets.txt --probe --fingerprint --sqli-triage` |
| one_click_workflow.py | `D:\PythonSource\PythonProjects\PythonProject4\one_click_workflow.py` | 一键完整流程 bat 的调用对象：子域→活性→指纹→triage→弱口令复核→证据；--no-subdomain 可跳过子域爆破 | 见 --help | runs/<ts>/ 全套 | 只读（弱口令复核阶段内有人工门） | `python one_click_workflow.py --mode full --targets 目标文件.txt --second-pass-sql-limit 10` |
| sqli_triage.py | `D:\PythonSource\PythonProjects\PythonProject4\sqli_triage.py` | SQLi 三合一探测：请求预算 16/参数、基线差分、marker 确认；只对发现的参数化 GET URL 低影响探测 | 见 --help | sqli_candidates.jsonl / sqli_reflection_checks.jsonl | 只读探测（禁时间盲注/UNION/堆叠/dump） | `python sqli_triage.py --run-dir runs/<ts>` |
| xss_candidate_triage.py | `D:\PythonSource\PythonProjects\PythonProject4\xss_candidate_triage.py` | XSS 反射候选：从参数化 URL 构造候选并做 GET 反射探测 | 见 --help | xss_candidates.jsonl / xss_reflection_checks.jsonl | 只读 | `python xss_candidate_triage.py --run-dir runs/<ts>` |
| shiro_triage.py | `D:\PythonSource\PythonProjects\PythonProject4\shiro_triage.py` | Shiro 轻量筛选：基线 GET + 无效 rememberMe cookie 探测，只存元数据/哈希/Set-Cookie 名；置信度 high/medium 信号排序（shiro_triage.py:231-258） | 见 --help | shiro_candidates.jsonl / shiro_triage_results.jsonl / shiro_manual_queue.csv | 只读（爆破 key / 序列化 payload = 审批门） | `python shiro_triage.py --run-dir runs/<ts>` |
| shiro_bypass_review.py | `D:\PythonSource\PythonProjects\PythonProject4\shiro_bypass_review.py` | Shiro 轻量筛选第 2 级：--plan 离线读 shiro_candidates.jsonl，high/medium 按 URL 去重合并成审批队列（low 不入队）；--review 对 approved 行做只读 GET 路径变体 | 见 --help | shiro_bypass_approval_queue.csv / shiro_bypass_approval_queue.jsonl / shiro_bypass_approval_required.md | --plan 离线零请求；--review 只读 GET | `python shiro_bypass_review.py --run-dir runs/<ts> --plan` |
| authenticated_session_review.py | `D:\PythonSource\PythonProjects\PythonProject4\authenticated_session_review.py` | 认证态复核：读 sessions.jsonl / auth_sessions.local.json，对需登录的业务 API 复核（只读） | 见 --help | auth_sessions.template.json / 认证态复核队列 | 只读；凭证只被本地脚本读 | `python authenticated_session_review.py --run-dir runs/<ts> --sessions sessions.jsonl` |
| product_triage.py | `D:\PythonSource\PythonProjects\PythonProject4\product_triage.py` | OA/ERP/CMS/框架/中间件产品识别（离线指纹映射） | 见 --help | product_candidates.jsonl | 只读 | `python product_triage.py --run-dir runs/<ts>` |
| fingerprint_deepening.py | `D:\PythonSource\PythonProjects\PythonProject4\fingerprint_deepening.py` | 指纹深化：产品/框架 → 安全后续检查点映射（离线） | 见 --help | fingerprint_deepening.jsonl | 只读/离线 | `python fingerprint_deepening.py --run-dir runs/<ts>` |
| tool_fingerprint_httpx.py | `D:\PythonSource\PythonProjects\PythonProject4\tool_fingerprint_httpx.py` | httpx 技术检测（单目标、外置延迟），fingerprint phase 的主工具 | 见 --help | httpx_fingerprint.jsonl | 只读 | `python tool_fingerprint_httpx.py --run-dir runs/<ts>` |
| api_discovery.py | `D:\PythonSource\PythonProjects\PythonProject4\api_discovery.py` | JS/流量解析发现 API 候选（crawl_api_js phase 主工具） | 见 --help | api_candidates.jsonl / api_interesting.jsonl | 只读 | `python api_discovery.py --run-dir runs/<ts>` |
| api_endpoint_confirm.py | `D:\PythonSource\PythonProjects\PythonProject4\api_endpoint_confirm.py` | API 端点确认：只确认有界的只读 GET 类候选；跳过 upload/import 等风险动词 | 见 --help | api_confirmed.jsonl | 只读 | `python api_endpoint_confirm.py --run-dir runs/<ts>` |
| second_pass_triage.py | `D:\PythonSource\PythonProjects\PythonProject4\second_pass_triage.py` | 二轮复核 triage：对候选集中做轻量深度确认 | 见 --help | second_pass_candidates.jsonl | 只读 | `python second_pass_triage.py --run-dir runs/<ts>` |
| deep_readonly_triage.py | `D:\PythonSource\PythonProjects\PythonProject4\deep_readonly_triage.py` | 深度只读 triage（保守模式用） | 见 --help | deep_readonly_candidates.jsonl | 只读 | `python deep_readonly_triage.py --run-dir runs/<ts>` |
| readonly_endpoint_confirm.py | `D:\PythonSource\PythonProjects\PythonProject4\readonly_endpoint_confirm.py` | 只读端点确认 | 见 --help | readonly_confirmed.jsonl | 只读 | `python readonly_endpoint_confirm.py --run-dir runs/<ts>` |
| readonly_config_probe.py | `D:\PythonSource\PythonProjects\PythonProject4\readonly_config_probe.py` | 只读配置探测（保守模式） | 见 --help | readonly_config_candidates.jsonl | 只读 | `python readonly_config_probe.py --run-dir runs/<ts>` |
| fastjson_triage.py | `D:\PythonSource\PythonProjects\PythonProject4\fastjson_triage.py` | fastjson 只读反格式化探测（类型错误/语法错误/嵌套解析），无 RCE payload | 见 --help | fastjson_candidates.jsonl | 只读 | `python fastjson_triage.py --run-dir runs/<ts>` |
| struts2_triage.py | `D:\PythonSource\PythonProjects\PythonProject4\struts2_triage.py` | struts2 只读指纹探测（默认 action 后缀/showcase/devMode/OGNL 错误标记） | 见 --help | struts2_candidates.jsonl | 只读 | `python struts2_triage.py --run-dir runs/<ts>` |
| tomcat_triage.py | `D:\PythonSource\PythonProjects\PythonProject4\tomcat_triage.py` | tomcat/weblogic 只读探测（ajp 8009 / t3 7001 / http 8080 连接检查 + 版本/manager/console） | 见 --help | tomcat_weblogic_candidates.jsonl | 只读 | `python tomcat_triage.py --run-dir runs/<ts>` |
| nacos_triage.py | `D:\PythonSource\PythonProjects\PythonProject4\nacos_triage.py` | nacos 只读探测（admin/console 小集合端点状态码） | 见 --help | nacos_candidates.jsonl | 只读 | `python nacos_triage.py --run-dir runs/<ts>` |
| redis_triage.py | `D:\PythonSource\PythonProjects\PythonProject4\redis_triage.py` | redis/elasticsearch/zookeeper 只读探测（PING/INFO banner、GET / 状态、connect+ruok） | 见 --help | redis_es_zk_candidates.jsonl | 只读 | `python redis_triage.py --run-dir runs/<ts>` |
| springboot_triage.py | `D:\PythonSource\PythonProjects\PythonProject4\springboot_triage.py` | springboot 只读指纹 + actuator 端点探测（env/heapdump 仅状态码存在性） | 见 --help | springboot_candidates.jsonl | 只读 | `python springboot_triage.py --run-dir runs/<ts>` |
| healthcare_privacy_triage.py | `D:\PythonSource\PythonProjects\PythonProject4\healthcare_privacy_triage.py` | 医疗隐私数据专项：患者身份/就诊/诊断/处方/LIS/PA 端点的只读 schema 复核 | 见 --help | healthcare_candidates.jsonl | 只读 | `python healthcare_privacy_triage.py --run-dir runs/<ts>` |
| header_reflection_probe.py | `D:\PythonSource\PythonProjects\PythonProject4\header_reflection_probe.py` | Header 注入反射探测（只读 marker） | 见 --help | header_reflection_candidates.jsonl | 只读 | `python header_reflection_probe.py --run-dir runs/<ts>` |
| weak_credential_review.py | `D:\PythonSource\PythonProjects\PythonProject4\weak_credential_review.py` | 弱口令复核（审批门）：读 run-dir 的登录面，默认 ≤3 目标/≤5 口令组、delay 3、首次成功即停；凭证不落盘 | 见 --help | weak_credential_manifest.json / weak_credential_successes.jsonl | 审批门双钥匙，缺一不可 | `python weak_credential_review.py --run-dir runs/<ts> --max-targets 1 --max-pairs 5 --delay 3` |
| evidence_builder.py | `D:\PythonSource\PythonProjects\PythonProject4\evidence_builder.py` | 证据构建：proven 级发现的报告装订（攻击成果.docx 模板） | 见 --help | 攻击成果.docx 报告 | 本地离线 | `python evidence_builder.py --run-dir runs/<ts>` |
| result_prioritizer.py | `D:\PythonSource\PythonProjects\PythonProject4\result_prioritizer.py` | 结果优先级排序：从全部候选压缩 TOP 列表（report phase 主工具） | 见 --help | priority_targets.json / priority_review.md | 本地离线 | `python result_prioritizer.py --run-dir runs/<ts>` |
| review_intelligence.py | `D:\PythonSource\PythonProjects\PythonProject4\review_intelligence.py` | 复核情报：跨 run 聚合候选与模式 | 见 --help | review_intelligence.jsonl | 本地离线 | `python review_intelligence.py --run-dir runs/<ts>` |
| run_health.py | `D:\PythonSource\PythonProjects\PythonProject4\run_health.py` | run 健康检查：health 分、missing tools、异常信号 | 见 --help | run_health.json | 本地离线 | `python run_health.py --run-dir runs/<ts>` |
| parallel_flow_runner.py | `D:\PythonSource\PythonProjects\PythonProject4\parallel_flow_runner.py` | 并行流程子 runner（已有子域名场景，按根域分组最多 3 批） | 见 --help | runs/<ts> 子流程产物 | 只读 | `python parallel_flow_runner.py --subdomains 子域名清单.txt` |
| subdomain_collector.py | `D:\PythonSource\PythonProjects\PythonProject4\subdomain_collector.py` | 子域名收集入口 | 见 --help | subdomains.jsonl / subdomains_for_scope_confirmation.txt | 只读（DNS 查询） | `python subdomain_collector.py --targets targets.txt` |
| subdomain_bruteforce_controlled.py | `D:\PythonSource\PythonProjects\PythonProject4\subdomain_bruteforce_controlled.py` | 受控子域爆破（低频 DNS 发现，产出先归类确认再探测） | 见 --help | subdomains_bruteforce.txt | 只读（受控低速率） | `python subdomain_bruteforce_controlled.py --targets targets.txt` |
| decrypt_wxapkg.py | `D:\PythonSource\PythonProjects\PythonProject4\decrypt_wxapkg.py` | 小程序 wxapkg 批量解密 + 域名提取 | 见 --help | tools/miniapp_extract/ 解密产物 | 离线 | `python decrypt_wxapkg.py <wxapkg路径>` |
| analyze_wx_miniapp_source.py | `D:\PythonSource\PythonProjects\PythonProject4\analyze_wx_miniapp_source.py` | 小程序源码树分析（白盒入口） | 见 --help | miniapp_analysis.jsonl | 离线 | `python analyze_wx_miniapp_source.py --source-dir unpacked/wxXXX` |
| analyze_js_static.py | `D:\PythonSource\PythonProjects\PythonProject4\analyze_js_static.py` | JS 静态分析（含 .min.js beautify，供白盒 sink 定位参考） | 见 --help | js_analysis.jsonl | 离线 | `python analyze_js_static.py --run-dir runs/<ts>` |
| batch_runner.py | `D:\PythonSource\PythonProjects\PythonProject4\batch_runner.py` | 批量子 runner（阶段内分批执行） | 见 --help | 批次产物 + 游标 | 只读 | `python batch_runner.py --run-dir runs/<ts>` |

## 工具策略（tool_strategy.json 全部 phase）

### scope
- primary：`runner_allowlist`；backup：`manual_review`（mode=on_mismatch）
- 说明：Classification and scope decisions must have one source of truth.
- primary 风险级：**只读**；外部工具路径：—；输出：见对应 runner 输出契约

### subdomain
- primary：`subdomain_bruteforce_controlled.py`；backup：`oneforall_or_certificate_transparency`（mode=controlled_discovery_then_scope_confirmation）
- 说明：Run low-rate DNS discovery in the full one-click flow, then feed resolved hosts through scope confirmation before HTTP probing.
- primary 风险级：**只读**；外部工具路径：—；输出：见对应 runner 输出契约
- backup：`oneforall_or_certificate_transparency`（风险级 **只读**）；路径：—

### alive_probe
- primary：`runner_http_probe`；backup：`httpx`（mode=sample_failures_and_edge_cases）
- 说明：Do not run two liveness probes full-scope unless the first output is incomplete.
- primary 风险级：**只读**；外部工具路径：—；输出：见对应 runner 输出契约
- backup：`httpx`（风险级 **只读**）；路径：D:\PythonSource\PythonProjects\PythonProject4/tools/managed/httpx/1.9.0/httpx.exe（存在）; D:/Desktop/天狐渗透工具箱-社区版V3.0+4.0更新升级包/天狐渗透工具箱-社区版V3.0/tools/gui_scan/fcke/httpx.exe（存在）

### fingerprint
- primary：`tool_fingerprint_httpx.py`；backup：`runner_rules_or_ehole_tidefinger_sample`（mode=rate_controlled_tool_first）
- 说明：Use httpx technology detection one target at a time with an outer delay; keep runner rules as fallback categories.
- primary 风险级：**只读**；外部工具路径：—；输出：见对应 runner 输出契约
- backup：`runner_rules_or_ehole_tidefinger_sample`（风险级 **只读**）；路径：—

### product_aware_triage
- primary：`product_triage.py`；backup：`oa-exptool_or_dddd/nuclei_template_inventory`（mode=offline_map_then_manual_confirm）
- 说明：Identify the specific OA/ERP/CMS/framework/middleware product offline, then map it to a bounded tool branch. Never launch product exploit templates automatically.
- primary 风险级：**只读**；外部工具路径：—；输出：见对应 runner 输出契约
- backup：`oa-exptool_or_dddd/nuclei_template_inventory`（风险级 **只读**）；路径：—

### fingerprint_deepening
- primary：`fingerprint_deepening.py`；backup：`manual_template_review`（mode=offline_plan_then_single_target_manual_followup）
- 说明：Map detected products/frameworks to safe follow-up checks, local tool/template candidates, command previews, and approval gates. Do not execute tools automatically.
- primary 风险级：**只读**；外部工具路径：—；输出：见对应 runner 输出契约

### crawl_api_js
- primary：`api_discovery.py_plus_katana`；backup：`packerfuzzer_or_manual_proxy`（mode=controlled_crawl_then_builtin_parser）
- 说明：One-click enables Katana with depth=2, concurrency=1, parallelism=1, rate-limit=1, and delay; built-in parsing still normalizes candidates.
- primary 风险级：**只读**；外部工具路径：—；输出：见对应 runner 输出契约
- backup：`packerfuzzer_or_manual_proxy`（风险级 **只读**）；路径：—

### wechat_miniapp_discovery
- primary：`wechat_miniapp_discovery.py`；backup：`manual_wechat_or_search_review`（mode=confirm_candidates_and_scope）
- 说明：Generate mini-program, official-account, QR-code, and search-dork clues. Feed only authorized source domains from wechat_subdomain_scan_targets.txt back into subdomain/alive scanning; keep WeChat platform and third-party links pending review.
- primary 风险级：**只读**；外部工具路径：—；输出：见对应 runner 输出契约

### api_endpoint_confirm
- primary：`api_endpoint_confirm.py`；backup：`manual_browser_or_proxy`（mode=review_interesting_json_only）
- 说明：Confirm bounded GET-like API candidates only. Skip risky verbs such as upload, import, export, download, delete, update, save, pay, password, and file.
- primary 风险级：**只读**；外部工具路径：—；输出：见对应 runner 输出契约

### xss_candidate_screening
- primary：`xss_candidate_triage.py`；backup：`nuclei_or_dalfox_or_xsstrike`（mode=single_candidate_manual_validation_only）
- 说明：Build XSS candidates from discovered parameterized URLs and optionally send one inert GET marker per safe parameter. Stored/blind/script-payload validation and full-scope external scanners are not default automation.
- primary 风险级：**只读**；外部工具路径：—；输出：见对应 runner 输出契约
- backup：`nuclei_or_dalfox_or_xsstrike`（风险级 **只读**）；路径：—

### authenticated_session_review
- primary：`authenticated_session_review.py`；backup：`manual_browser_or_proxy`（mode=confirm_high_value_authenticated_candidates）
- 说明：The runner creates a manual login/registration queue. After the operator supplies a valid local session file, review same-host JS and bounded GET-like APIs. Never persist cookies, response values, or downloaded files.
- primary 风险级：**只读**；外部工具路径：—；输出：见对应 runner 输出契约

### idor_diff
- primary：`idor_triage.py`；backup：`manual_curl_differential`（mode=None）
- 说明：IDOR 水平越权差分：基线A/B重放/匿名三请求，结构指纹+Jaccard 判据；只读 GET/HEAD；需同host≥2凭证（sessions.jsonl）；delay≥3s、每host≤5端点；A凭证401/302即停该host
- primary 风险级：**只读**；外部工具路径：—；输出：见对应 runner 输出契约
- backup：`manual_curl_differential`（风险级 **只读**）；路径：—

### healthcare_privacy_triage
- primary：`healthcare_privacy_triage.py`；backup：`manual_browser_or_proxy`（mode=schema_only_then_single_endpoint_review）
- 说明：Prioritize patient identity, encounter, diagnosis, prescription, LIS/PACS, billing, insurance, follow-up, and mental-health field names. Store endpoint paths, parameter names, field names, counts, and hashes only; never retain patient values, bodies, reports, or images.
- primary 风险级：**只读**；外部工具路径：—；输出：见对应 runner 输出契约

### high_value_paths
- primary：`runner_high_value_path_set`；backup：`manual_browser_or_proxy`（mode=manual_confirm_only）
- 说明：Keep the path set small and deterministic.
- primary 风险级：**只读**；外部工具路径：—；输出：见对应 runner 输出契约

### truth_verify
- primary：`runner_truth_verification`；backup：`manual_review`（mode=review_borderline_scores）
- 说明：Use one consistent scoring algorithm to avoid inconsistent claims.
- primary 风险级：**只读**；外部工具路径：—；输出：见对应 runner 输出契约

### template_validation
- primary：`nuclei`；backup：`afrog`（mode=confirm_verified_candidates）
- 说明：Use the pinned managed Nuclei engine and reviewed templates as the general core; use afrog mainly for confirmed Chinese OA products. Filter by technology, severity, and intrusiveness, and never run approval-gated templates automatically.
- primary 风险级：**只读**；外部工具路径：D:\PythonSource\PythonProjects\PythonProject4/tools/managed/nuclei/3.8.0/nuclei.exe（存在）; D:/Desktop/天狐渗透工具箱-社区版V3.0+4.0更新升级包/天狐渗透工具箱-社区版V3.0/tools/gui_scan/nuclei/nuclei.exe（存在）；输出：nuclei_results.jsonl
- backup：`afrog`（风险级 **只读**）；路径：D:\PythonSource\PythonProjects\PythonProject4/tools/managed/afrog/3.5.3/afrog.exe（存在）; D:\PythonSource\PythonProjects\PythonProject4/tools/afrog.exe（存在）

### shiro_candidate_screening
- primary：`shiro_triage.py`；backup：`manual_browser_or_proxy`（mode=review_positive_candidates）
- 说明：Detect Shiro rememberMe behavior with baseline GET plus invalid rememberMe cookie only. Do not brute force keys or send serialized payloads in the default flow.
- primary 风险级：**只读**；外部工具路径：—；输出：见对应 runner 输出契约

### shiro_validation
- primary：`ShiroAttack2`；backup：`manual_request_review`（mode=confirm_single_candidate_only）
- 说明：Use only on one authorized candidate target at a time for key/rememberMe verification. Command execution, memory shell, upload, and persistence features are approval-gated and disabled by default.
- primary 风险级：**审批门**；外部工具路径：—；输出：shiro_success.txt（人工确认后）

### sqli_candidate_screening
- primary：`sqli_triage.py`；backup：`vuln_sqli_pure.py_or_manual_request_diff_review`（mode=review_positive_and_borderline_candidates）
- 说明：Retain the shallow SQLi check but do not launch broad or proactive SQL injection scanning. Test only already-discovered parameterized GET URLs with strict per-host, parameter, request, delay, and stop limits. Never enumerate databases or retrieve data; 500/status deltas are candidates, not proof.
- primary 风险级：**只读**；外部工具路径：—；输出：见对应 runner 输出契约
- backup：`vuln_sqli_pure.py_or_manual_request_diff_review`（风险级 **只读**）；路径：—

### sqli_validation
- primary：`sqlmap`；backup：`manual_request_diff_review`（mode=confirm_single_candidate_only）
- 说明：Use only on one high-probability or operator-approved candidate URL at a time with risk=1, level=1, technique BE, delay, request caps, and no database dumping or destructive options.
- primary 风险级：**审批门**；外部工具路径：D:/Desktop/天狐渗透工具箱-社区版V3.0+4.0更新升级包/天狐渗透工具箱-社区版V3.0/tools/gui_scan/sqlmap/sqlmap.py（存在）; D:\PythonSource\PythonProjects\PythonProject4/sqlmap/sqlmap.py（缺失）；输出：sqlmap 会话目录（无 dump）
- backup：`manual_request_diff_review`（风险级 **只读**）；路径：—

### springboot_candidate_screening
- primary：`springboot_triage.py`；backup：`manual_browser_or_proxy`（mode=review_positive_candidates）
- 说明：Read-only fingerprint plus actuator endpoint probes (env/heapdump only as status-code existence checks). Do not download heapdump files or dump memory in the default flow.
- primary 风险级：**只读**；外部工具路径：—；输出：见对应 runner 输出契约

### springboot_validation
- primary：`SpringBoot-Scan.py`；backup：`nuclei_templates_springboot_actuator_full`（mode=confirm_single_candidate_only）
- 说明：CLI: python tools/managed/springbootscan/SpringBoot-Scan-main/SpringBoot-Scan.py -u <url> (GitHub AabyssZG v2.7.2; needs Defender exclusion for its inc/poc.py which is flagged Exploit:Python/SpringShell.SGA!MSR - verified enabled on this host). Headless use: pipe an empty/0 line to answer the interactive delay prompt (e.g. echo '0' | python SpringBoot-Scan.py -u <url>). -v/-d exploit and heapdump-download modes are approval-gated. Nuclei springboot actuator set is the backup: detection-only downloads (heapdump/env/logfile content-feature checks, never archived). Verified on local sim: 8 actuator infoleak URLs found; nuclei heapdump critical hit.
- primary 风险级：**审批门**；外部工具路径：—；输出：springbootscan_report.txt
- backup：`nuclei_templates_springboot_actuator_full`（风险级 **只读**）；路径：—

### fastjson_candidate_screening
- primary：`fastjson_triage.py`；backup：`manual_browser_or_proxy`（mode=review_positive_candidates）
- 说明：Read-only deformatter checks only (type error, syntax error, nested parse). No RCE payloads or DNS lookups in the default flow.
- primary 风险级：**只读**；外部工具路径：—；输出：见对应 runner 输出契约

### fastjson_validation
- primary：`FastjsonScan.exe`；backup：`nuclei_templates_fastjson_1_2_24_68_rce`（mode=confirm_single_candidate_only）
- 说明：CLI only: FastjsonScan.exe -u <url> [-o result.txt]. Detects version ranges (1.2.48/1.2.68/1.2.80), autoType status, dependency library, and error/DNS/latency probes. Any real RCE/out-of-band exploitation beyond probes is approval-gated. Use on one authorized candidate at a time.
- primary 风险级：**审批门**；外部工具路径：—；输出：fastjsonscan_result.txt
- backup：`nuclei_templates_fastjson_1_2_24_68_rce`（风险级 **只读**）；路径：—

### struts2_candidate_screening
- primary：`struts2_triage.py`；backup：`manual_browser_or_proxy`（mode=review_positive_candidates）
- 说明：Read-only fingerprint probes only: default action suffix, showcase, devMode, OGNL error markers. No exploitation or OGNL evaluation in the default flow.
- primary 风险级：**只读**；外部工具路径：—；输出：见对应 runner 输出契约

### struts2_validation
- primary：`Struts2Scan.py`；backup：`nuclei_templates_struts_cves_5638_11776_17530_31805`（mode=confirm_single_candidate_only）
- 说明：CLI only: python tools/managed/struts2scan/Struts2-Scan-master/Struts2Scan.py -u <url> for S2-001-S2-057 plus devMode (local copy patched: -n name check uses s2_dict instead of class list to fix always-unsupported bug). Nuclei backup covers S2-045/S2-057/S2-061/S2-062 and executes payloads (cat /etc/passwd matcher) - intrusive, approval-gated. Verified end-to-end on local sim: 4/4 struts CVE templates hit.
- primary 风险级：**审批门**；外部工具路径：—；输出：struts2scan_report.txt
- backup：`nuclei_templates_struts_cves_5638_11776_17530_31805`（风险级 **只读**）；路径：—

### tomcat_weblogic_candidate_screening
- primary：`tomcat_triage.py`；backup：`manual_browser_or_proxy`（mode=review_positive_candidates）
- 说明：Read-only probes: TCP connect checks for ajp 8009, t3 7001, http 8080 plus version/manager/console existence markers. No payloads.
- primary 风险级：**只读**；外部工具路径：—；输出：见对应 runner 输出契约

### tomcat_weblogic_validation
- primary：`nuclei`；backup：`manual_request_review`（mode=confirm_single_candidate_only）
- 说明：Pinned managed Nuclei engine with reviewed templates only: ghostcat CVE-2020-1938 (network), weblogic CVE-2019-2725/CVE-2020-14882/CVE-2018-2894/CVE-2023-21839, tomcat manager/default-login/jolokia-creds-leak. Verified end-to-end on local sim: ghostcat critical hit; CVE-2020-14882 critical hit and CVE-2023-21839 high hit via self-hosted interactsh (public oast.pro unreachable from this network). Local OOB stack: interactsh-server -d 127.0.0.1 -http-port 8000 -dns-port 30053 -lip 127.0.0.1 -sa (domain MUST equal the nuclei server IP form, i.e. -d 127.0.0.1, else DNS callbacks are not matched), then nuclei -iserver http://127.0.0.1:8000. Independent CLI for 21839: tools\managed\weblogic21839\POC_CVE-2023-21839\CVE-2023-21839.py -ip <t> -p 7001 -l ldap://<oast>/x (pure T3/IIOP handshake, verified 7/7 steps on sim). Approval-gated RCE templates never auto-run; per-host template caps apply.
- primary 风险级：**只读**；外部工具路径：D:\PythonSource\PythonProjects\PythonProject4/tools/managed/nuclei/3.8.0/nuclei.exe（存在）; D:/Desktop/天狐渗透工具箱-社区版V3.0+4.0更新升级包/天狐渗透工具箱-社区版V3.0/tools/gui_scan/nuclei/nuclei.exe（存在）；输出：nuclei_results.jsonl

### nacos_candidate_screening
- primary：`nacos_triage.py`；backup：`manual_browser_or_proxy`（mode=review_positive_candidates）
- 说明：Read-only probe of a small set of admin/console endpoints; record status codes and key-value existence only, never contents of sensitive configuration.
- primary 风险级：**只读**；外部工具路径：—；输出：见对应 runner 输出契约

### nacos_validation
- primary：`nuclei`；backup：`manual_request_review`（mode=confirm_single_candidate_only）
- 说明：Pinned managed Nuclei templates only: nacos-auth-bypass, nacos-authentication-bypass, nacos-info-leak, nacos-create-user, nacos-default-login. Do not create users or mutate configuration in the default flow; those require explicit approval.
- primary 风险级：**只读**；外部工具路径：D:\PythonSource\PythonProjects\PythonProject4/tools/managed/nuclei/3.8.0/nuclei.exe（存在）; D:/Desktop/天狐渗透工具箱-社区版V3.0+4.0更新升级包/天狐渗透工具箱-社区版V3.0/tools/gui_scan/nuclei/nuclei.exe（存在）；输出：nuclei_results.jsonl

### redis_es_zk_candidate_screening
- primary：`redis_triage.py`；backup：`manual_browser_or_proxy`（mode=review_positive_candidates）
- 说明：Read-only probes: Redis PING/INFO banner, Elasticsearch GET / status, ZooKeeper connect + ruok. No command execution, no data reads beyond banners.
- primary 风险级：**只读**；外部工具路径：—；输出：见对应 runner 输出契约

### redis_es_zk_validation
- primary：`nuclei`；backup：`manual_request_review`（mode=confirm_single_candidate_only）
- 说明：Pinned managed Nuclei templates only: exposed-redis/redis-config/redis-info, elasticsearch detect and known info-leak templates. Actual key/value reads or config writes require explicit approval.
- primary 风险级：**只读**；外部工具路径：D:\PythonSource\PythonProjects\PythonProject4/tools/managed/nuclei/3.8.0/nuclei.exe（存在）; D:/Desktop/天狐渗透工具箱-社区版V3.0+4.0更新升级包/天狐渗透工具箱-社区版V3.0/tools/gui_scan/nuclei/nuclei.exe（存在）；输出：nuclei_results.jsonl

### custom_probe_policy
- primary：`mature_tool_or_manual_review_for_validation`；backup：`custom_scripts_for_candidate_screening`（mode=candidate_screening_only）
- 说明：Custom scripts such as vuln_sqli_pure.py, vuln_lfi.py, vuln_rce.py, vuln_ssti.py, weak_passwd_scanner.py, and upload/RCE helpers are not authoritative validators by default. Use them as low-rate candidate screeners or wrappers, then validate with a mature tool, manual request review, or explicit approval-gated minimal proof.
- primary 风险级：**只读**；外部工具路径：—；输出：见对应 runner 输出契约
- backup：`custom_scripts_for_candidate_screening`（风险级 **只读**）；路径：—

### directory_fuzz
- primary：`dirsearch_or_ffuf`；backup：`manual_browser_or_proxy`（mode=important_targets_only）
- 说明：Use small curated wordlists and low rate. Avoid broad recursion by default.
- primary 风险级：**只读**；外部工具路径：—；输出：见对应 runner 输出契约

### report
- primary：`result_prioritizer_and_evidence_builder`；backup：`manual_review`（mode=human_quality_check）
- 说明：Review priority_targets.json and run_health.json before report drafting.
- primary 风险级：**只读**；外部工具路径：—；输出：见对应 runner 输出契约

---
*本清单由生成器维护；修改工具/phase 后重跑 `python scripts/gen_agent_manifest.py`。*