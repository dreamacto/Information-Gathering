# 政务专场安全调度层

这套脚本用于把授权目标、工具、证据和限速策略统一到项目内。默认是低速、只读、证据导向，不会自动跑弱口令、爆破、写入型上传、webshell、内网扫描或数据导出。

## 主要文件

- `gov_exercise_runner.py`: 主入口，导入目标、创建 `runs/`、检查工具、低速探活、分类、固定高价值路径、JS/API 深挖。
- `api_discovery.py`: 新增的只读 JS/API 发现器，会抓首页、robots、sitemap、Swagger/OpenAPI、同站 JS，并提取高价值接口线索。
- `api_endpoint_confirm.py`: 对发现的高优先级 GET 风格 API 做限量只读确认，只保存元信息和 JSON 结构。
- `tool_assisted_triage.py`: 成熟工具受控编排器，默认只生成 nuclei 命令计划，明确 `--execute` 后才会低速执行。
- `result_prioritizer.py`: 离线结果汇总器，把候选、API 线索、指纹和工具结果合并成高价值复核队列。
- `operator_action_hub.py`: 每轮结束自动生成 `00_重要_人工复核入口/`，把登录拿 Cookie、业务 API 只读复核、弱口令人工确认和可报告候选集中起来。
- `fingerprint_deepening.py`: 离线指纹后深入分支规划器，把产品/框架/中间件指纹映射到安全复核项、本地工具/模板候选和审批队列；不自动执行工具。
- `review_intelligence.py`: 离线 P0-P3 候选总表和每目标画像生成器，合并二次复测、API、产品、指纹后深入分支、SQLi、XSS、弱口令等线索。
- `weak_credential_review.py`: 显式弱口令复核阶段，默认不运行；只有命令行加 `--weak-credential-review` 才会对队列里的登录面做最多 5 组动态组合尝试；额外加 `--weak-credential-auto-auth-review` 时，成功登录当次响应里的 Cookie/JWT 会只在内存中接入认证态只读复核。
- `tools/browser_xhr_capture.mjs`: 浏览器辅助 XHR/FETCH 采集器；你手工登录和点击业务功能后，生成高价值接口、越权复核队列，并可显式保存 `.local` 本地复现草稿。
- `miniapp_endpoint_offline.py`: 已解包小程序源码离线分析器，提取域名、接口常量、sign/鉴权线索和高价值复核队列，不主动访问目标。
- `run_health.py`: 离线健康评分，判断本次后台任务是否覆盖充分、是否假阳性过高。
- `exercise_runtime.py`: 路径、目标解析、运行目录、运行时和工具发现。
- `evidence_builder.py`: 生成日报草稿、平台提交模板和证据索引。
- `gov_exercise_config.json`: 天狐工具箱路径、常用工具候选路径、默认限速和禁用动作。
- `gov_exercise_workflow.json`: 机器可读完整流程。
- `tool_strategy.json`: 每阶段“一主一备”的工具策略。
- `skills/gx-gov-exercise/SKILL.md`: 给后续会话使用的项目 playbook。

## 推荐运行

只建运行目录和合规材料，不发网络请求：

```powershell
<python.exe> .\gov_exercise_runner.py --targets "D:\Desktop\all_alive_alive.txt"
```

低速完整只读流程：

```powershell
<python.exe> .\gov_exercise_runner.py --targets "D:\Desktop\all_alive_alive.txt" --probe --fingerprint --high-value-paths --shiro-triage --api-discovery --api-confirm --sqli-triage --delay 3
```

小批量试跑：

```powershell
<python.exe> .\gov_exercise_runner.py --targets "D:\Desktop\all_alive_alive.txt" --probe --fingerprint --high-value-paths --shiro-triage --api-discovery --api-confirm --sqli-triage --limit 10 --delay 3
```

如果安装或天狐中存在 `katana`，可以让 API 阶段先跑工具爬取，再走内置解析：

```powershell
<python.exe> .\gov_exercise_runner.py --targets "D:\Desktop\all_alive_alive.txt" --probe --fingerprint --high-value-paths --api-discovery --api-use-katana --delay 3
```

断点续跑：

```powershell
<python.exe> .\gov_exercise_runner.py --targets "D:\Desktop\all_alive_alive.txt" --resume-run-dir .\runs\YYYYMMDD_HHMMSS_gx_gov --probe --fingerprint --high-value-paths --shiro-triage --api-discovery --api-confirm --sqli-triage --delay 3
```

生成报告草稿：

```powershell
<python.exe> .\evidence_builder.py .\runs\YYYYMMDD_HHMMSS_gx_gov
```

当 run 目录存在 `confirmed_findings.json` / `confirmed_findings.jsonl`，或已有 `verified_exposures.jsonl` 结果时，`evidence_builder.py` 会按 `gov_exercise_config.json` 中的报告配置自动生成攻击成果 Word：

- 队伍名称：`观叶识微`
- 模板：`D:\Desktop\claude projects\attack and defend test\攻击成果模版\攻击成果.docx`
- 输出：`runs\<run>\reports\攻击成果_观叶识微_<时间>.docx`
- 截图：优先插入 `evidence/` 目录下已有图片；没有可用截图时在报告中写明 `【需截图】` 和需要截图的内容。

如只想生成 Markdown/JSON 草稿，可加：

```powershell
<python.exe> .\evidence_builder.py .\runs\YYYYMMDD_HHMMSS_gx_gov --no-attack-report
```

对 API/高价值线索做成熟工具复核，先生成命令计划：

```powershell
<python.exe> .\tool_assisted_triage.py --run-dir .\runs\YYYYMMDD_HHMMSS_gx_gov --source priority --tool nuclei --limit 20 --rate-limit 1 --concurrency 1
```

确认目标、模板范围和时间窗口后再执行：

```powershell
<python.exe> .\tool_assisted_triage.py --run-dir .\runs\YYYYMMDD_HHMMSS_gx_gov --source priority --tool nuclei --limit 20 --rate-limit 1 --concurrency 1 --execute
```

## 前台/后台运行与进程查看

前台完整流程命令：

```powershell
cd /d D:\PythonSource\PythonProjects\PythonProject4

& 'C:\Users\ASUS\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' .\gov_exercise_runner.py `
  --targets "<你的目标文件.txt>" `
  --probe `
  --fingerprint `
  --high-value-paths `
  --shiro-triage `
  --api-discovery `
  --api-confirm `
  --sqli-triage `
  --wechat-miniapp `
  --wechat-live `
  --wechat-max-js 3 `
  --delay 3
```

后台完整流程命令：

```powershell
Start-Process powershell -WindowStyle Hidden -ArgumentList @(
  '-NoProfile',
  '-ExecutionPolicy', 'Bypass',
  '-Command',
  'cd /d D:\PythonSource\PythonProjects\PythonProject4; & "C:\Users\ASUS\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" .\gov_exercise_runner.py --targets "<你的目标文件.txt>" --probe --fingerprint --high-value-paths --shiro-triage --api-discovery --api-confirm --sqli-triage --wechat-miniapp --wechat-live --wechat-max-js 3 --delay 3'
)
```

查看是否已经开始：

```powershell
Get-CimInstance Win32_Process |
  Where-Object { $_.CommandLine -like '*gov_exercise_runner.py*' } |
  Select-Object ProcessId, CommandLine
```

查看最新 run 目录：

```powershell
Get-ChildItem .\runs -Directory |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 5 Name, FullName, LastWriteTime
```

查看进度和关键结果：

```powershell
Get-Content <run_dir>\run_summary.json
Get-Content <run_dir>\reports\run_health.md
Get-Content <run_dir>\reports\priority_review.md
Get-Content <run_dir>\shiro_manual_queue.csv
Get-Content <run_dir>\sqli_high_probability.txt
Get-Content <run_dir>\sqli_500_or_error_anomalies.txt
```

停止后台进程：

```powershell
Get-CimInstance Win32_Process |
  Where-Object { $_.CommandLine -like '*gov_exercise_runner.py*' } |
  Select-Object ProcessId, CommandLine

Stop-Process -Id <ProcessId>
```

## 新流程

### 2026-07-26 主流程增强

- `一键完整流程_含弱口令.bat` 现在默认启用低速子域名发现，输出 `subdomains_for_scope_confirmation.txt` 和 `subdomains_for_next_run.txt`；新子域名先确认范围，再作为下一轮目标输入。
- 指纹识别新增 `tool_fingerprint_httpx.py`，用 httpx 一条一条探测并按全局 delay 控速，输出 `tool_fingerprints.jsonl/csv`。
- JS/API 深挖默认启用 Katana 增强，Katana 被限制为 depth=2、concurrency=1、parallelism=1、rate-limit=1，并带请求 delay。
- 产品队列新增 `product_vuln_candidate_queue.csv`、`product_vuln_candidates.jsonl` 和 `reports/product_vuln_candidate_queue.md`，覆盖 Fastjson、Log4j、Struts2、Spring Boot、Nacos、ThinkPHP、Shiro、泛微、致远、用友等候选项；默认只排队，不自动利用。
- 新增桌面入口 `一键保守全流程_尽量多信息_避WAF.bat`：保留低速子域名、探活、httpx 指纹、Katana/JS/API 信息收集、小批量 API 确认、SQLi/Shiro/XSS 候选筛选、二次轻量复测、指纹后深入分支、产品候选和小程序/微信离线线索，跳过高价值固定路径和弱口令。

```text
域名表
  -> 范围校验
  -> 子域名收集
  -> 存活探测
  -> 指纹识别
  -> 分类归档
  -> JS/API 深挖
  -> 高价值路径发现
  -> 真伪验证
  -> 风险分级/审批闸门
  -> 最小化漏洞验证
  -> 证据链生成
  -> 评分映射/成果报告
```

## 重点输出

- `00_重要_人工复核入口/README_先看这里.md`: 每轮结束后最先打开的文件，集中解释本轮最重要的人工动作。
- `00_重要_人工复核入口/00_P0-P3候选总表.md`: 合并二次复测、API、产品、指纹后深入分支、SQLi、XSS、弱口令等结果的复核优先级总表。
- `00_重要_人工复核入口/00B_目标画像索引.md`: 每个 host 的画像入口，聚合指纹、API、候选、二次复测和后续分支。
- `00_重要_人工复核入口/01_需要你登录拿Cookie.md`: 需要你人工打开、登录、拿 Cookie 的站点；Cookie 放到本地 `auth_sessions.local.json`，不提交。
- `00_重要_人工复核入口/02_业务API只读复核队列.md`: 从 Swagger、JS、API、认证态结果里压缩出的高价值业务接口队列，只做字段/数量/结构复核。
- `00_重要_人工复核入口/03_弱口令人工确认队列_不自动跑.md`: 登录页、OA、SSO、后台入口的人工确认清单。项目不会默认自动尝试密码。
- `00_重要_人工复核入口/04_可报告候选_TOP.md`: 从所有扫描结果里汇总出的 Top 候选，便于人工截图和报告化。
- `00_重要_人工复核入口/04D_指纹后深入分支.md`: 识别到产品/框架/中间件后，对应的安全复核项、本地工具/模板候选和审批门槛。
- `00_重要_人工复核入口/06_弱口令显式复核命令.md`: 如规则允许，显式运行弱口令复核的命令示例。
- `runs/<时间>_browser_xhr_capture/00_浏览器采集结果/浏览器采集结果_汇总.md`: 手工登录点击后的 XHR/FETCH/API 汇总；本地复现模式会额外生成 `.local` 文件，不要提交。
- `probe_results.jsonl`: 存活、标题、跳转、Server、Content-Type、首页 hash。
- `fingerprints.jsonl` 和 `cat_*.txt`: 技术分类。
- `candidate_exposures.jsonl`: 固定高价值路径候选。
- `verified_exposures.jsonl`: 经过首页差异、关键词、长度、类型等真伪验证后的候选。
- `api_discovery_manifest.json`: API 阶段使用的工具发现情况。
- `api_discovery.jsonl`: 首页、robots、sitemap、Swagger、JS 抓取记录。
- `api_candidates.jsonl`: 从 HTML/JS 中提取的接口候选和优先级标签。
- `impact_candidates.jsonl`: 更值得人工深挖的线索，例如真实 OpenAPI paths、source map、上传/导出/管理类接口。
- `api_confirmed.jsonl`: 被限量确认过的只读 API 端点。
- `api_interesting.jsonl`: 返回 JSON 结构且更值得复核的 API 端点。
- `priority_targets.json`: 自动排序后的高价值目标队列。
- `candidate_confidence.csv/jsonl`: P0-P3 复核优先级队列；优先级不是漏洞结论。
- `target_dossiers/index.md`: 目标画像索引。
- `fingerprint_deepening_plan.jsonl`: 指纹后深入分支计划。
- `fingerprint_deepening_safe_queue.csv`: 安全只读/离线复核队列。
- `fingerprint_deepening_approval_queue.csv`: 需要明确审批的动作/模板队列。
- `fingerprint_tool_command_queue.csv`: 单目标人工命令预览，不会自动执行。
- `reports/fingerprint_deepening.md`: 指纹后深入分支的人读报告。
- `reports/priority_review.md`: 适合人工快速复核的 Top 目标清单。
- `run_health.json` 和 `reports/run_health.md`: 本次运行质量、覆盖率、假阳性率和建议。
- `tool_assisted_triage_plan.json`: 成熟工具复核命令计划。
- `tool_triage_nuclei_*.jsonl`: nuclei 复核结果。

## 工具策略

默认不是每个阶段两个工具全量跑，而是：

```text
一个主工具全量跑 + 一个备用工具抽样复核 / 补盲 / 交叉确认
```

当前建议：

- 子域名：OneForAll 为主，证书透明度/subfinder 作为被动补充。
- 存活：runner HTTP probe 为主，httpx 抽样复核失败和边界目标。
- 指纹：runner 规则为主，EHole/TideFinger/P1finger 复核高价值目标。
- JS/API：`api_discovery.py` 为默认主流程，katana/PackerFuzzer/API-Explorer 用于重要目标补盲。
- 高价值路径：runner 小路径集为主，浏览器/代理人工复核。
- 模板验证：nuclei 为主，afrog 只复核已确认候选。
- Shiro：`shiro_triage.py` 做低影响 rememberMe 特征识别，输出 `shiro_manual_queue.csv`；ShiroAttack2 只做授权单点人工验证，不默认命令执行/内存马/上传。
- SQL 注入：`sqli_triage.py` 是默认低影响候选筛查，输出 `sqli_high_probability.txt` 和 `sqli_500_or_error_anomalies.txt`；`sqlmap` 只用于后续单点确认，使用低 risk/level、delay、无 dump/破坏参数。
- 报告：`evidence_builder.py` 统一生成。

## 限速与边界

- 默认并发为 1，目标间有延迟和 jitter。
- 遇到 429/5xx 会退避，同一 host 连续错误会停止。
- `--api-discovery` 只读，不提交写入型 payload。
- 路径验证只保存 hash、长度、状态和关键词命中，不保存敏感响应正文。
- SQLMap、弱口令、爆破、命令执行、文件上传验证、webshell、内网扫描仍属于审批后单点动作，不进入默认全量流程。

## 卫生专场配置

先从授权工作簿生成分流后的目标清单；原始工作簿不会被修改：

```text
<python.exe> .\health_scope_import.py --xlsx "D:\Desktop\claude projects\attack and defend test\卫生靶标信息.xlsx" --output-dir .\health_scope
```

- `health_web_targets_public.txt`：默认低速 Web 输入。
- `health_web_targets_internal.txt`：内网 Web 单独保存，仅在具备内网扫描批准和网络条件时显式选择。
- `health_nonweb_manual_queue.csv`：数据库、PACS、VPN、SSH、网络设备等非 Web 端点，默认不交给通用 Web 扫描器。
- `health_scope_manifest.json`：源文件哈希、资产分类和计数；不包含患者数据。

卫生专场运行示例：

```text
<python.exe> .\gov_exercise_runner.py --targets .\health_scope\health_web_targets_public.txt --healthcare-profile --probe --fingerprint --api-discovery --api-confirm --sqli-triage --delay 3
```

`--healthcare-profile` 把实时请求间隔下限固定为 3 秒，并在运行末尾离线生成 `healthcare_privacy/` 队列。该队列优先标记患者身份、就诊、诊断、处方、LIS/PACS、医保收费、随访和心理健康相关的接口路径与字段名，只保存结构元数据，不保存响应正文、患者字段值、报告或影像。

`--sqli-triage` 仍保留原来的浅层 SQL 注入测试，但不会主动进行广泛 SQL 注入扫描：它只处理已经发现的参数化 GET URL，每主机最多 3 个参数探针、每 URL 最多 2 个参数、每参数 5 个请求、默认间隔 3 秒，并禁用延时、UNION、堆叠、枚举、dump 和写入型测试。

## 受管工具版本

- Nuclei 3.8.0 + Nuclei Templates 10.4.4：通用模板核心，模板需先按技术、风险和侵入性筛选。
- httpx 1.9.0：通用 HTTP 元数据补充，不与内置存活探测全量重复运行。
- Katana 1.6.1：重要目标的 JS/API 盲区补充，限制同域、深度、页面数和速率。
- afrog 3.5.3：中国 OA 产品确认后的专项候选工具，默认仅入队，不自动执行漏洞模板。
- ShiroAttack2 5.1.1：只用于已经由 `shiro_triage.py` 筛出的单目标人工确认；命令执行、上传、内存马和持久化功能不属于默认流程。

已安装版本、哈希与离线版本检查结果记录在 `tools/managed/managed_inventory.json`。OA-EXPTOOL、dddd、旧 afrog/xray/Shiro 包继续保留为旧模板参考或人工备选，不再作为默认主工具。
## 微信小程序发现阶段

该阶段已经接入完整流程，默认用于离线生成线索，不会主动访问目标站。它会从 `targets.csv`、`probe_results.jsonl`、历史 run 目录或给定输入目录中提取单位名、标题、域名、公众号文章、二维码图片、小程序关键词，并生成搜索 dork 与后续扫描交接文件。

离线生成小程序/公众号线索：

```text
<python.exe> .\gov_exercise_runner.py --targets "D:\Desktop\all_alive_alive.txt" --wechat-miniapp --delay 3
```

该命令完全离线，不会因为缺少 `probe_results.jsonl` 而自动探测目标。

低速读取首页和同站 JS 提取微信线索：

```text
<python.exe> .\gov_exercise_runner.py --targets "D:\Desktop\all_alive_alive.txt" --wechat-miniapp --wechat-live --wechat-max-js 3 --delay 3
```

关键输出：

- `wechat_unit_keyword_seeds.csv`: 单位/标题/域名关键词种子。
- `wechat_search_dorks.txt` / `wechat_search_dorks.csv`: 快速检索小程序、公众号、扫码入口的 dork。
- `wechat_miniapp_candidates.jsonl`: 首页或 JS 中提取的 `wx_appid`、`gh_`、公众号链接、二维码图片、候选后端 API、登录/注册/OAuth/Token/Session 等线索；URL 参数值会被脱敏。
- `wechat_subdomain_scan_targets.txt`: 已确认来自授权源站的域名/URL，可回流到子域名收集、存活探测和主流程。
- `wechat_pending_extra_assets.txt`: 微信平台域名、第三方域名、需人工确认归属的小程序/公众号线索，不直接扫描。
- `wechat_auth_domains.csv` / `wechat_auth_domains.json`: 需要人工登录或可能允许注册的域名、登录入口、来源、授权状态和处理提示。
- `wechat_auth_domains.txt`: 当前目标范围内、需要你登录取 Cookie 的纯域名清单。
- `wechat_auth_sessions.template.json`: 只为当前范围内域名生成的 Cookie 会话模板；未确认归属的域名不会进入模板。
- `reports/wechat_auth_domains.md`: 便于人工逐项勾选的登录提醒报告。

已解包小程序源码离线分析：

```powershell
<python.exe> .\miniapp_endpoint_offline.py --source-dir "C:\Users\ASUS\AppData\Local\Temp\wxapp_unpack\__APP__" --out-dir .\runs\manual_wxapp_source_review
```

输出包括 `summary.json`、`domains.json`、`urls.redacted.json`、`endpoints.redacted.json`、`sign_hits.redacted.json` 和 `微信小程序源码离线分析.md`。该脚本只读取本地源码，不访问后端接口。

回流方式：

```text
<python.exe> .\gov_exercise_runner.py --targets .\runs\YYYYMMDD_HHMMSS_gx_gov\wechat_subdomain_scan_targets.txt --probe --fingerprint --high-value-paths --api-discovery --delay 3
```

边界规则：小程序发现阶段默认只做离线 OSINT；只有显式 `--wechat-live` 才读取首页和同站 JS。微信平台域名和未确认第三方资产不得直接进入扫描。新域名即使名称看起来属于广西单位，也先进入归属确认队列。

## 登录注册与认证态 API 分支

主流程现在会自动生成 `manual_auth_queue.csv`、`manual_auth_queue.json` 和 `reports/manual_auth_queue.md`。它会合并普通 Web/API 与小程序流程发现的登录页、认证接口和疑似注册入口，供人工逐一打开、确认是否允许注册并完成登录。项目不会自动注册、尝试密码或绕过认证。

同一批登录入口也会汇总到更显眼的 `00_重要_人工复核入口/01_需要你登录拿Cookie.md`。日常查看优先打开这个文件，不需要在 run 目录里猜哪个清单最重要。

登录后，把浏览器中当前会话的 Cookie 写入本地会话文件。可从 run 目录下的 `auth_sessions.template.json` 复制结构，新文件建议命名为 `auth_sessions.local.json`，不要把它上传到报告、代码仓库或聊天记录：

```json
{
  "sessions": [
    {
      "base_url": "https://authorized.example.gov.cn",
      "entry_url": "https://authorized.example.gov.cn/dashboard",
      "cookie": "SESSION=实际值",
      "headers": {}
    }
  ]
}
```

在原 run 目录续跑认证态只读复查：

```text
<python.exe> .\gov_exercise_runner.py --targets "D:\Desktop\targets.txt" --resume-run-dir .\runs\YYYYMMDD_HHMMSS_gx_gov --auth-review --auth-cookie-file .\auth_sessions.local.json --auth-max-js 20 --auth-max-endpoints 30 --delay 3
```

主要结果：

- `authenticated_api_results.jsonl`：状态、类型、长度、样本 hash 和 JSON 字段名。
- `authenticated_impact_candidates.jsonl`：认证后敏感字段结构、文件/导出接口候选、source map 等高价值线索。
- `authenticated_review_skips.jsonl`：被边界规则跳过的下载、导出、写入和越界接口。
- `authenticated_new_assets_pending.txt`：认证后 JS 泄露的新域名、子域名或外部 API，确认授权后再加入目标表。

Cookie、Authorization、响应正文和敏感文件不会写入结果。下载、导出、上传、删除、修改和账号操作不会自动触发。

业务 API 复核队列会优先把用户、人员、患者、机构、监督检查、列表、详情、查询等接口放入 `00_重要_人工复核入口/02_业务API只读复核队列.md`。默认不会调用写入、导出、下载、删除、短信、密码、审批类接口；认证态复核也只保存字段名、数量、状态、长度和 hash，不保存响应正文或敏感字段值。

弱口令不会作为默认自动动作。登录页、OA、SSO、后台入口会进入 `00_重要_人工复核入口/03_弱口令人工确认队列_不自动跑.md`。如果你显式启用弱口令复核，脚本会先尝试最多 5 组动态常见组合；如果同时加 `--weak-credential-auto-auth-review`，成功后会优先使用当次登录响应里的 Cookie/JWT 在内存中继续跑认证态只读 API/JS 复核，失败或没有可用会话材料时才回到手动 Cookie 清单。

如本轮规则允许弱口令复核，必须显式加参数运行，默认不会跑：

```text
<python.exe> .\gov_exercise_runner.py --targets "D:\Desktop\targets.txt" --resume-run-dir .\runs\YYYYMMDD_HHMMSS_gx_gov --weak-credential-review --weak-credential-max-pairs 5 --weak-credential-max-targets 10 --delay 3
```

如希望“先自动拿认证态，不行再手动”，在同一条命令中额外启用自动认证态只读复核：

```text
<python.exe> .\gov_exercise_runner.py --targets "D:\Desktop\targets.txt" --resume-run-dir .\runs\YYYYMMDD_HHMMSS_gx_gov --weak-credential-review --weak-credential-auto-auth-review --weak-credential-max-pairs 5 --weak-credential-max-targets 10 --auth-max-js 20 --auth-max-endpoints 30 --delay 3
```

该阶段会根据系统/OA/中间件线索动态选择最多 5 组常见组合，例如 Jeecg、若依、Druid、Tomcat 和通用后台会使用不同优先级。遇到验证码、锁定、风控、失败次数提示或首个成功即停止。自动认证态复核不会抓浏览器 token，也不会保存 Cookie/JWT 值；它只使用弱口令成功当次 HTTP 响应里的认证材料在内存中继续访问同主机、GET 型、只读接口。输出包括：

- `weak_credential_attempts.jsonl`：尝试元信息，不保存明文密码、Cookie、Token 或响应正文。
- `weak_credential_successes.jsonl`：成功候选，只记录用户名、密码 profile、状态、跳转和是否临时准备了会话等最小证据。
- `weak_credential_skips.jsonl`：验证码、锁定、非 POST 登录表单、无支持登录表单等跳过原因。
- `weak_auto_authenticated_review_manifest.json`：仅在启用自动认证态复核且拿到可用临时会话时生成，只包含请求数、影响候选数和限额。
- `authenticated_api_results.jsonl` / `authenticated_impact_candidates.jsonl`：自动认证态复核得到的状态、长度、hash、字段名和高价值候选。
- `weak_credential_success_sessions.local.template.json`：本地模板，若自动认证态复核没有可用会话或仍需人工确认，再由你在浏览器中确认后手工粘贴 Cookie。
