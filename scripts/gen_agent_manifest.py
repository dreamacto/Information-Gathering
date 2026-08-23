#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成 AGENT_MANIFEST.md：机器可读工具清单（由 AI 选工具时读取）。

数据源：
  - tool_strategy.json       全部 phase 的主备工具映射 + approval_gated_phases
  - gov_exercise_config.json tools(工具路径) / rate_control / blocked_actions
  - 内置 ROOT_SCRIPTS 表     根目录核心 py 脚本（用途/输出/示例命令）
  - 内置 DESKTOP_SCRIPTS 表  桌面 bat 入口

用法：python scripts/gen_agent_manifest.py     # 覆盖生成根目录 AGENT_MANIFEST.md
要求：纯 stdlib；幂等（重跑覆盖）；输出 UTF-8。
"""
import ast
import json
import datetime
import pathlib
import re

BASE = pathlib.Path(__file__).resolve().parent.parent
TOOL_STRATEGY = BASE / "tool_strategy.json"
GOV_CONFIG = BASE / "gov_exercise_config.json"
OUTPUT = BASE / "AGENT_MANIFEST.md"

# 桌面 bat 入口（逐条登记触发场景）
DESKTOP_SCRIPTS = {
    "一键完整流程_含弱口令.bat": {
        "scene": "从零开始完整攻击链（子域→活性→指纹→triage→弱口令复核），需要目标文件；跑完看 runs/last_one_click_run.txt",
        "risk": "审批门内含弱口令复核阶段（会停下等人确认）", "example": "一键完整流程_含弱口令.bat 目标文件.txt",
    },
    "一键已有子域名后流程_含弱口令.bat": {
        "scene": "已有子域名清单，跳过子域爆破，从活性/指纹阶段接着跑（parallel_flow_runner.py，按根域分组）",
        "risk": "审批门内含弱口令复核阶段", "example": "一键已有子域名后流程_含弱口令.bat 子域名清单.txt",
    },
    "一键保守全流程_尽量多信息_避WAF.bat": {
        "scene": "保守模式：delay=5s、单线程、跳过弱口令与高价值路径，尽量避开 WAF 触发（gov_exercise_runner.py）",
        "risk": "只读", "example": "一键保守全流程_尽量多信息_避WAF.bat 目标文件.txt",
    },
    "SQLi会话探测.bat": {
        "scene": "SQLi 三合一探测（请求预算 16/参数、基线差分、marker 确认）；浏览器登录后粘贴 cURL 的会话探测",
        "risk": "只读探测", "example": "SQLi会话探测.bat （交互：粘贴 cURL）",
    },
    "小程序Burp导入到最近一次流程.bat": {
        "scene": "把小程序的 Burp 导出导入到最近一次 run 流程（miniapp_burp_import_latest.py）",
        "risk": "离线导入", "example": "小程序Burp导入到最近一次流程.bat",
    },
    "无影TscanPlus.bat": {
        "scene": "本地 GUI 扫描器入口（手动页面操作，非命令行）",
        "risk": "手动工具，按需", "example": "无影TscanPlus.bat",
    },
    "一键IDOR差分_只读.bat": {
        "scene": "交互输入 run 目录/会话文件/端点文件，跑 idor_triage.py 只读差分（.venv）",
        "risk": "只读差分", "example": "一键IDOR差分_只读.bat",
    },
    "一键竞态靶场.bat": {
        "scene": "本地起 race_lab_server.py（8892）：/claim 漏洞真值 /claim_safe 负例 /transfer 超扣；判据校准教学用",
        "risk": "本地靶场，零外联", "example": "一键竞态靶场.bat",
    },
    "一键竞态测试_授权目标.bat": {
        "scene": "读配方D 产出的 race_config.json 对授权目标执行竞态；开场强制 YES 确认；必须 .venv",
        "risk": "审批门：写端点需 write_risk_ack", "example": "一键竞态测试_授权目标.bat",
    },
    "AI配方_一键复制.bat": {
        "scene": "菜单选 1-6 把 prompts/ 配方A-F 全文复制到剪贴板，粘贴给任意 AI 启动对应会话（copy_prompt.py）",
        "risk": "离线复制，零网络请求", "example": "AI配方_一键复制.bat",
    },
}

# 根目录核心脚本（用途/输出/示例命令；缺省字段自动从 docstring/argparse 提取）
ROOT_SCRIPTS = {
    "fh_review_dispatch.py": {
        "scene": "W6 复核编排：把 postrun_review 工作区切成子代理批次(batch md 自包含) + 聚合 verdict 回台账；零网络",
        "outputs": "postrun_review/review_batches/*.md、verdicts/*.json、findings_ledger.csv、fp_memory.jsonl、TOP_人工复核.md",
        "example": "python fh_review_dispatch.py --run-dir runs/<ts> --prepare --batch-size 8",
        "risk": "离线编排",
    },
    "idor_triage.py": {
        "scene": "W7 IDOR 水平越权差分：基线A/B重放/匿名三请求对比结构指纹与 Jaccard，只读 GET/HEAD",
        "outputs": "<run_dir>/idor_candidates.jsonl、idor_manual_review.md",
        "example": "python idor_triage.py --run-dir runs/<ts> --sessions sessions.jsonl --requests api_confirmed.jsonl",
        "risk": "只读（需≥2凭证、delay≥3s、每host≤5端点）",
    },
    "report_docx.py": {
        "scene": "攻防成果报告 docx 生成器（北港网格式）：findings.json+meta.json 渲染 / --from-ledger 台账骨架 / --demo 模板；自动插入红色【需截图】标注",
        "outputs": "reports/攻防成果报告_<名>_<日期>.docx",
        "example": "python report_docx.py --meta reports/meta.json --findings reports/findings.json",
        "risk": "纯离线渲染",
    },
    "run_lifecycle.py": {
        "scene": "run 完成态查询器：从盘上产物推导 scan/review/planned/light_exhausted/swept 状态，回答'跑完了吗/下一步是什么'；--mark 人工标记",
        "outputs": "run_lifecycle.json（run 目录内）",
        "example": "python run_lifecycle.py runs/<ts>",
        "risk": "纯离线",
    },
    "waf_profile.py": {
        "scene": "WAF/拦截画像合成：零请求聚合 candidate_exposures/sqli_candidates/second_pass/light_verify 的 4xx 证据，每 host 出拦截层/统一拦截页判定，防 WAF 差异被误读成业务信号",
        "outputs": "waf_profile.jsonl、reports/waf_profile.md",
        "example": "python waf_profile.py --run-dir runs/<ts>",
        "risk": "纯离线",
    },
    "light_diff_probe.py": {
        "scene": "标准化只读差分探针（baseline/quote/dquote/boolean/empty），统一限速/元数据落盘/连续拦截提前停——替代 AI 手搓探测脚本；须 .venv",
        "outputs": "--out 指定 jsonl（元数据）",
        "example": '.venv/Scripts/python.exe light_diff_probe.py --url "https://x/api?q=1" --probes baseline,quote',
        "risk": "只读 GET；并发1；delay 默认 3s；预算默认 8 请求/URL",
    },
    "import_run_to_engagement.py": {
        "scene": "一键流程→深挖交接：把 run 的 api_confirmed/interesting/candidates 导入 engagement 的 endpoint-inventory.csv 种子行（去重、全 untested）",
        "outputs": "engagements/<名>/artifacts/endpoint-inventory.csv 追加",
        "example": "python import_run_to_engagement.py --run-dir runs/<ts> --engagement engagements/<名-日期>",
        "risk": "纯离线",
    },
    "metrics_weekly.py": {
        "scene": "W10 周度度量：扫 runs/*/ 聚五指标（候选数/确认率/FP率/假设命中率），出周报+history",
        "outputs": "reports/metrics_YYYYMMDD.md、metrics_history.jsonl",
        "example": "python metrics_weekly.py --days 7",
        "risk": "纯离线",
    },
    "oob_listener.py": {
        "scene": "W11 OOB 回调监听（默认8899）：每请求记 {token,src_ip,ts} 到 oob_hits.jsonl；--pull 拉 VPS 命中",
        "outputs": "oob_hits.jsonl",
        "example": "python oob_listener.py --port 8899 --prefix ab12cd",
        "risk": "本地监听；VPS 部署需随机前缀",
    },
    "race_triage.py": {
        "scene": "W8 竞态执行器：三模式(h2单包/last-byte/barrier)测 check-then-act；矩阵判据只出 limit_overrun 布尔",
        "outputs": "race_results.jsonl（基线vs并发矩阵）",
        "example": "python race_triage.py --config race_config.json",
        "risk": "必须 .venv；写端点需 write_risk_ack==true；并发≤30",
    },
    "ssrf_triage.py": {
        "scene": "W11 SSRF 探测：可疑参数筛出后 OOB token 注入 + 时间盲双路；POST 只静态候选不自动发",
        "outputs": "<run_dir>/ssrf_candidates.jsonl",
        "example": "python ssrf_triage.py --run-dir runs/<ts> --endpoints api_confirmed.jsonl --oob http://vps:8899/xx",
        "risk": "只读 GET；delay≥3s；每host≤5端点",
    },
    "whitebox_triage.py": {
        "scene": "W13 白盒 sink 流水线：sink_lib(62条) 正则扫 .js/.wxml/.json，出命中±3行上下文供配方F研判",
        "outputs": "sink_findings.jsonl、whitebox_review.md",
        "example": "python whitebox_triage.py --source-dir unpacked/<appid> --out-dir <dir> --scan",
        "risk": "纯离线",
    },
    "xss_verify_headless.py": {
        "scene": "W12 XSS 执行确认：读反射候选，dalfox→playwright→stdlib 三级引擎判 executable/context_safe",
        "outputs": "<run_dir>/xss_verified.jsonl",
        "example": "python xss_verify_headless.py --run-dir runs/<ts>",
        "risk": "只验证 GET 反射；marker 唯一；403连续即停",
    },
    "gov_exercise_runner.py": {
        "scene": "主编排器：73 个 CLI 参数、30+ phase 编排、--resume-run-dir 断点续跑；所有新 phase 的挂载点",
        "outputs": "runs/<ts>/ 全套（run_summary.json、00_重要_人工复核入口/、各 *_candidates.jsonl）",
        "example": "python gov_exercise_runner.py --targets targets.txt --probe --fingerprint --sqli-triage",
        "risk": "只读编排（含审批门 phase 的显式参数）",
    },
    "one_click_workflow.py": {
        "scene": "一键完整流程 bat 的调用对象：子域→活性→指纹→triage→弱口令复核→证据；--no-subdomain 可跳过子域爆破",
        "outputs": "runs/<ts>/ 全套",
        "example": "python one_click_workflow.py --mode full --targets 目标文件.txt --second-pass-sql-limit 10",
        "risk": "只读（弱口令复核阶段内有人工门）",
    },
    "sqli_triage.py": {
        "scene": "SQLi 三合一探测：请求预算 16/参数、基线差分、marker 确认；只对发现的参数化 GET URL 低影响探测",
        "outputs": "sqli_candidates.jsonl / sqli_reflection_checks.jsonl",
        "example": "python sqli_triage.py --run-dir runs/<ts>",
        "risk": "只读探测（禁时间盲注/UNION/堆叠/dump）",
    },
    "xss_candidate_triage.py": {
        "scene": "XSS 反射候选：从参数化 URL 构造候选并做 GET 反射探测",
        "outputs": "xss_candidates.jsonl / xss_reflection_checks.jsonl",
        "example": "python xss_candidate_triage.py --run-dir runs/<ts>",
        "risk": "只读",
    },
    "shiro_triage.py": {
        "scene": "Shiro 轻量筛选：基线 GET + 无效 rememberMe cookie 探测，只存元数据/哈希/Set-Cookie 名；置信度 high/medium 信号排序（shiro_triage.py:231-258）",
        "outputs": "shiro_candidates.jsonl / shiro_triage_results.jsonl / shiro_manual_queue.csv",
        "example": "python shiro_triage.py --run-dir runs/<ts>",
        "risk": "只读（爆破 key / 序列化 payload = 审批门）",
    },
    "shiro_bypass_review.py": {
        "scene": "Shiro 轻量筛选第 2 级：--plan 离线读 shiro_candidates.jsonl，high/medium 按 URL 去重合并成审批队列（low 不入队）；--review 对 approved 行做只读 GET 路径变体",
        "outputs": "shiro_bypass_approval_queue.csv / shiro_bypass_approval_queue.jsonl / shiro_bypass_approval_required.md",
        "example": "python shiro_bypass_review.py --run-dir runs/<ts> --plan",
        "risk": "--plan 离线零请求；--review 只读 GET",
    },
    "authenticated_session_review.py": {
        "scene": "认证态复核：读 sessions.jsonl / auth_sessions.local.json，对需登录的业务 API 复核（只读）",
        "outputs": "auth_sessions.template.json / 认证态复核队列",
        "example": "python authenticated_session_review.py --run-dir runs/<ts> --sessions sessions.jsonl",
        "risk": "只读；凭证只被本地脚本读",
    },
    "product_triage.py": {
        "scene": "OA/ERP/CMS/框架/中间件产品识别（离线指纹映射）",
        "outputs": "product_candidates.jsonl",
        "example": "python product_triage.py --run-dir runs/<ts>",
        "risk": "只读",
    },
    "fingerprint_deepening.py": {
        "scene": "指纹深化：产品/框架 → 安全后续检查点映射（离线）",
        "outputs": "fingerprint_deepening.jsonl",
        "example": "python fingerprint_deepening.py --run-dir runs/<ts>",
        "risk": "只读/离线",
    },
    "tool_fingerprint_httpx.py": {
        "scene": "httpx 技术检测（单目标、外置延迟），fingerprint phase 的主工具",
        "outputs": "httpx_fingerprint.jsonl",
        "example": "python tool_fingerprint_httpx.py --run-dir runs/<ts>",
        "risk": "只读",
    },
    "api_discovery.py": {
        "scene": "JS/流量解析发现 API 候选（crawl_api_js phase 主工具）",
        "outputs": "api_candidates.jsonl / api_interesting.jsonl",
        "example": "python api_discovery.py --run-dir runs/<ts>",
        "risk": "只读",
    },
    "api_endpoint_confirm.py": {
        "scene": "API 端点确认：只确认有界的只读 GET 类候选；跳过 upload/import 等风险动词",
        "outputs": "api_confirmed.jsonl",
        "example": "python api_endpoint_confirm.py --run-dir runs/<ts>",
        "risk": "只读",
    },
    "second_pass_triage.py": {
        "scene": "二轮复核 triage：对候选集中做轻量深度确认",
        "outputs": "second_pass_candidates.jsonl",
        "example": "python second_pass_triage.py --run-dir runs/<ts>",
        "risk": "只读",
    },
    "deep_readonly_triage.py": {
        "scene": "深度只读 triage（保守模式用）",
        "outputs": "deep_readonly_candidates.jsonl",
        "example": "python deep_readonly_triage.py --run-dir runs/<ts>",
        "risk": "只读",
    },
    "readonly_endpoint_confirm.py": {
        "scene": "只读端点确认",
        "outputs": "readonly_confirmed.jsonl",
        "example": "python readonly_endpoint_confirm.py --run-dir runs/<ts>",
        "risk": "只读",
    },
    "readonly_config_probe.py": {
        "scene": "只读配置探测（保守模式）",
        "outputs": "readonly_config_candidates.jsonl",
        "example": "python readonly_config_probe.py --run-dir runs/<ts>",
        "risk": "只读",
    },
    "fastjson_triage.py": {
        "scene": "fastjson 只读反格式化探测（类型错误/语法错误/嵌套解析），无 RCE payload",
        "outputs": "fastjson_candidates.jsonl",
        "example": "python fastjson_triage.py --run-dir runs/<ts>",
        "risk": "只读",
    },
    "struts2_triage.py": {
        "scene": "struts2 只读指纹探测（默认 action 后缀/showcase/devMode/OGNL 错误标记）",
        "outputs": "struts2_candidates.jsonl",
        "example": "python struts2_triage.py --run-dir runs/<ts>",
        "risk": "只读",
    },
    "tomcat_triage.py": {
        "scene": "tomcat/weblogic 只读探测（ajp 8009 / t3 7001 / http 8080 连接检查 + 版本/manager/console）",
        "outputs": "tomcat_weblogic_candidates.jsonl",
        "example": "python tomcat_triage.py --run-dir runs/<ts>",
        "risk": "只读",
    },
    "nacos_triage.py": {
        "scene": "nacos 只读探测（admin/console 小集合端点状态码）",
        "outputs": "nacos_candidates.jsonl",
        "example": "python nacos_triage.py --run-dir runs/<ts>",
        "risk": "只读",
    },
    "redis_triage.py": {
        "scene": "redis/elasticsearch/zookeeper 只读探测（PING/INFO banner、GET / 状态、connect+ruok）",
        "outputs": "redis_es_zk_candidates.jsonl",
        "example": "python redis_triage.py --run-dir runs/<ts>",
        "risk": "只读",
    },
    "springboot_triage.py": {
        "scene": "springboot 只读指纹 + actuator 端点探测（env/heapdump 仅状态码存在性）",
        "outputs": "springboot_candidates.jsonl",
        "example": "python springboot_triage.py --run-dir runs/<ts>",
        "risk": "只读",
    },
    "healthcare_privacy_triage.py": {
        "scene": "医疗隐私数据专项：患者身份/就诊/诊断/处方/LIS/PA 端点的只读 schema 复核",
        "outputs": "healthcare_candidates.jsonl",
        "example": "python healthcare_privacy_triage.py --run-dir runs/<ts>",
        "risk": "只读",
    },
    "header_reflection_probe.py": {
        "scene": "Header 注入反射探测（只读 marker）",
        "outputs": "header_reflection_candidates.jsonl",
        "example": "python header_reflection_probe.py --run-dir runs/<ts>",
        "risk": "只读",
    },
    "weak_credential_review.py": {
        "scene": "弱口令复核（审批门）：读 run-dir 的登录面，默认 ≤3 目标/≤5 口令组、delay 3、首次成功即停；凭证不落盘",
        "outputs": "weak_credential_manifest.json / weak_credential_successes.jsonl",
        "example": "python weak_credential_review.py --run-dir runs/<ts> --max-targets 1 --max-pairs 5 --delay 3",
        "risk": "审批门双钥匙，缺一不可",
    },
    "evidence_builder.py": {
        "scene": "证据构建：proven 级发现的报告装订（攻击成果.docx 模板）",
        "outputs": "攻击成果.docx 报告",
        "example": "python evidence_builder.py --run-dir runs/<ts>",
        "risk": "本地离线",
    },
    "result_prioritizer.py": {
        "scene": "结果优先级排序：从全部候选压缩 TOP 列表（report phase 主工具）",
        "outputs": "priority_targets.json / priority_review.md",
        "example": "python result_prioritizer.py --run-dir runs/<ts>",
        "risk": "本地离线",
    },
    "review_intelligence.py": {
        "scene": "复核情报：跨 run 聚合候选与模式",
        "outputs": "review_intelligence.jsonl",
        "example": "python review_intelligence.py --run-dir runs/<ts>",
        "risk": "本地离线",
    },
    "run_health.py": {
        "scene": "run 健康检查：health 分、missing tools、异常信号",
        "outputs": "run_health.json",
        "example": "python run_health.py --run-dir runs/<ts>",
        "risk": "本地离线",
    },
    "parallel_flow_runner.py": {
        "scene": "并行流程子 runner（已有子域名场景，按根域分组最多 3 批）",
        "outputs": "runs/<ts> 子流程产物",
        "example": "python parallel_flow_runner.py --subdomains 子域名清单.txt",
        "risk": "只读",
    },
    "subdomain_collector.py": {
        "scene": "子域名收集入口",
        "outputs": "subdomains.jsonl / subdomains_for_scope_confirmation.txt",
        "example": "python subdomain_collector.py --targets targets.txt",
        "risk": "只读（DNS 查询）",
    },
    "subdomain_bruteforce_controlled.py": {
        "scene": "受控子域爆破（低频 DNS 发现，产出先归类确认再探测）",
        "outputs": "subdomains_bruteforce.txt",
        "example": "python subdomain_bruteforce_controlled.py --targets targets.txt",
        "risk": "只读（受控低速率）",
    },
    "decrypt_wxapkg.py": {
        "scene": "小程序 wxapkg 批量解密 + 域名提取",
        "outputs": "tools/miniapp_extract/ 解密产物",
        "example": "python decrypt_wxapkg.py <wxapkg路径>",
        "risk": "离线",
    },
    "analyze_wx_miniapp_source.py": {
        "scene": "小程序源码树分析（白盒入口）",
        "outputs": "miniapp_analysis.jsonl",
        "example": "python analyze_wx_miniapp_source.py --source-dir unpacked/wxXXX",
        "risk": "离线",
    },
    "analyze_js_static.py": {
        "scene": "JS 静态分析（含 .min.js beautify，供白盒 sink 定位参考）",
        "outputs": "js_analysis.jsonl",
        "example": "python analyze_js_static.py --run-dir runs/<ts>",
        "risk": "离线",
    },
    "batch_runner.py": {
        "scene": "批量子 runner（阶段内分批执行）",
        "outputs": "批次产物 + 游标",
        "example": "python batch_runner.py --run-dir runs/<ts>",
        "risk": "只读",
    },
}

# 名称归一化：tool_strategy 里的工具名 → (路径模板、风险级、备注)
TOOL_RISK_MAP = {
    "sqlmap": ("审批门", "仅单候选 URL、risk=1、level=1、technique BE、带 delay、无 dump"),
    "ShiroAttack2": ("审批门", "仅单授权候选 key/rememberMe 人工验证"),
    "weak": ("审批门", "弱口令复核需双钥匙"),
    "weekpasswd": ("审批门", "GUI 弱口令工具，需人工门"),
    "hydra": ("审批门", "仅显式批准后使用"),
    "nuclei": ("只读", "固定管理的 nuclei 引擎与已审模板"),
    "afrog": ("只读", "仅确认的中国 OA 爆点模板"),
    "httpx": ("只读", "技术检测单目标+外置延迟"),
    "katana": ("只读", "depth=2、concurrency=1、parallelism=1"),
    "dirsearch": ("只读", "小词表、低速率、默认不递归"),
    "ffuf": ("只读", "小词表、低速率"),
    "oneforall": ("只读", "子域枚举低频"),
    "ksubdomain": ("只读", "验证通过的子域枚举"),
    "ehole": ("只读", "指纹识别"),
    "tidefinger": ("只读", "指纹识别样本"),
    "xray": ("审批门", "主动扫描需人工门"),
    "FastjsonScan.exe": ("审批门", "仅单候选"),
    "SpringBoot-Scan.py": ("审批门", "仅单候选"),
    "Struts2Scan.py": ("审批门", "仅单候选"),
    "api_tool": ("只读", "API 工具"),
    "api_explorer": ("只读", "API 工具"),
    "packerfuzzer": ("只读", "webpack 包解析"),
    "oa-exptool": ("审批门", "产品验证工具需人工门"),
    "dddd": ("只读", "指纹/资产"),
    "nuclei_templates": ("只读", "模板引用"),
}

# 工具名 → 输出文件（tool_strategy 引用到的外部工具常用输出）
EXTERNAL_OUTPUTS = {
    "nuclei": "nuclei_results.jsonl",
    "afrog": "afrog_results.jsonl",
    "sqlmap": "sqlmap 会话目录（无 dump）",
    "httpx": "httpx_tech.jsonl",
    "katana": "katana_crawl.jsonl",
    "dirsearch": "dirsearch_report.jsonl",
    "oneforall": "oneforall subdomains.txt",
    "ksubdomain": "ksubdomain_results.txt",
    "ehole": "ehole_fingerprint.jsonl",
    "tidefinger": "tide_fingerprint.jsonl",
    "ShiroAttack2": "shiro_success.txt（人工确认后）",
    "FastjsonScan.exe": "fastjsonscan_result.txt",
    "SpringBoot-Scan.py": "springbootscan_report.txt",
    "Struts2Scan.py": "struts2scan_report.txt",
}


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def extract_docstring_first_line(path):
    """返回 py 文件 docstring 首行或 argparse description（兜底用途提取）。"""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return ""
    doc = ast.get_docstring(tree)
    if doc:
        first = doc.strip().splitlines()[0].strip()
        if first and len(first) < 120:
            return first
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "ArgumentParser":
            for kw in node.keywords:
                if kw.arg == "description" and isinstance(kw.value, ast.Constant):
                    return str(kw.value.value)[:120]
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and "description" in target.id.lower():
                    try:
                        return ast.literal_eval(node.value)[:120]
                    except Exception:
                        pass
    return ""


def risk_of(name, phase_name, approval_gated):
    """风险级：审批门 phase > 工具名映射 > 默认只读。"""
    if phase_name in approval_gated:
        return "审批门"
    low = name.lower()
    for key, (risk, note) in TOOL_RISK_MAP.items():
        if key.lower() in low:
            return risk
    return "只读"


def build_root_entries():
    """根目录核心脚本条目：内置表 + docstring 兜底。"""
    entries = []
    for name, meta in ROOT_SCRIPTS.items():
        path = BASE / name
        scene = meta.get("scene", "")
        if not scene and path.exists():
            scene = extract_docstring_first_line(path) or "（无 docstring，见 --help）"
        entries.append({
            "name": name, "path": str(path), "scene": scene,
            "outputs": meta.get("outputs", "runs/<ts>/ 对应产物或见 --help"),
            "example": meta.get("example", f"python {name} --help"),
            "risk": meta.get("risk", "只读"),
        })
    return entries


def external_path(tool_name, config_tools, tianhu_base):
    """从 gov_exercise_config.json tools 里找工具候选路径（展开 {base}/{tianhu}）。"""
    cands = config_tools.get(tool_name, [])
    paths = []
    for c in cands:
        p = c.replace("{base}", str(BASE)).replace("{tianhu}", tianhu_base)
        exists = "存在" if pathlib.Path(p).exists() else "缺失"
        paths.append(f"{p}（{exists}）")
    return "; ".join(paths[:2]) if paths else "—"


def build_manifest():
    ts = load_json(TOOL_STRATEGY)
    cfg = load_json(GOV_CONFIG)
    phases = ts["phases"]                  # dict: phase_name -> {primary,backup,backup_mode,notes}
    approval_gated = ts["approval_gated_phases"]
    config_tools = cfg.get("tools", {})
    tianhu_base = cfg.get("tianhu_base", "")
    rate = cfg["rate_control"]
    blocked = cfg["blocked_actions"]

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    out = []
    out.append("# AGENT_MANIFEST.md — 机器可读工具清单\n")
    out.append(f"> 由 scripts/gen_agent_manifest.py 生成，勿手改（生成时间：{now}）\n")
    out.append("> 用法：AI 选工具前先查本清单；所有新工具/新 phase 由生成器登记，不手写本文件。\n")

    out.append("## 全局速率红线（gov_exercise_config.json rate_control）\n")
    out.append(f"- 默认请求间隔 ≥{rate['default_delay_seconds']}s（jitter ±{int(rate['jitter_ratio']*100)}%）；"
               f"单 host 最小间隔 ≥{rate['per_host_min_interval_seconds']}s")
    out.append(f"- 退避：{rate['backoff_status_codes']} → 停 {rate['backoff_seconds']}s；"
               f"并发上限 {rate['max_concurrency_default']}；同 host 连续错误 {rate['stop_on_repeated_errors_per_host']} 次 → 停该 host\n")

    out.append("## 禁止动作（blocked_actions 全表）\n")
    out.append("`" + "` / `".join(blocked) + "`\n")

    out.append("## 审批门 phase（tool_strategy.json approval_gated_phases）\n")
    for pname, pmeta in approval_gated.items():
        out.append(f"- **{pname}**：primary=`{pmeta.get('primary')}` backup=`{pmeta.get('backup')}`（mode={pmeta.get('backup_mode')}）。"
                   f"{pmeta.get('notes','')}")
    out.append("")

    out.append("## 桌面入口（bat）\n")
    out.append("| 入口 | 场景 | 风险 | 示例 |")
    out.append("|---|---|---|---|")
    for name, meta in DESKTOP_SCRIPTS.items():
        out.append(f"| {name} | {meta['scene']} | {meta['risk']} | `{meta['example']}` |")
    out.append("")

    root_entries = build_root_entries()
    out.append("## 根目录核心脚本（%d 个）\n" % len(root_entries))
    out.append("| 工具 | 路径 | 用途 | 输入 | 输出 | 风险 | 示例 |")
    out.append("|---|---|---|---|---|---|---|")
    for e in root_entries:
        out.append(f"| {e['name']} | `{e['path']}` | {e['scene']} | 见 --help | {e['outputs']} | {e['risk']} | `{e['example']}` |")
    out.append("")

    out.append("## 工具策略（tool_strategy.json 全部 phase）\n")
    for pname, pmeta in phases.items():
        out.append(f"### {pname}")
        out.append(f"- primary：`{pmeta.get('primary')}`；backup：`{pmeta.get('backup')}`（mode={pmeta.get('backup_mode')}）")
        if pmeta.get("notes"):
            out.append(f"- 说明：{pmeta['notes']}")
        risk = risk_of(str(pmeta.get("primary")), pname, approval_gated)
        primary = str(pmeta.get("primary"))
        pout = EXTERNAL_OUTPUTS.get(primary, "见对应 runner 输出契约")
        ppath = external_path(primary, config_tools, tianhu_base)
        out.append(f"- primary 风险级：**{risk}**；外部工具路径：{ppath}；输出：{pout}")
        backup = str(pmeta.get("backup"))
        if backup and backup not in ("manual_review", "manual_browser_or_proxy", "none_by_default",
                                     "manual_minimal_check", "manual_minimal_validation", "manual_request_review",
                                     "manual_template_review", "manual_wechat_or_search_review",
                                     "manual_browser_or_proxy", "manual_confirm_only", "review_borderline_scores",
                                     "human_quality_check", "review_interesting_json_only"):
            bk_risk = risk_of(backup, pname, approval_gated)
            bk_path = external_path(backup, config_tools, tianhu_base)
            out.append(f"- backup：`{backup}`（风险级 **{bk_risk}**）；路径：{bk_path}")
        out.append("")

    out.append("---\n*本清单由生成器维护；修改工具/phase 后重跑 `python scripts/gen_agent_manifest.py`。*")
    return "\n".join(out)


def main():
    if not TOOL_STRATEGY.exists() or not GOV_CONFIG.exists():
        raise SystemExit(f"缺少数据源：{TOOL_STRATEGY} / {GOV_CONFIG}")
    text = build_manifest()
    OUTPUT.write_text(text, encoding="utf-8")
    print(f"OK 生成 {OUTPUT}（{len(text)} chars，{len(ROOT_SCRIPTS)} root scripts + {len(DESKTOP_SCRIPTS)} desktop entries + {len(json.load(open(TOOL_STRATEGY, encoding='utf-8'))['phases'])} phases）")


if __name__ == "__main__":
    main()