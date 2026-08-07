# 2026-07-25 报告反哺项目记录

来源目录：`D:\Desktop\claude projects\attack and defend test\attack`

本轮共 11 个文件：7 个 Word 报告、2 个提示词测试清单、1 个 JSON 数据样例、1 个 Markdown 报告。离线关键词聚合显示，最集中的模式是登录后接口、XHR/API、未授权/越权、敏感字段暴露和弱口令入口。

## 高频模式

1. 登录、注册或弱口令进入系统后，业务接口暴露出用户、订单、访客、缴费、角色、组织等数据结构。
2. 小程序、访客系统、采购平台、OA/SSO 后台这类系统里，接口路径和参数名比页面本身更有价值。
3. 漏洞常见证据不是“拿更多数据”，而是字段名、数量、接口状态、hash、截图和最小样本证明。
4. 多个报告需要手工复现同一个 Cookie 登录态下的 XHR 请求，旧工具只做脱敏元数据，复现成本偏高。
5. 越权类报告需要更稳定的“两个账号/两个身份/两个对象 ID”人工差异记录，而不是自动遍历。
6. AI 提示词清单属于另一条分支，后续可以做成评分清单和证据模板，而不和 Web 接口扫描混在一起。

## 本轮已落地

- 新增 `tools/browser_xhr_capture.mjs`：打开 Chrome/Edge 独立 profile，手工登录点击后采集 XHR/FETCH/API。
- 新增 `启动浏览器XHR采集_本地复现版.bat`：双击启动，默认开启本地复现模式。
- 新增 `BROWSER_XHR_CAPTURE.md`：记录使用方式和边界。
- 更新 `.gitignore`：忽略 `*.local.json`、`*.local.jsonl`、`*.local.txt`，避免 Cookie/Token 文件误入仓库。
- 新增 `miniapp_endpoint_offline.py`：离线读取已解包小程序源码目录，提取域名、URL、接口常量、sign/鉴权线索和高价值复核队列。

## 下一批优先级

1. `idor_pair_review.py`：输入两个账号的本地会话文件和接口清单，只生成人工对照表；默认只支持 GET，不自动批量改 ID。
2. `report_intake.py`：把报告目录自动解析为漏洞模式、证据类型、项目待办和工具改进建议。
3. `miniapp_endpoint_offline.py` 增强：识别更多小程序分包格式、生成可导入 `api_candidates.jsonl` 的接口清单。
4. `evidence_request_pack.py`：把接口元数据、curl 草稿、截图占位和报告字段整理成攻击成果模板素材。
5. `ai_prompt_checklist_runner.py`：把提示词测试清单转为可打分、可截图、可复测的 AI 安全测试模板。

## 门控边界

弱口令、批量登录、自动注册、批量 ID 遍历、数据导出/下载、上传、命令执行、SQLMap、数据库访问和内网扫描仍然需要显式审批或人工门控。默认项目路线继续保持低速、只读、最小证据和敏感值不入报告。
