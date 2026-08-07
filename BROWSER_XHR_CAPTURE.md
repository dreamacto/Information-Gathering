# 浏览器 XHR/FETCH 采集与本地复现

这个工具用于你手工登录、注册、点击业务功能时，自动收集 XHR/FETCH/API 元数据，并在显式开启时生成本机复现用的 Cookie/Authorization 草稿。

## 一键启动

双击项目根目录：

```text
启动浏览器XHR采集_本地复现版.bat
```

按提示输入目标 URL。浏览器打开后，你正常登录并点击个人中心、列表、详情、订单、访客、缴费、后台菜单等业务功能。完成后回到终端按 Enter。

也可以命令行运行：

```powershell
& 'C:\Users\ASUS\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe' .\tools\browser_xhr_capture.mjs --url https://example.edu.cn --profile example --save-local-replay
```

## 输出

默认一定生成：

- `浏览器采集结果_汇总.md`：高价值接口、疑似越权参数、新域名、全部接口清单。

开启 `--save-local-replay` 时额外保留：

- `auth_sessions.local.json`：可接入 `authenticated_session_review.py` 的本地会话文件。
- `replay_requests.local.jsonl`：同站请求复现草稿，含必要请求头。
- `curl_replay.local.txt`：本机 curl 复现草稿。
- `manifest.local.json`：本地复现输出说明。

这些 `.local` 文件可能包含 Cookie、Authorization 或 Token，只能短期留在本机使用，不要随攻击成果报告提交，也不要上传仓库。

## 安全边界

脚本不会自动执行弱口令、注册、批量改 ID、导出、下载、支付、删除或提交动作。

默认不保存响应正文，也不保存请求体原文。POST/PUT/PATCH/DELETE 会进入人工复核队列；只有你额外加 `--save-local-request-body` 才会保存请求体原文。

推荐流程：

1. 先用同一个 `--profile` 保持登录态。
2. 看 `浏览器采集结果_汇总.md` 的高价值接口和疑似越权参数。
3. 用 `curl_replay.local.txt` 对 GET 型接口做最小化只读复现。
4. 需要接入项目认证态复核时，把 `auth_sessions.local.json` 作为 `authenticated_session_review.py --cookie-file` 输入。
