# Burp MCP Server 调用指南（适配所有 agent）

> 目的：本机 Burp（PortSwigger 官方 **MCP Server 扩展**）暴露 HTTP 历史，供任意 AI agent 读取。
> **一份文档，换任何 agent 都能用。** 核心思路：不用每个 agent 各自的 MCP 配置，而是用
> **mcporter 作 CLI 桥**——任何能执行 shell 命令的 agent 都能调用（通用性最高）。

## 1. 服务是什么、在哪、怎么算可用

| 项 | 值 |
|---|---|
| 提供商 | PortSwigger（Burp 官方 **MCP Server** 扩展） |
| 端点 | `http://127.0.0.1:9876` |
| 传输 | SSE（旧式。README 的"先 GET 建流拿 sessionId 再 POST"是手动裸调法；用 mcporter 已封装） |
| 前提 | **Burp 必须打开** 且 已安装/启用 **MCP Server** 扩展（listen 127.0.0.1:9876） |
| 判断 | mcporter `list` 成功 = 可用；`ECONNREFUSED 127.0.0.1:9876` = Burp 未启用 MCP 扩展（见下） |
| 易失性 | **Burp 重启 / 切项目会丢历史**，重要窗口先用下面方法导出落盘再继续 |

## 2. 通用调用法（不需要 agent 支持 MCP —— 推荐）

任何 agent，只要有 shell/终端执行能力，用 mcporter（Node 包，`npx` 即可，无需安装）：

```bash
# 1) 列出服务是否在线 + 工具（mcporter 直连 SSE）
npx -y mcporter@0.9.0 list http://127.0.0.1:9876 --allow-http

# 2) 调用工具（call 用 --http-url，不是位置参数；参数 key=value 风格）
npx -y mcporter@0.9.0 call get_proxy_http_history \
  --http-url http://127.0.0.1:9876 --allow-http \
  "count=60" "offset=0" --output json

# 3) 用正则查历史（最常用）
npx -y mcporter@0.9.0 call get_proxy_http_history_regex \
  --http-url http://127.0.0.1:9876 --allow-http \
  "count=60" "offset=0" "regex=addSsFavorite" --output json
```

> 24 个工具，读历史主要是两个：`get_proxy_http_history(count, offset)`、
> `get_proxy_http_history_regex(count, offset, regex)`。`--output json` 是 mcporter 输出格式。

## 3. 如果你用的 agent 原生支持 MCP —— 各自配置样例

> 不同 agent 配置文件不同（这也是"适配所有"难的地方）。以下为常见几种，找不到就退回第 2 节 mcporter。
> 本服务传输是 **SSE**（旧式），MCP 客户端里 transport 选 `sse` / url 填端点。

**OpenCode（本项目在用）** — `opencode.json`：
```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": { "burp": { "type": "remote", "url": "http://127.0.0.1:9876", "enabled": true } }
}
```
> ⚠️ 本服务是**旧式 SSE**、非 Streamable HTTP，部分 OpenCode/newer 客户端版本可能连不上。
> 连不上就**别配 MCP，直接让 agent 跑第 2 节的 mcporter 命令**（这是最稳、最通用的方式），
> 或在 `mcp` 里配 `"command": ["npx", "-y", "mcp-remote", "http://127.0.0.1:9876"]`（用 mcp-remote 转成本地 stdio）。
> 一句话：本项目实际用方式 = **agent shell 直接 `npx mcporter call ...`**（第 2 节），不依赖 opencode.json 的 mcp 配置。

**Claude Desktop** — `claude_desktop_config.json`：
```json
{
  "mcpServers": {
    "burp": { "type": "sse", "url": "http://127.0.0.1:9876" }
  }
}
```

**Cursor / Windsurf** — `.mcp.json`（或被合并到全局 `~/.cursor/mcp.json`）：
```json
{ "mcpServers": { "burp": { "type": "sse", "url": "http://127.0.0.1:9876" } } }
```

**Continue** — `~/.continue/config.yaml`：
```yaml
mcpServers:
  burp:
    type: sse
    url: http://127.0.0.1:9876
```

> 一句话：凡是支持 `sse`/`url` 的直接填端点；不支持的（或懒得配的）一律用 **第 2 节 mcporter**，
> 它把 MCP 翻译成 shell 命令，任何 agent 都能调。这就是"适配所有 agent 软件"的通用答案。

## 4. 手动裸调（SSE 握手，备用）

仅当 mcporter 不可用、且你确认要自己握手才用（一般不需要）：
1. `GET http://127.0.0.1:9876`（Accept: text/event-stream）建立 SSE 流，服务端下发 `data: ?sessionId=<uuid>`。
2. 之后所有 JSON-RPC 请求 POST 到 `http://127.0.0.1:9876/?sessionId=<uuid>`。
3. 顺序：`initialize` → `notifications/initialized` → `tools/list` → `tools/call`。

## 5. 纪律（必须遵守，否则污染报告/台账）

- **只读结构**：只取 URL/path/method/状态码/字段名；历史条目里的 Cookie / Authorization / x-token / jsCode /
  手机号 / 姓名 / unionid / userid 等值 **只记字段名与状态码，值不进对话、不落盘**。
- **取证只引 request 行结构**（如 `GET /bbsapi/topic/addUserFavTopics`），不带参数值。
- **导出优先**：Burp 重启丢历史；重要窗口结束先用 MCP 拉取并落盘（下面 PowerShell 注意编码）。

## 6. 从命令行/脚本落盘的编码坑（Windows PowerShell）

`npx ... --output json > file` 会把输出写成 **UTF-16**（PowerShell 重定向默认），导致 Python `json.loads`
报 `UnicodeDecodeError: 'utf-8' codec ... 0xff`。两种解法：
```powershell
# 解法 A：让 PowerShell 明确 UTF-8（注意 5.1 无 utf8NoBOM，用 Set-Content / Out-File -Encoding utf8 仍可能带BOM）
npx -y mcporter@0.9.0 call get_proxy_http_history_regex --http-url http://127.0.0.1:9876 --allow-http "count=60" "offset=0" "regex=addUserFavTopics" --output json | Set-Content -Encoding utf8 "$env:TEMP\x.json"
```
```python
# 解法 B（最稳）：Python 里自适应解码（BOM / UTF-16 / UTF-8 都兼容）
raw = open(r'C:\...\x.json', 'rb').read()
for enc in ('utf-8-sig', 'utf-16-le'):
    try: t = raw.decode(enc); break
    except Exception: continue
t = t.lstrip('\ufeff')
d = json.loads(t)          # 然后从 d['content'] 取 text，text 是内嵌 JSON(请求/响应)
```
> mcporter 返回结构通常是 `{"content": "<一个 JSON 字符串（含 request/response 文本）>", "isError": false}`；
> 解析时先 `json.loads(d['content'])` 再逐条，或用 `json.dumps` 检查 `isError`。

## 7. 快速自检命令

```bash
# 在线?  成功 => 列出服务;  失败(mcporter list 报 offline / ECONNREFUSED) => Burp 未开 MCP 扩展
npx -y mcporter@0.9.0 list http://127.0.0.1:9876 --allow-http
```
