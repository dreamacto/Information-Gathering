# -*- coding: utf-8 -*-
"""W13 · sink 模式库生成器（写入 knowledge_base/sink_lib.jsonl）

七类 × js 为主的 60+ 条种子。正则 pattern（RE 语法），severity: high|medium|low。
"""
import json
from pathlib import Path

SINKS = [
    # ---- sqli (10) ----
    ("sqli", "js", r"wx\.request\(\{[^}]*url[^}]*\+[^}]*\}", "high", "小程序请求 URL 拼接（可能注入 SQL/路径）"),
    ("sqli", "js", r"\$\.(?:get|post|ajax)\(\s*[\"'][^\"']*[\"']\s*\+", "high", "jQuery 请求 URL 拼接"),
    ("sqli", "js", r"(?:query|execute|sql)[\"']?\s*[:=]\s*[\"'][^\"']*SELECT[^\"']*[\"']\s*\+", "high", "SQL 字符串拼接（前端构造）"),
    ("sqli", "js", r"querySql\s*\(|runSql\s*\(|execSql\s*\(", "high", "直接执行 SQL 的封装调用"),
    ("sqli", "js", r"\$\{[^}]*\}\s*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)", "high", "模板字符串拼 SQL"),
    ("sqli", "js", r"where.*\+.*(?:id|uid|userId)", "medium", "WHERE 条件拼接 id"),
    ("sqli", "js", r"order\s*by\s*[\"']?\s*\+", "medium", "ORDER BY 拼接"),
    ("sqli", "js", r"like\s*[\"']?%", "medium", "LIKE 模糊拼接"),
    ("sqli", "js", r"interfaceUrl\s*\+\s*\w+", "medium", "接口 URL 变量拼接"),
    ("sqli", "js", r"/api/\w+\s*\+\s*(?:id|uid|userId|no)", "medium", "RESTful 路径拼接 id"),
    # ---- command (8) ----
    ("command", "js", r"child_process\.exec(?:Sync)?\s*\(", "high", "Node 子进程命令执行"),
    ("command", "js", r"child_process\.execFile\s*\(", "medium", "Node execFile"),
    ("command", "js", r"\.exec\s*\(\s*[\"'`][^\"'`]*\$\{", "high", "exec 模板字符串命令拼接"),
    ("command", "js", r"eval\s*\(", "high", "eval 动态执行"),
    ("command", "js", r"new\s+Function\s*\(", "high", "new Function 动态构造"),
    ("command", "js", r"setTimeout\s*\(\s*[\"']", "medium", "setTimeout 字符串执行"),
    ("command", "js", r"\bshell\s*\.\s*(?:exec|run)\s*\(", "high", "shell 库执行"),
    ("command", "js", r"process\.env\s*\+\s*[\"']", "low", "env 拼接命令（信息泄露面）"),
    # ---- path_traversal (9) ----
    ("path_traversal", "js", r"(?:fs|fsExtra|fs\.(?:promises)?)\.(?:readFile|readFileSync|writeFile|writeFileSync|unlink|unlinkSync|createReadStream)\s*\(\s*[^,)]*\+", "high", "文件读写路径拼接"),
    ("path_traversal", "js", r"path\.(?:join|resolve)\s*\([^)]*(?:req\.(?:query|params|body)|request\.)", "high", "path.join 入参含请求数据"),
    ("path_traversal", "js", r"(?:download|upload|file|get)[A-Za-z]*\s*\(\s*req\.(?:query|params)\.", "high", "下载/文件接口直接用请求参数"),
    ("path_traversal", "js", r"\.\./\.\./", "medium", "穿越序列硬编码"),
    ("path_traversal", "js", r"readFile\s*\(\s*[\"']\.\./", "medium", "相对路径读取"),
    ("path_traversal", "js", r"sendFile\s*\(\s*[^,)]*\+", "high", "sendFile 拼接"),
    ("path_traversal", "js", r"static\s*\(\s*[\"']/\s*[\"']\s*\)", "low", "静态目录挂根"),
    ("path_traversal", "js", r"multer|formidable", "low", "上传中间件（检查落盘名是否可控）"),
    ("path_traversal", "js", r"\.createWriteStream\s*\(\s*[^,)]*\+", "high", "写流路径拼接"),
    # ---- ssrf (7) ----
    ("ssrf", "js", r"(?:axios|fetch|request|got)\s*\(\s*(?:req|request)\.(?:query|body|params)", "high", "HTTP 客户端 URL 直接取自请求"),
    ("ssrf", "js", r"url\s*[:=]\s*req\.query\.url", "high", "经典 ?url= 直传"),
    ("ssrf", "js", r"(?:imageUrl|fileUrl|webhookUrl|callbackUrl)\s*[:=]\s*req\.", "high", "回调/资源 URL 取自请求"),
    ("ssrf", "js", r"urllib\.request\s*\(\s*[^,)]*\+", "medium", "urllib 拼接"),
    ("ssrf", "js", r"http\.get\s*\(\s*[^,)]*(?:host|domain|target)", "medium", "http.get 变量目标"),
    ("ssrf", "js", r"\.pipe\s*\(\s*request\s*\(\s*req\.", "high", "代理管道直传"),
    ("ssrf", "js", r"dns\.resolve\w*\s*\(\s*req\.", "medium", "DNS 解析请求参数"),
    # ---- deserialize (6) ----
    ("deserialize", "js", r"JSON\.parse\s*\(\s*(?:atob|unescape|decodeURIComponent)\s*\(", "high", "解码后反序列化（可能原型污染/注入）"),
    ("deserialize", "js", r"serialize\.unserialize\s*\(", "high", "node-serialize 反序列化（RCE 经典）"),
    ("deserialize", "js", r"yaml\.load\s*\(", "medium", "yaml.load 非 safeLoad"),
    ("deserialize", "js", r"node-serialize|funcster|serialize-javascript", "medium", "序列化库引用"),
    ("deserialize", "js", r"Object\.assign\s*\(\s*\{\}\s*,\s*JSON\.parse\s*\(\s*req\.", "medium", "请求体合并到对象（原型污染）"),
    ("deserialize", "js", r"lodash.*merge\s*\(\s*[^,]*req\.body", "medium", "lodash merge 请求体（原型污染）"),
    # ---- weak_crypto (10) ----
    ("weak_crypto", "js", r"\bmd5\s*\(|createHash\s*\(\s*[\"']md5[\"']", "medium", "MD5 弱哈希"),
    ("weak_crypto", "js", r"\bsha1\s*\(|createHash\s*\(\s*[\"']sha1[\"']", "low", "SHA1 弱哈希"),
    ("weak_crypto", "js", r"DES|des\.encrypt|3des", "medium", "DES 弱加密"),
    ("weak_crypto", "js", r"Math\.random\s*\(\s*\)", "low", "Math.random（token/密钥生成不可用）"),
    ("weak_crypto", "js", r"[\"'](?:123456|admin|password|passwd|secret|token|apikey|app_?key)[\"']\s*[:=]\s*[\"'][^\"']{4,}[\"']", "high", "硬编码口令/密钥"),
    ("weak_crypto", "js", r"aes[- ]?128[- ]?ecb|AES-128-ECB", "medium", "ECB 模式"),
    ("weak_crypto", "js", r"jwt\.sign\s*\([^,]*,\s*[\"'][^\"']{1,16}[\"']", "high", "JWT 弱密钥签名"),
    ("weak_crypto", "js", r"verify.*signature.*false|verify\s*=\s*false", "medium", "关闭签名校验"),
    ("weak_crypto", "js", r"https?://[^\"']*(?:password|passwd|secret|token)=", "high", "URL 携带凭证"),
    ("weak_crypto", "js", r"(?:accessKey|secretKey|appSecret|secret_key)\s*[:=]\s*[\"'][A-Za-z0-9+/=]{16,}[\"']", "high", "云/支付密钥硬编码"),
    # ---- authz_missing (12) ----
    ("authz_missing", "js", r"(?:admin|manage|internal|debug)/\w+\.js", "medium", "管理/内部页面源码可达"),
    ("authz_missing", "js", r"isAdmin\s*[:=]\s*(?:req\.|params|query|body)", "high", "管理员判定取自请求参数"),
    ("authz_missing", "js", r"role\s*[:=]\s*req\.(?:body|query)\.role", "high", "角色取自请求"),
    ("authz_missing", "js", r"userId\s*[:=]\s*req\.(?:body|query)\.(?:userId|uid)", "high", "身份取自请求（水平越权温床）"),
    ("authz_missing", "js", r"owner\s*[:=]\s*req\.body", "high", "owner 取自请求体"),
    ("authz_missing", "js", r"(?:delete|update|remove)\w*\s*\(\s*req\.params\.id\s*\)(?![^)]*check|[^)]*auth)", "medium", "删改操作仅凭 id"),
    ("authz_missing", "js", r"@role\(['\"]?(?:user|guest)['\"]?\)", "low", "低权限注解（检查是否可提权）"),
    ("authz_missing", "js", r"(?:skipAuth|noAuth|ignoreAuth|disableAuth)\s*[:=]\s*true", "high", "显式关闭鉴权"),
    ("authz_missing", "js", r"session(?:s)?\.(?:userId|uid|user_id)\s*=\s*req\.", "high", "会话身份可被请求覆盖"),
    ("authz_missing", "js", r"/api/(?:admin|internal|debug|test)/", "medium", "内部 API 路径"),
    ("authz_missing", "js", r"checkLogin\s*\(\s*\)\s*\{\s*return\s+true", "high", "登录校验恒真"),
    ("authz_missing", "js", r"permission\s*[:=]\s*(?:0|false|none)", "low", "权限字段弱值"),
]

out = Path(__file__).resolve().parent.parent / "knowledge_base" / "sink_lib.jsonl"
out.parent.mkdir(parents=True, exist_ok=True)
with out.open("w", encoding="utf-8") as f:
    for cat, lang, pat, sev, note in SINKS:
        f.write(json.dumps({"category": cat, "lang": lang, "pattern": pat,
                            "severity": sev, "note": note}, ensure_ascii=False) + "\n")
print(f"[+] {len(SINKS)} 条 sink 模式 → {out}")
