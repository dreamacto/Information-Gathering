// Paste into a logged-in Butian page console.
// Purpose: read Butian platform submit pages and extract the "域名或ip" field.
// It only requests https://www.butian.net/Loo/submit?cid=... pages with the current session.
// It does NOT request target domains and does NOT submit any vulnerability form.
//
// Input: choose butian_company_ids_captured_*.csv when prompted.
// Output CSV: butian_submit_domains_*.csv

(async () => {
  const STORAGE_KEY = "__butian_submit_domain_extract_v1__";
  const STOP_KEY = "__butian_submit_domain_extract_stop_v1__";
  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const BUTIAN_ORIGIN = location.origin || "https://www.butian.net";
  const DENY_HOST_PARTS = [
    "butian.net",
    "qianxin.com",
    "yun.qianxin.com",
    "qq.com",
    "qpic.cn",
    "weixin.qq.com",
    "mp.weixin.qq.com",
    "baidu.com",
    "bdstatic.com",
    "cnzz.com",
  ];
  const ALLOWED_TLDS = new Set([
    "cn", "com", "net", "org", "edu", "gov", "ac", "mil",
    "cc", "info", "biz", "top", "vip", "xyz", "io", "me", "tv",
  ]);
  const DENY_EXACT_HOSTS = new Set([
    "t.filelist",
    "t.url",
    "t.href",
    "t.domain",
    "t.host",
    "this.filelist",
    "window.location",
    "location.href",
  ]);

  function nowStamp() {
    return new Date().toISOString();
  }

  function csvParse(text) {
    const rows = [];
    let row = [];
    let cell = "";
    let quoted = false;
    for (let i = 0; i < text.length; i += 1) {
      const ch = text[i];
      const next = text[i + 1];
      if (quoted) {
        if (ch === '"' && next === '"') {
          cell += '"';
          i += 1;
        } else if (ch === '"') {
          quoted = false;
        } else {
          cell += ch;
        }
      } else if (ch === '"') {
        quoted = true;
      } else if (ch === ",") {
        row.push(cell);
        cell = "";
      } else if (ch === "\n") {
        row.push(cell);
        rows.push(row);
        row = [];
        cell = "";
      } else if (ch !== "\r") {
        cell += ch;
      }
    }
    row.push(cell);
    rows.push(row);
    while (rows.length && rows[rows.length - 1].every((value) => !String(value || "").trim())) rows.pop();
    if (!rows.length) return [];
    const headers = rows.shift().map((value) => String(value || "").replace(/^\ufeff/, "").trim());
    return rows.map((values) => Object.fromEntries(headers.map((header, index) => [header, values[index] ?? ""])));
  }

  async function pickCsvFile() {
    return await new Promise((resolve, reject) => {
      const oldPanel = document.getElementById("__butian_submit_domain_file_panel__");
      if (oldPanel) oldPanel.remove();

      const panel = document.createElement("div");
      panel.id = "__butian_submit_domain_file_panel__";
      panel.style.cssText = [
        "position:fixed",
        "z-index:2147483647",
        "right:24px",
        "top:96px",
        "width:420px",
        "padding:16px",
        "background:#fff",
        "border:2px solid #1677ff",
        "box-shadow:0 8px 28px rgba(0,0,0,.25)",
        "border-radius:8px",
        "font-size:14px",
        "line-height:1.6",
        "color:#111",
      ].join(";");

      const title = document.createElement("div");
      title.textContent = "补天 CSV 选择";
      title.style.cssText = "font-weight:700;font-size:16px;margin-bottom:8px;color:#1677ff";
      panel.appendChild(title);

      const tip = document.createElement("div");
      tip.textContent = "浏览器禁止控制台脚本自动弹出文件框。请你手动点击下面的“选择文件”，选择 butian_company_ids_captured_*.csv。";
      tip.style.cssText = "margin-bottom:10px";
      panel.appendChild(tip);

      const input = document.createElement("input");
      input.type = "file";
      input.accept = ".csv,text/csv";
      input.style.cssText = "display:block;width:100%;margin:8px 0 12px";
      panel.appendChild(input);

      const status = document.createElement("div");
      status.textContent = "等待你手动选择 CSV 文件……";
      status.style.cssText = "color:#666;margin-bottom:8px";
      panel.appendChild(status);

      const cancel = document.createElement("button");
      cancel.textContent = "取消";
      cancel.style.cssText = "padding:6px 12px;border:1px solid #ccc;background:#f7f7f7;border-radius:4px;cursor:pointer";
      cancel.addEventListener("click", () => {
        panel.remove();
        reject(new Error("file selection cancelled"));
      });
      panel.appendChild(cancel);

      document.body.appendChild(panel);
      input.addEventListener("change", async () => {
        try {
          const file = input.files?.[0];
          if (!file) throw new Error("no file selected");
          status.textContent = `读取文件：${file.name}`;
          const text = await file.text();
          panel.remove();
          resolve({ name: file.name, text });
        } catch (error) {
          panel.remove();
          reject(error);
        }
      });
    });
  }

  function existingResults() {
    try {
      return JSON.parse(sessionStorage.getItem(STORAGE_KEY) || "[]");
    } catch (_) {
      return [];
    }
  }

  function saveResults(results) {
    const dedup = new Map();
    for (const row of results) {
      const key = String(row.company_id || row.submit_url || row.name || "");
      if (key && !dedup.has(key)) {
        dedup.set(key, {
          index: row.index ?? "",
          name: row.name ?? "",
          company_id: row.company_id ?? "",
          submit_url: row.submit_url ?? "",
          domain_or_ip: row.domain_or_ip ?? "",
          normalized_target_url: row.normalized_target_url ?? "",
          all_candidates: String(row.all_candidates ?? "").slice(0, 300),
          status: row.status ?? "",
          error: row.error ?? "",
          captured_at: row.captured_at ?? "",
        });
      }
    }
    const saved = [...dedup.values()];
    const payload = JSON.stringify(saved);
    try {
      sessionStorage.setItem(STORAGE_KEY, payload);
    } catch (error) {
      console.warn("[butian-submit-domain] sessionStorage quota hit; retrying with compact cache", error);
      const compact = saved.map((row) => ({
        index: row.index,
        name: row.name,
        company_id: row.company_id,
        submit_url: row.submit_url,
        domain_or_ip: row.domain_or_ip,
        normalized_target_url: row.normalized_target_url,
        status: row.status,
        error: row.error,
        captured_at: row.captured_at,
      }));
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify(compact));
      return compact;
    }
    return saved;
  }

  function htmlDecode(value) {
    const textarea = document.createElement("textarea");
    textarea.innerHTML = String(value || "");
    return textarea.value;
  }

  function stripTags(value) {
    return htmlDecode(String(value || "").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ")).trim();
  }

  function hostOf(value) {
    let raw = String(value || "").trim();
    if (!raw) return "";
    if (/^www\./i.test(raw)) raw = `https://${raw}`;
    try {
      return new URL(raw).hostname.toLowerCase();
    } catch (_) {
      return raw.split(/[/:?#]/)[0].toLowerCase();
    }
  }

  function isDeniedHost(host) {
    if (!host) return true;
    const lowered = String(host || "").toLowerCase();
    if (DENY_EXACT_HOSTS.has(lowered)) return true;
    if (/^(?:t|e|i|o|r|n|this|that|item|data|res|row)\./i.test(lowered)) return true;
    return DENY_HOST_PARTS.some((part) => lowered === part || lowered.endsWith(`.${part}`) || lowered.includes(part));
  }

  function cleanCandidate(value) {
    let raw = htmlDecode(String(value || ""))
      .replace(/\\\//g, "/")
      .replace(/^[\s"'“”‘’<>{}()[\]：:，,。;；、]+|[\s"'“”‘’<>{}()[\]：:，,。;；、]+$/g, "")
      .trim();
    if (!raw) return "";
    raw = raw.replace(/^URL格式[:：]\s*/i, "");
    raw = raw.replace(/^域名或ip[:：]\s*/i, "");
    raw = raw.replace(/^域名或IP[:：]\s*/i, "");
    if (/^www\./i.test(raw)) return raw.toLowerCase();
    if (/^https?:\/\//i.test(raw)) {
      try {
        const url = new URL(raw);
        url.hash = "";
        return url.href.replace(/\/$/, "");
      } catch (_) {
        return "";
      }
    }
    return raw.toLowerCase();
  }

  function looksLikeDomainOrIp(value) {
    const raw = cleanCandidate(value);
    if (!raw || raw.length > 180) return false;
    const host = hostOf(raw);
    if (!host || isDeniedHost(host)) return false;
    if (!/^[a-z0-9.-]+$/i.test(host) && !/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)) return false;
    if (/\.(?:png|jpg|jpeg|gif|svg|webp|ico|css|js|woff2?|ttf|map)$/i.test(host)) return false;
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)) return true;
    const parts = host.split(".");
    const tld = parts[parts.length - 1];
    if (!ALLOWED_TLDS.has(tld)) return false;
    if (parts.length < 2 || parts.some((part) => !part || part.length > 63)) return false;
    return /^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/i.test(host);
  }

  function normalizedTargetUrl(value) {
    const raw = cleanCandidate(value);
    if (!raw) return "";
    if (/^https?:\/\//i.test(raw)) return raw;
    return `https://${raw}`;
  }

  function addCandidate(map, value, source, weight = 0) {
    const cleaned = cleanCandidate(value);
    if (!looksLikeDomainOrIp(cleaned)) return;
    const host = hostOf(cleaned);
    const prev = map.get(cleaned) || { value: cleaned, host, score: 0, sources: [] };
    prev.score += weight;
    if (!prev.sources.includes(source)) prev.sources.push(source);
    map.set(cleaned, prev);
  }

  function extractFromRegion(region, candidates, source, weight) {
    const valueRegex = /\bvalue\s*=\s*["']([^"']{3,240})["']/gi;
    let match;
    while ((match = valueRegex.exec(region)) !== null) addCandidate(candidates, match[1], `${source}:value`, weight + 20);

    const urlRegex = /((?:https?:\/\/|www\.)[a-z0-9.-]+(?::\d+)?(?:\/[^\s"'<>，。；;、]*)?)/gi;
    while ((match = urlRegex.exec(region)) !== null) addCandidate(candidates, match[1], `${source}:url`, weight + 10);

    const domainRegex = /\b([a-z0-9-]+(?:\.[a-z0-9-]+){1,})(?::\d+)?\b/gi;
    while ((match = domainRegex.exec(region)) !== null) addCandidate(candidates, match[1], `${source}:domain`, weight);
  }

  function parseSubmitPage(html, name) {
    const candidates = new Map();
    const labels = ["域名或ip", "域名或IP", "域名或 ip", "域名/IP", "主URL", "主 URL", "主站", "官网", "官方网站", "测试范围", "可测范围", "资产范围"];

    for (const label of labels) {
      let idx = html.indexOf(label);
      while (idx >= 0) {
        const region = html.slice(Math.max(0, idx - 800), Math.min(html.length, idx + 2600));
        extractFromRegion(region, candidates, `label:${label}`, 80);
        idx = html.indexOf(label, idx + label.length);
      }
    }

    const jsonFieldRegex = /["'](?:domain|host|url|site|weburl|web_url|target|target_url|company_url|scope|asset|asset_url|main_url)["']\s*[:=]\s*["']([^"']{3,240})["']/gi;
    let match;
    while ((match = jsonFieldRegex.exec(html)) !== null) addCandidate(candidates, match[1], "json_field", 45);

    const ranked = [...candidates.values()]
      .map((item) => {
        let score = item.score;
        if (/学院|大学|学校|师范|职业|科技|医学院|医院/.test(name || "") && /\.edu\.cn$/i.test(item.host)) score += 35;
        if (/医院/.test(name || "") && /(hospital|hosp|yfy|fy|120|med|health)/i.test(item.host)) score += 15;
        if (/oss-|qianxin|butian/i.test(item.host)) score -= 1000;
        return { ...item, score };
      })
      .filter((item) => item.score > -100)
      .sort((a, b) => b.score - a.score || a.value.length - b.value.length);

    return {
      best: ranked[0]?.value || "",
      all: ranked.map((item) => `${item.value} [${item.score}:${item.sources.join("+")}]`),
    };
  }

  async function fetchText(url, timeoutMs) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(url, {
        credentials: "include",
        signal: controller.signal,
        headers: { "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" },
      });
      const text = await response.text();
      return { status: response.status, text, final_url: response.url };
    } finally {
      clearTimeout(timer);
    }
  }

  function downloadRows(data, suffix = "") {
    const headers = ["index", "name", "company_id", "submit_url", "domain_or_ip", "normalized_target_url", "all_candidates", "status", "error", "captured_at"];
    const csvEscape = (value) => `"${String(value ?? "").replaceAll('"', '""')}"`;
    const csv = "\ufeff" + [
      headers.join(","),
      ...data.map((row) => headers.map((key) => csvEscape(row[key])).join(",")),
    ].join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    const a = document.createElement("a");
    const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
    a.href = URL.createObjectURL(blob);
    a.download = `butian_submit_domains_${suffix ? suffix + "_" : ""}${stamp}.csv`;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 3000);
    a.remove();
    console.table(data);
    console.log(`[butian-submit-domain] exported ${data.length} rows`);
  }

  const cached = existingResults();
  if (cached.length) {
    const choice = prompt(`发现上次缓存 ${cached.length} 条：1=直接导出，2=继续/补跑，0=清空重来，9=停止当前任务`, "1");
    if (choice === "1") return downloadRows(cached, "cached");
    if (choice === "9") {
      sessionStorage.setItem(STOP_KEY, "1");
      console.warn("[butian-submit-domain] stop flag set");
      return;
    }
    if (choice === "0") {
      sessionStorage.removeItem(STORAGE_KEY);
    }
  }
  sessionStorage.removeItem(STOP_KEY);

  const picked = await pickCsvFile();
  const csvRows = csvParse(picked.text)
    .map((row, index) => ({
      index: index + 1,
      name: String(row.name || row.company_name || row.companyName || "").trim(),
      company_id: String(row.company_id || row.cid || row.companyId || "").trim(),
      submit_url: String(row.submit_url || "").trim(),
    }))
    .filter((row) => row.company_id && row.name)
    .map((row) => ({
      ...row,
      submit_url: row.submit_url || new URL(`/Loo/submit?cid=${row.company_id}`, BUTIAN_ORIGIN).href,
    }));

  const maxCount = Math.max(0, Number(prompt(`共 ${csvRows.length} 条，最多处理多少条？0=全部`, "0") || 0) || 0);
  const delayMs = Math.max(3000, Number(prompt("每个补天提交页间隔毫秒？建议 5000", "5000") || 5000) || 5000);
  const timeoutMs = Math.max(8000, Number(prompt("单页超时毫秒？", "15000") || 15000) || 15000);
  const rowsToRun = maxCount ? csvRows.slice(0, maxCount) : csvRows;

  const results = existingResults();
  const done = new Set(results.map((row) => String(row.company_id || "")));
  console.log(`[butian-submit-domain] start rows=${rowsToRun.length} delayMs=${delayMs} timeoutMs=${timeoutMs}`);

  for (const row of rowsToRun) {
    if (sessionStorage.getItem(STOP_KEY) === "1") {
      console.warn("[butian-submit-domain] stopped by operator");
      break;
    }
    if (done.has(row.company_id)) continue;
    const output = {
      index: row.index,
      name: row.name,
      company_id: row.company_id,
      submit_url: row.submit_url,
      domain_or_ip: "",
      normalized_target_url: "",
      all_candidates: "",
      status: "",
      error: "",
      captured_at: nowStamp(),
    };
    try {
      const fetched = await fetchText(row.submit_url, timeoutMs);
      const parsed = parseSubmitPage(fetched.text, row.name);
      output.domain_or_ip = parsed.best;
      output.normalized_target_url = parsed.best ? normalizedTargetUrl(parsed.best) : "";
      output.all_candidates = parsed.all.slice(0, 5).join("; ");
      output.status = `fetch_${fetched.status}_${parsed.best ? "domain_found" : "no_domain"}`;
    } catch (error) {
      output.status = "fetch_error";
      output.error = String(error && error.message ? error.message : error).slice(0, 300);
    }
    results.push(output);
    const savedResults = saveResults(results);
    results.length = 0;
    results.push(...savedResults);
    done.add(row.company_id);
    console.log(`[butian-submit-domain] ${output.index}/${csvRows.length} ${output.name} ${output.status} ${output.domain_or_ip || ""}`);
    await sleep(delayMs);
  }

  downloadRows(saveResults(results), "captured");
})();
