// Paste into a logged-in Butian page console.
// Purpose: render Butian submit pages in a same-origin iframe and extract the "域名或ip" input value.
// It only loads https://www.butian.net/Loo/submit?cid=... pages.
// It does NOT request target domains and does NOT submit any vulnerability form.
//
// Input: choose butian_company_ids_captured_*.csv when prompted.
// Output CSV: butian_submit_domains_iframe_*.csv

(async () => {
  const STORAGE_KEY = "__butian_submit_domain_iframe_extract_v2__";
  const RESULT_GLOBAL_KEY = "__butian_submit_domain_iframe_results_v2__";
  const STOP_KEY = "__butian_submit_domain_iframe_stop_v1__";
  const OLD_STORAGE_KEYS = [
    "__butian_submit_domain_extract_v1__",
    "__butian_submit_domain_iframe_extract_v1__",
    "__butian_submit_domain_iframe_extract_v2__",
  ];
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
  const ALLOWED_TLDS = new Set(["cn", "com", "net", "org", "edu", "gov", "ac", "mil", "cc", "info", "biz", "top", "vip", "xyz", "io", "me", "tv"]);
  const runtimeState = {
    geetestErrors: 0,
    lastGeetestError: "",
  };

  function stringifyErrorLike(value) {
    if (!value) return "";
    if (typeof value === "string") return value;
    if (value.message || value.stack) return `${value.message || ""} ${value.stack || ""}`.trim();
    try {
      return JSON.stringify(value);
    } catch (_) {
      return String(value);
    }
  }

  function looksLikeGeetestError(value) {
    return /geetest|gt\.js|fullpage|\/get\.php|gettype\.php|challenge/i.test(String(value || ""));
  }

  function rememberGeetestError(value, source) {
    const compact = stringifyErrorLike(value).replace(/\s+/g, " ").slice(0, 260);
    runtimeState.geetestErrors += 1;
    runtimeState.lastGeetestError = `${source}: ${compact || "geetest runtime error"}`;
    console.warn(`[butian-iframe-domain] Geetest/风控错误已记录 ${runtimeState.geetestErrors} 次：${runtimeState.lastGeetestError}`);
  }

  function installGeetestGuardOnWindow(targetWindow, label) {
    try {
      if (!targetWindow || targetWindow.__butian_geetest_guard_installed__) return;
      targetWindow.__butian_geetest_guard_installed__ = true;
      targetWindow.addEventListener("error", (event) => {
        const text = `${event.message || ""} ${event.filename || ""} ${stringifyErrorLike(event.error)}`;
        if (!looksLikeGeetestError(text)) return;
        rememberGeetestError(text, `${label}:error`);
        event.preventDefault();
      }, true);
      targetWindow.addEventListener("unhandledrejection", (event) => {
        const text = stringifyErrorLike(event.reason);
        if (!looksLikeGeetestError(text)) return;
        rememberGeetestError(text, `${label}:promise`);
        event.preventDefault();
      }, true);
    } catch (_) {
      // Cross-window guard installation is best-effort only.
    }
  }

  installGeetestGuardOnWindow(window, "parent");

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
      const oldPanel = document.getElementById("__butian_iframe_file_panel__");
      if (oldPanel) oldPanel.remove();
      const panel = document.createElement("div");
      panel.id = "__butian_iframe_file_panel__";
      panel.style.cssText = [
        "position:fixed",
        "z-index:2147483647",
        "right:24px",
        "top:96px",
        "width:430px",
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
      title.textContent = "补天 company_id CSV 选择";
      title.style.cssText = "font-weight:700;font-size:16px;margin-bottom:8px;color:#1677ff";
      panel.appendChild(title);
      const tip = document.createElement("div");
      tip.textContent = "请手动选择 butian_company_ids_captured_*.csv。脚本会低速加载补天提交页 iframe，并读取渲染后的“域名或ip”输入框。";
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
    if (Array.isArray(window[RESULT_GLOBAL_KEY])) return window[RESULT_GLOBAL_KEY];
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
      if (!key || dedup.has(key)) continue;
      dedup.set(key, {
        index: row.index ?? "",
        name: row.name ?? "",
        company_id: row.company_id ?? "",
        submit_url: row.submit_url ?? "",
        domain_or_ip: row.domain_or_ip ?? "",
        normalized_target_url: row.normalized_target_url ?? "",
        all_candidates: String(row.all_candidates ?? "").slice(0, 260),
        status: row.status ?? "",
        error: row.error ?? "",
        captured_at: row.captured_at ?? "",
      });
    }
    const saved = [...dedup.values()];
    window[RESULT_GLOBAL_KEY] = saved;
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
    try {
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify(compact));
    } catch (error) {
      console.warn("[butian-iframe-domain] sessionStorage quota hit; clearing old extractor caches and retrying compact progress", error);
      for (const key of OLD_STORAGE_KEYS) {
        if (key !== STORAGE_KEY) sessionStorage.removeItem(key);
      }
      try {
        sessionStorage.setItem(STORAGE_KEY, JSON.stringify(compact));
      } catch (secondError) {
        console.warn("[butian-iframe-domain] compact progress cache still failed; continuing in memory only", secondError);
      }
      return saved;
    }
    return saved;
  }

  function cleanCandidate(value) {
    let raw = String(value || "")
      .replace(/\\\//g, "/")
      .replace(/^[\s"'“”‘’<>{}()[\]：:，,。;；、]+|[\s"'“”‘’<>{}()[\]：:，,。;；、]+$/g, "")
      .trim();
    raw = raw.replace(/^URL格式[:：]\s*/i, "");
    raw = raw.replace(/^域名或ip[:：]\s*/i, "");
    raw = raw.replace(/^域名或IP[:：]\s*/i, "");
    raw = raw.replace(/^请填写[:：]\s*/i, "");
    return raw;
  }

  function hostOf(value) {
    let raw = cleanCandidate(value);
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
    const lowered = host.toLowerCase();
    if (/^(?:t|e|i|o|r|n|this|that|item|data|res|row)\./i.test(lowered)) return true;
    return DENY_HOST_PARTS.some((part) => lowered === part || lowered.endsWith(`.${part}`) || lowered.includes(part));
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
    return parts.length >= 2 && parts.every((part) => part && part.length <= 63) && /^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/i.test(host);
  }

  function normalizedTargetUrl(value) {
    const raw = cleanCandidate(value);
    if (!raw) return "";
    if (/^https?:\/\//i.test(raw)) return raw.replace(/\/$/, "");
    return `https://${raw}`.replace(/\/$/, "");
  }

  function addCandidate(candidates, value, source, score) {
    const cleaned = cleanCandidate(value);
    if (!looksLikeDomainOrIp(cleaned)) return;
    const key = cleaned.toLowerCase();
    const prev = candidates.get(key) || { value: cleaned, host: hostOf(cleaned), score: 0, sources: [] };
    prev.score += score;
    if (!prev.sources.includes(source)) prev.sources.push(source);
    candidates.set(key, prev);
  }

  function textOf(el) {
    return (el?.innerText || el?.textContent || "").replace(/\s+/g, " ").trim();
  }

  function distanceScore(labelEl, inputEl) {
    try {
      const a = labelEl.getBoundingClientRect();
      const b = inputEl.getBoundingClientRect();
      const dy = Math.abs((a.top + a.bottom) / 2 - (b.top + b.bottom) / 2);
      const dx = Math.abs((a.left + a.right) / 2 - (b.left + b.right) / 2);
      if (dy < 35) return 260 - Math.min(120, dx / 5);
      if (dy < 90) return 180 - Math.min(100, dx / 6);
      return 0;
    } catch (_) {
      return 0;
    }
  }

  function extractDomainFromIframeDoc(doc, name) {
    const candidates = new Map();
    const inputs = [...doc.querySelectorAll("input,textarea")].filter((el) => (el.value || "").trim());
    const labelElements = [...doc.querySelectorAll("label,span,div,p,td,th,li")]
      .filter((el) => /域名\s*或\s*ip|域名\s*或\s*IP|域名\/IP|主\s*URL|主站|官网|官方网站|测试范围|可测范围|资产范围/i.test(textOf(el)));

    for (const label of labelElements) {
      const labelText = textOf(label);
      const nearbyInputs = [...(label.closest("tr,li,.form-group,.el-form-item,.ant-form-item,div")?.querySelectorAll("input,textarea") || [])];
      for (const input of nearbyInputs) {
        addCandidate(candidates, input.value, `near_label:${labelText.slice(0, 20)}`, 260);
      }
      for (const input of inputs) {
        const score = distanceScore(label, input);
        if (score > 0) addCandidate(candidates, input.value, `visual_label:${labelText.slice(0, 20)}`, score);
      }
    }

    for (const input of inputs) {
      const value = input.value;
      const meta = [input.name, input.id, input.placeholder, input.getAttribute("aria-label"), input.className].join(" ");
      let score = 20;
      if (/domain|host|site|url|asset|scope|web/i.test(meta)) score += 35;
      if (/漏洞URL|漏洞\s*URL|URL格式/i.test(meta)) score -= 60;
      addCandidate(candidates, value, "input_value", score);
    }

    const ranked = [...candidates.values()]
      .map((item) => {
        let score = item.score;
        if (/学院|大学|学校|师范|职业|科技|医学院|医院/.test(name || "") && /\.edu\.cn$/i.test(item.host)) score += 50;
        if (/医院/.test(name || "") && /(hospital|hosp|yfy|fy|120|med|health)/i.test(item.host)) score += 20;
        if (/^https?:\/\//i.test(item.value)) score += 5;
        return { ...item, score };
      })
      .sort((a, b) => b.score - a.score || a.value.length - b.value.length);

    return {
      best: ranked[0]?.value || "",
      all: ranked.slice(0, 6).map((item) => `${item.value} [${Math.round(item.score)}:${item.sources.join("+")}]`),
      labels: labelElements.map((el) => textOf(el).slice(0, 80)).slice(0, 8),
      input_values: inputs.map((el) => cleanCandidate(el.value)).filter(Boolean).slice(0, 20),
    };
  }

  function buildRunnerIframe() {
    const iframe = document.createElement("iframe");
    iframe.id = "__butian_submit_domain_iframe__";
    iframe.style.cssText = "width:100%;height:488px;border:0;background:#fff";
    iframe.setAttribute("referrerpolicy", "same-origin");
    return iframe;
  }

  function ensureRunnerPanel() {
    let panel = document.getElementById("__butian_iframe_runner_panel__");
    if (panel) {
      if (!document.getElementById("__butian_submit_domain_iframe__")) panel.appendChild(buildRunnerIframe());
      return panel;
    }
    panel = document.createElement("div");
    panel.id = "__butian_iframe_runner_panel__";
    panel.style.cssText = [
      "position:fixed",
      "z-index:2147483646",
      "left:16px",
      "bottom:16px",
      "width:760px",
      "height:520px",
      "background:#fff",
      "border:2px solid #52c41a",
      "box-shadow:0 8px 28px rgba(0,0,0,.25)",
      "border-radius:8px",
      "overflow:hidden",
    ].join(";");
    const header = document.createElement("div");
    header.id = "__butian_iframe_runner_status__";
    header.style.cssText = "height:32px;line-height:32px;padding:0 10px;font-size:13px;background:#f6ffed;color:#135200;border-bottom:1px solid #b7eb8f";
    header.textContent = "补天 iframe 提取器待启动";
    panel.appendChild(header);
    panel.appendChild(buildRunnerIframe());
    document.body.appendChild(panel);
    return panel;
  }

  function setRunnerStatus(text) {
    const el = document.getElementById("__butian_iframe_runner_status__");
    if (el) el.textContent = text;
  }

  async function recycleRunnerIframe(reason = "recycle") {
    const panel = ensureRunnerPanel();
    const oldIframe = document.getElementById("__butian_submit_domain_iframe__");
    if (oldIframe) {
      try {
        oldIframe.src = "about:blank";
      } catch (_) {
        // best-effort cleanup
      }
      await sleep(250);
      try {
        oldIframe.remove();
      } catch (_) {
        // best-effort cleanup
      }
    }
    const iframe = buildRunnerIframe();
    panel.appendChild(iframe);
    console.log(`[butian-iframe-domain] iframe recycled: ${reason}`);
    return iframe;
  }

  async function loadSubmitPageInIframe(url, timeoutMs, row) {
    ensureRunnerPanel();
    let iframe = document.getElementById("__butian_submit_domain_iframe__");
    if (!iframe) iframe = await recycleRunnerIframe("missing_before_load");
    const started = Date.now();
    const geetestErrorsAtStart = runtimeState.geetestErrors;
    iframe.src = url;
    let lastError = "";
    while (Date.now() - started < timeoutMs) {
      await sleep(500);
      try {
        installGeetestGuardOnWindow(iframe.contentWindow, "iframe");
        if (runtimeState.geetestErrors > geetestErrorsAtStart) {
          return {
            ok: false,
            parsed: null,
            bodyText: "",
            error: `geetest_runtime_error: ${runtimeState.lastGeetestError}`,
            geetestError: true,
          };
        }
        const doc = iframe.contentDocument;
        if (!doc) {
          lastError = "iframe_contentDocument_empty";
          continue;
        }
        const frameHref = String(iframe.contentWindow?.location?.href || doc.location?.href || "");
        if (row.company_id && !frameHref.includes(`cid=${row.company_id}`)) {
          lastError = `waiting_current_cid frame=${frameHref}`;
          continue;
        }
        const bodyText = doc.body ? textOf(doc.body) : "";
        if (row.name && !bodyText.includes(row.name)) {
          lastError = `waiting_current_company_name expected=${row.name}`;
          continue;
        }
        const parsed = extractDomainFromIframeDoc(doc, row.name);
        if (parsed.best) return { ok: true, parsed, bodyText };
        if (/登录|请登录|login/i.test(bodyText) && !/提交漏洞/.test(bodyText)) {
          lastError = "maybe_not_logged_in";
        }
        if (/域名\s*或\s*ip|域名\s*或\s*IP|提交漏洞/.test(bodyText)) {
          lastError = "rendered_but_no_domain";
        }
      } catch (error) {
        lastError = String(error && error.message ? error.message : error);
      }
    }
    return { ok: false, parsed: null, bodyText: "", error: lastError || "timeout" };
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
    const filename = `butian_submit_domains_iframe_${suffix ? suffix + "_" : ""}${stamp}.csv`;
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 3000);
    a.remove();
    console.log(`[butian-iframe-domain] exported ${data.length} rows -> ${filename}`);
  }

  function downloadPartRows(data, fromIndex, suffix = "") {
    if (!data.length) return;
    downloadRows(data, suffix || `part_${fromIndex + 1}_${fromIndex + data.length}`);
  }

  const cached = existingResults();
  if (cached.length) {
    const choice = prompt(`发现 iframe 缓存 ${cached.length} 条：1=直接导出，2=继续/补跑，0=清空重来，9=停止当前任务`, "1");
    if (choice === "1") return downloadRows(cached, "cached");
    if (choice === "9") {
      sessionStorage.setItem(STOP_KEY, "1");
      console.warn("[butian-iframe-domain] stop flag set");
      return;
    }
    if (choice === "0") {
      sessionStorage.removeItem(STORAGE_KEY);
      window[RESULT_GLOBAL_KEY] = [];
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

  const startIndex = Math.max(1, Number(prompt(`从第几条开始？从中断点继续可填下一条序号。例如刚跑到 95，就填 96`, "1") || 1) || 1);
  const maxCount = Math.max(0, Number(prompt(`共 ${csvRows.length} 条，最多处理多少条？0=全部。建议先填 10 测试`, "10") || 10) || 0);
  const delayMs = Math.max(3000, Number(prompt("每个补天提交页间隔毫秒？建议 5000", "5000") || 5000) || 5000);
  const timeoutMs = Math.max(10000, Number(prompt("单页渲染超时毫秒？建议 20000", "20000") || 20000) || 20000);
  const chunkSize = Math.max(5, Number(prompt("每多少条自动下载一个分片 CSV？建议 20，避免浏览器缓存爆掉", "20") || 20) || 20);
  const geetestStopAfter = Math.max(0, Number(prompt("遇到几次 Geetest/风控错误后自动导出并暂停？建议 1；0=不自动停", "1") || 1) || 0);
  const iframeRecycleEvery = Math.max(1, Number(prompt("低内存模式：每多少条重建一次 iframe？建议 10", "10") || 10) || 10);
  const rowsFromStart = csvRows.filter((row) => Number(row.index || 0) >= startIndex);
  const rowsToRun = maxCount ? rowsFromStart.slice(0, maxCount) : rowsFromStart;

  const results = existingResults();
  const done = new Set(results.map((row) => String(row.company_id || "")));
  let lastPartExportAt = results.length;
  let finalDownloaded = false;
  const geetestErrorsAtRunStart = runtimeState.geetestErrors;
  console.log(`[butian-iframe-domain] start rows=${rowsToRun.length} startIndex=${startIndex} delayMs=${delayMs} timeoutMs=${timeoutMs} recycleEvery=${iframeRecycleEvery}`);

  for (const row of rowsToRun) {
    if (sessionStorage.getItem(STOP_KEY) === "1") {
      console.warn("[butian-iframe-domain] stopped by operator");
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
    let shouldStopAfterSave = false;
    try {
      setRunnerStatus(`${row.index}/${csvRows.length} ${row.name} 加载中：${row.submit_url}`);
      const loaded = await loadSubmitPageInIframe(row.submit_url, timeoutMs, row);
      if (loaded.ok) {
        output.domain_or_ip = loaded.parsed.best;
        output.normalized_target_url = normalizedTargetUrl(loaded.parsed.best);
        output.all_candidates = loaded.parsed.all.join("; ");
        output.status = "iframe_domain_found";
      } else {
        output.status = loaded.geetestError ? "iframe_geetest_error" : "iframe_no_domain";
        output.error = loaded.error || "no domain after render";
        if (loaded.geetestError && geetestStopAfter > 0 && runtimeState.geetestErrors - geetestErrorsAtRunStart >= geetestStopAfter) {
          shouldStopAfterSave = true;
        }
      }
    } catch (error) {
      const errorText = String(error && error.message ? error.message : error);
      if (looksLikeGeetestError(errorText)) {
        rememberGeetestError(errorText, "loop:catch");
        output.status = "iframe_geetest_error";
        shouldStopAfterSave = geetestStopAfter > 0 && runtimeState.geetestErrors - geetestErrorsAtRunStart >= geetestStopAfter;
      } else {
        output.status = "iframe_error";
      }
      output.error = errorText.slice(0, 300);
    }
    results.push(output);
    const savedResults = saveResults(results);
    results.length = 0;
    results.push(...savedResults);
    done.add(row.company_id);
    setRunnerStatus(`${output.index}/${csvRows.length} ${output.name} ${output.status} ${output.domain_or_ip || output.error || ""}`);
    console.log(`[butian-iframe-domain] ${output.index}/${csvRows.length} ${output.name} ${output.status} ${output.domain_or_ip || output.error || ""}`);
    if (shouldStopAfterSave) {
      const part = results.slice(lastPartExportAt);
      if (part.length) downloadPartRows(part, lastPartExportAt, `part_${lastPartExportAt + 1}_${results.length}_geetest_pause`);
      lastPartExportAt = results.length;
      downloadRows(saveResults(results), "geetest_pause");
      finalDownloaded = true;
      setRunnerStatus(`已因 Geetest/风控错误自动暂停：已导出 ${results.length} 条；建议稍等后从第 ${Number(output.index || 0) + 1} 条继续`);
      console.warn(`[butian-iframe-domain] Geetest/风控错误达到阈值，已自动导出并暂停。下次可从第 ${Number(output.index || 0) + 1} 条继续。`);
      break;
    }
    if (chunkSize > 0 && results.length - lastPartExportAt >= chunkSize) {
      downloadPartRows(results.slice(lastPartExportAt), lastPartExportAt);
      lastPartExportAt = results.length;
    }
    if (iframeRecycleEvery > 0 && results.length % iframeRecycleEvery === 0) {
      await recycleRunnerIframe(`processed_${results.length}`);
    } else {
      try {
        const iframe = document.getElementById("__butian_submit_domain_iframe__");
        if (iframe) iframe.src = "about:blank";
      } catch (_) {
        // best-effort cleanup
      }
    }
    await sleep(delayMs);
  }

  if (results.length > lastPartExportAt) {
    downloadPartRows(results.slice(lastPartExportAt), lastPartExportAt, `part_${lastPartExportAt + 1}_${results.length}_final`);
  }
  if (!finalDownloaded) downloadRows(saveResults(results), "captured");
})();
