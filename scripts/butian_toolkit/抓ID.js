// Paste into Butian Reward list page console.
// Purpose: capture company_id/company_name from Butian list API responses.
// It does NOT open submit pages and does NOT submit anything.
//
// Usage:
// 1) Paste this script on https://www.butian.net/Reward/plan/...
// 2) Default behavior is automatic: install capture hook, turn pages slowly, then export.
// 3) It only clicks pagination next / next page number; it never clicks "提交漏洞".
// 4) Optional before paste: window.__BUTIAN_COMPANY_CAPTURE_CONFIG__ = { action: "ask", maxPages: 50, delayMs: 8000 }
//
// Output CSV: page,current,name,company_id,submit_url,api_url,captured_at

(async () => {
  const STORAGE_KEY = "__butian_company_api_capture_v1__";
  const HOOK_KEY = "__butian_company_api_hook_v1__";
  const STOP_KEY = "__butian_company_api_capture_stop_v1__";
  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const CONFIG = {
    action: "auto", // auto | ask | hook | export | clear | stop
    maxPages: 200,
    delayMs: 5000,
    minDelayMs: 3000,
    clickDelayMs: 250,
    waitPollMs: 300,
    waitAfterChangeMs: 900,
    waitChangeLoops: 60,
    ...window.__BUTIAN_COMPANY_CAPTURE_CONFIG__,
  };

  function existingRows() {
    try {
      return JSON.parse(sessionStorage.getItem(STORAGE_KEY) || "[]");
    } catch (_) {
      return [];
    }
  }

  function saveRows(rows) {
    const dedup = new Map();
    for (const row of rows) {
      const key = `${row.company_id || ""}||${row.name || ""}`;
      if (!dedup.has(key)) dedup.set(key, row);
    }
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify([...dedup.values()]));
    return [...dedup.values()];
  }

  function normalizeApiUrl(url) {
    try {
      return new URL(String(url || ""), location.href).href;
    } catch (_) {
      return String(url || "");
    }
  }

  function collectFromJson(json, apiUrl) {
    const now = new Date().toISOString();
    const rows = existingRows();
    const containers = [];
    if (Array.isArray(json?.data?.list)) containers.push(json.data);
    if (Array.isArray(json?.list)) containers.push(json);
    if (Array.isArray(json?.data)) containers.push({ list: json.data });

    let added = 0;
    for (const container of containers) {
      const current = container.current ?? container.page ?? container.pageNo ?? "";
      const count = container.count ?? container.total ?? "";
      for (const item of container.list || []) {
        const companyId = String(item.company_id ?? item.cid ?? item.id ?? item.companyId ?? "").trim();
        const name = String(item.company_name ?? item.name ?? item.companyName ?? "").trim();
        if (!companyId || !name) continue;
        rows.push({
          page: count,
          current,
          name,
          company_id: companyId,
          submit_url: new URL(`/Loo/submit?cid=${companyId}`, location.origin).href,
          api_url: apiUrl,
          captured_at: now,
        });
        added += 1;
      }
    }
    if (added) {
      const saved = saveRows(rows);
      console.log(`[butian-capture] added=${added} total=${saved.length} from=${apiUrl}`);
    }
    return added;
  }

  function tryCollectText(text, apiUrl) {
    if (!text || !/(company_id|company_name|companyId|companyName)/.test(text)) return 0;
    try {
      return collectFromJson(JSON.parse(text), apiUrl);
    } catch (_) {
      return 0;
    }
  }

  function installHook() {
    if (window[HOOK_KEY]) {
      console.log("[butian-capture] hook already installed");
      return;
    }
    window[HOOK_KEY] = true;

    const originalFetch = window.fetch;
    window.fetch = async (...args) => {
      const response = await originalFetch(...args);
      try {
        const apiUrl = normalizeApiUrl(args[0]?.url || args[0] || "");
        const clone = response.clone();
        const type = clone.headers.get("content-type") || "";
        if (/json|text/i.test(type)) {
          clone.text().then((text) => tryCollectText(text, apiUrl)).catch(() => {});
        }
      } catch (_) {}
      return response;
    };

    const originalOpen = XMLHttpRequest.prototype.open;
    const originalSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function(method, url, ...rest) {
      this.__butianCaptureUrl = normalizeApiUrl(url);
      return originalOpen.call(this, method, url, ...rest);
    };
    XMLHttpRequest.prototype.send = function(...args) {
      this.addEventListener("load", () => {
        try {
          tryCollectText(this.responseText || "", this.__butianCaptureUrl || "");
        } catch (_) {}
      });
      return originalSend.apply(this, args);
    };
    console.log("[butian-capture] hook installed. Turn pages to capture API responses.");
  }

  function textOf(el) {
    return (el?.innerText || el?.textContent || "").replace(/\s+/g, " ").trim();
  }

  function isVisible(el) {
    if (!el || !(el instanceof Element)) return false;
    const rect = el.getBoundingClientRect();
    const style = getComputedStyle(el);
    return rect.width > 0 && rect.height > 0 && style.display !== "none" && style.visibility !== "hidden";
  }

  function disabled(el) {
    const text = [
      el.className || "",
      el.getAttribute?.("aria-disabled") || "",
      el.getAttribute?.("disabled") || "",
    ].join(" ");
    return /disabled|true|不可用|禁用/.test(text) || el.disabled;
  }

  function numericPageOf(el) {
    const value = textOf(el);
    return /^\d+$/.test(value) ? Number(value) : 0;
  }

  function activePageNumber() {
    const activeCandidates = [...document.querySelectorAll(".active,[aria-current='page'],.current,.cur,.on,.selected,.ant-pagination-item-active,.el-pager .active")]
      .filter(isVisible)
      .map(numericPageOf)
      .filter(Boolean);
    if (activeCandidates.length) return activeCandidates[activeCandidates.length - 1];
    return 0;
  }

  function pageSignature() {
    const visibleText = [...document.querySelectorAll("button,a,span,div,p,td")]
      .filter(isVisible)
      .map(textOf)
      .filter(Boolean)
      .slice(0, 120)
      .join("|");
    return `${location.href}::${activePageNumber()}::${visibleText}`;
  }

  function clickTarget(el) {
    return el.querySelector?.("button:not([disabled]),a") || el;
  }

  function findNextButton() {
    const selectors = [
      ".btn-next",
      ".ant-pagination-next",
      ".el-pagination .btn-next",
      "[aria-label='下一页']",
      "[title='下一页']",
      "button",
      "a",
      "li",
    ];
    const candidates = [...new Set(selectors.flatMap((selector) => [...document.querySelectorAll(selector)]))]
      .filter(isVisible)
      .filter((el) => !disabled(el));
    const found = candidates.find((el) => {
      const value = [
        textOf(el),
        el.getAttribute?.("aria-label") || "",
        el.getAttribute?.("title") || "",
        String(el.className || ""),
      ].join(" ");
      return /下一页|next|btn-next|pagination-next|›|»|>/.test(value);
    }) || null;
    return found ? clickTarget(found) : null;
  }

  function findNextPageNumberButton() {
    const current = activePageNumber();
    if (!current) return null;
    const candidates = [...document.querySelectorAll("button,a,li,span")]
      .filter(isVisible)
      .filter((el) => !disabled(el))
      .filter((el) => numericPageOf(el) === current + 1);
    return candidates[0] ? clickTarget(candidates[0]) : null;
  }

  async function waitForPageChange(before) {
    for (let i = 0; i < Math.max(10, Number(CONFIG.waitChangeLoops) || 60); i += 1) {
      await sleep(Math.max(200, Number(CONFIG.waitPollMs) || 300));
      if (pageSignature() !== before) {
        await sleep(Math.max(500, Number(CONFIG.waitAfterChangeMs) || 900));
        return true;
      }
    }
    return false;
  }

  async function clickNextPageOnly() {
    const before = pageSignature();
    let next = findNextButton();
    let mode = "next_button";
    if (!next) {
      next = findNextPageNumberButton();
      mode = "next_number";
    }
    if (!next) {
      console.log("[butian-capture] no next page button found");
      return false;
    }
    const nextText = textOf(next);
    if (/提交漏洞/.test(nextText)) {
      console.warn("[butian-capture] refused to click submit button");
      return false;
    }
    console.log(`[butian-capture] turn page via ${mode}; current=${activePageNumber() || "unknown"}; target=${nextText || next.className || ""}`);
    next.scrollIntoView({ block: "center", inline: "center" });
    await sleep(Math.max(150, Number(CONFIG.clickDelayMs) || 250));
    next.click();
    return await waitForPageChange(before);
  }

  async function autoTurnPages(options = {}) {
    sessionStorage.removeItem(STOP_KEY);
    const maxPages = Math.max(1, Number(options.maxPages ?? CONFIG.maxPages ?? 200) || 200);
    const delayMs = Math.max(
      Math.max(3000, Number(CONFIG.minDelayMs) || 3000),
      Number(options.delayMs ?? CONFIG.delayMs ?? 5000) || 5000,
    );
    console.log(`[butian-capture] auto paging start maxPages=${maxPages} delayMs=${delayMs}`);
    for (let i = 1; i <= maxPages; i += 1) {
      if (sessionStorage.getItem(STOP_KEY) === "1") {
        console.warn("[butian-capture] stopped by operator");
        break;
      }
      const beforeTotal = existingRows().length;
      const changed = await clickNextPageOnly();
      await sleep(delayMs);
      const afterTotal = existingRows().length;
      console.log(`[butian-capture] step=${i} changed=${changed} total=${afterTotal} added=${afterTotal - beforeTotal}`);
      if (!changed) break;
    }
    downloadRows(existingRows(), "captured");
  }

  function downloadRows(data, suffix = "") {
    const headers = ["page", "current", "name", "company_id", "submit_url", "api_url", "captured_at"];
    const csvEscape = (value) => `"${String(value ?? "").replaceAll('"', '""')}"`;
    const csv = "\ufeff" + [
      headers.join(","),
      ...data.map((row) => headers.map((key) => csvEscape(row[key])).join(",")),
    ].join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    const a = document.createElement("a");
    const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
    a.href = URL.createObjectURL(blob);
    a.download = `butian_company_ids_${suffix ? suffix + "_" : ""}${stamp}.csv`;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 3000);
    a.remove();
    console.log(`[butian-capture] exported ${data.length} rows`);
  }

  window.__butianCompanyCaptureStop = () => {
    sessionStorage.setItem(STOP_KEY, "1");
    console.warn("[butian-capture] stop flag set");
  };
  window.__butianCompanyCaptureExport = () => downloadRows(existingRows(), "manual");
  window.__butianCompanyCaptureClear = () => {
    sessionStorage.removeItem(STORAGE_KEY);
    window[HOOK_KEY] = false;
    console.log("[butian-capture] cache cleared");
  };

  let action = String(CONFIG.action || "auto").toLowerCase();
  if (action === "ask") {
    const mode = prompt(
      "选择：1=只安装接口捕获；2=导出已捕获；3=清空缓存；4=低速自动翻页；9=停止自动翻页",
      "4",
    );
    action = ({ "1": "hook", "2": "export", "3": "clear", "4": "auto", "9": "stop" }[mode] || "auto");
  }
  if (action === "9") action = "stop";
  if (action === "3") action = "clear";
  if (action === "2") action = "export";
  if (action === "1") action = "hook";

  if (action === "stop") {
    window.__butianCompanyCaptureStop();
    return;
  }
  if (action === "clear") {
    window.__butianCompanyCaptureClear();
    return;
  }
  if (action === "export") {
    return downloadRows(existingRows(), "captured");
  }
  installHook();
  if (action === "auto" || action === "4" || !action) {
    await autoTurnPages();
  }
})();
