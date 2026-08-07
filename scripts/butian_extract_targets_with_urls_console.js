// Paste this into the browser DevTools Console on https://www.butian.net/Reward/plan/...
// Version 6: collect vendor names, then click each row's "提交漏洞" entry to extract main/scope URLs
// from the Butian detail/submission page. It never clicks the final form-submit button.
// It uses the current browser session only. It does not export cookies, tokens, localStorage, or sessionStorage.
//
// Output CSV columns:
// page,name,detail_href,main_urls,scope_urls,all_detail_urls,detail_status,source

(async () => {
  const STORAGE_KEY = "__butian_target_url_export_v6__";
  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const currentOrigin = location.origin;
  const listSource = location.href;
  const denyHost = /(^|\.)((butian\.net)|(aliyuncs\.com)|(qpic\.cn)|(qq\.com)|(weixin\.qq\.com)|(mp\.weixin\.qq\.com)|(baidu\.com)|(bdstatic\.com)|(cnzz\.com))$/i;
  const denyPath = /\.(?:png|jpg|jpeg|gif|svg|webp|ico|css|js|woff2?|ttf|map)(?:[?#]|$)/i;

  const cached = sessionStorage.getItem(STORAGE_KEY);
  if (cached) {
    const choice = prompt("发现 v6 缓存：输入 1 直接导出缓存，输入 2 继续追加，输入 0 清空重来", "1");
    if (choice === "1") {
      const cacheRows = JSON.parse(cached || "[]");
      return downloadRows(cacheRows, "cached");
    }
    if (choice === "0") {
      sessionStorage.removeItem(STORAGE_KEY);
    }
  }

  const maxPagesInput = prompt("最多自动翻多少页？", "200");
  const maxPages = Math.max(1, Number(maxPagesInput || 200) || 200);
  const detailModeInput = prompt("是否抓详情页主URL？1=抓取详情，0=只导名单", "1");
  const detailMode = detailModeInput !== "0";
  const clickModeInput = prompt("没有详情href时，是否自动点击该行“提交漏洞”入口读取主URL？1=点击，0=跳过", "1");
  const clickMode = clickModeInput !== "0";
  const delayMs = 900;
  const detailDelayMs = 700;
  const rows = new Map();
  if (cached && sessionStorage.getItem(STORAGE_KEY)) {
    for (const row of JSON.parse(cached || "[]")) {
      rows.set(`${row.name}||${row.detail_href || ""}`, row);
    }
  }

  const networkTexts = [];
  function installNetworkSniffer() {
    if (window.__butianV5SnifferInstalled) return;
    window.__butianV5SnifferInstalled = true;
    const originalFetch = window.fetch;
    window.fetch = async (...args) => {
      const response = await originalFetch(...args);
      try {
        const url = String(args[0]?.url || args[0] || "");
        const clone = response.clone();
        const contentType = clone.headers.get("content-type") || "";
        if (/json|text|html/i.test(contentType)) {
          clone.text().then((text) => {
            if (text && text.length < 2_000_000) networkTexts.push({ url, text: text.slice(0, 2_000_000), at: Date.now() });
            if (networkTexts.length > 80) networkTexts.splice(0, networkTexts.length - 80);
          }).catch(() => {});
        }
      } catch (_) {}
      return response;
    };

    const originalOpen = XMLHttpRequest.prototype.open;
    const originalSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function(method, url, ...rest) {
      this.__butianV5Url = String(url || "");
      return originalOpen.call(this, method, url, ...rest);
    };
    XMLHttpRequest.prototype.send = function(...args) {
      this.addEventListener("load", () => {
        try {
          const contentType = this.getResponseHeader("content-type") || "";
          if (/json|text|html/i.test(contentType) && typeof this.responseText === "string" && this.responseText.length < 2_000_000) {
            networkTexts.push({ url: this.__butianV5Url || "", text: this.responseText.slice(0, 2_000_000), at: Date.now() });
            if (networkTexts.length > 80) networkTexts.splice(0, networkTexts.length - 80);
          }
        } catch (_) {}
      });
      return originalSend.apply(this, args);
    };
  }

  if (detailMode && clickMode) installNetworkSniffer();

  function textOf(el) {
    return (el?.innerText || el?.textContent || "").replace(/\s+/g, " ").trim();
  }

  function isVisible(el) {
    if (!el || !(el instanceof Element)) return false;
    const rect = el.getBoundingClientRect();
    const style = getComputedStyle(el);
    return rect.width > 0 && rect.height > 0 && style.display !== "none" && style.visibility !== "hidden";
  }

  function keyword() {
    const inputs = [...document.querySelectorAll("input")].filter(isVisible);
    const candidate = inputs.find((input) => (input.value || "").trim());
    return (candidate?.value || "butian").trim();
  }

  function saveProgress() {
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify([...rows.values()]));
  }

  function downloadRows(data, suffix = "") {
    const headers = ["page", "name", "detail_href", "main_urls", "scope_urls", "all_detail_urls", "detail_status", "source"];
    const csvEscape = (value) => `"${String(value ?? "").replaceAll('"', '""')}"`;
    const csv = "\ufeff" + [
      headers.join(","),
      ...data.map((row) => headers.map((key) => csvEscape(row[key])).join(",")),
    ].join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    const a = document.createElement("a");
    const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
    a.href = URL.createObjectURL(blob);
    a.download = `butian_targets_with_urls_${keyword() || "export"}${suffix ? "_" + suffix : ""}_${stamp}.csv`;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 3000);
    a.remove();
    console.table(data);
    console.log(`done: exported ${data.length} targets with detail urls`);
  }

  function looksLikeTargetName(value) {
    const text = String(value || "").trim();
    if (text.length < 2 || text.length > 80) return false;
    if (!/[\u4e00-\u9fa5]/.test(text)) return false;
    if (/提交漏洞|补天|奖励|标准|帮助|公告|排行|登录|注册|搜索|更多详情|退出系统|项目大厅|综合排序|厂商信息|操作|公益SRC|事件漏洞|通用漏洞/.test(text)) return false;
    return /(职业技术学院|职业学院|科技学院|学院|大学|学校|医院|公司|集团|银行|政府|政务|中心|职业|科技|教育|航空|金融|证券|保险|局|厅|院|商城|平台|系统)$/.test(text);
  }

  function extractTargetNamesFromText(value) {
    const text = String(value || "")
      .replace(/\s+/g, " ")
      .replace(/提交漏洞/g, " ")
      .replace(/厂商信息|操作|公益SRC/g, " ");
    const pattern = /([\u4e00-\u9fa5A-Za-z0-9（）()·\-]{2,60}(?:职业技术学院|职业学院|科技学院|学院|大学|学校|医院|公司|集团|银行|政府|政务中心|数据中心|研究院|科学院|交易所|商城|平台|系统))/g;
    const out = [];
    let match;
    while ((match = pattern.exec(text)) !== null) {
      let name = match[1].replace(/^[^\u4e00-\u9fa5A-Za-z0-9]+|[^\u4e00-\u9fa5A-Za-z0-9）)]＋?$/g, "").trim();
      name = name.replace(/^(公益SRC|厂商信息|操作)+/, "").trim();
      if (looksLikeTargetName(name) && !out.includes(name)) out.push(name);
    }
    return out;
  }

  function absoluteUrl(value) {
    if (!value) return "";
    try {
      return new URL(value, location.href).href;
    } catch (_) {
      return "";
    }
  }

  function normalizeExternalUrl(value) {
    let raw = String(value || "")
      .replace(/^["'“”‘’<>\s]+|["'“”‘’<>\s，。；;、)）\]]+$/g, "")
      .trim();
    if (!raw) return "";
    if (/^www\./i.test(raw)) raw = `https://${raw}`;
    try {
      const url = new URL(raw);
      if (!/^https?:$/i.test(url.protocol)) return "";
      if (denyHost.test(url.hostname)) return "";
      if (denyPath.test(url.pathname)) return "";
      url.hash = "";
      return url.href;
    } catch (_) {
      return "";
    }
  }

  function extractUrlsFromText(rawText) {
    const text = String(rawText || "")
      .replace(/\\\//g, "/")
      .replace(/&amp;/g, "&")
      .replace(/[\u200b-\u200f]/g, "");
    const urls = new Set();
    const urlPattern = /((?:https?:\/\/|www\.)[A-Za-z0-9.-]+(?::\d+)?(?:\/[^\s"'<>，。；;、]*)?)/g;
    let match;
    while ((match = urlPattern.exec(text)) !== null) {
      const url = normalizeExternalUrl(match[1]);
      if (url) urls.add(url);
    }
    return [...urls];
  }

  function extractLabelUrls(rawText) {
    const text = String(rawText || "").replace(/\s+/g, " ");
    const labelPattern = /(主\s*URL|主站|官网|官方网站|厂商\s*URL|漏洞范围|测试范围|可测范围|资产范围|域名|URL)[：:\s]{0,8}((?:https?:\/\/|www\.)[A-Za-z0-9.-]+(?::\d+)?(?:\/[^\s"'<>，。；;、]*)?)/gi;
    const urls = new Set();
    let match;
    while ((match = labelPattern.exec(text)) !== null) {
      const url = normalizeExternalUrl(match[2]);
      if (url) urls.add(url);
    }
    return [...urls];
  }

  function classifyDetailUrls(rawText) {
    const all = extractUrlsFromText(rawText);
    const labelUrls = extractLabelUrls(rawText);
    const scopeUrls = new Set(labelUrls);
    const mainUrls = new Set(labelUrls);
    const text = String(rawText || "");
    for (const url of all) {
      const idx = text.indexOf(url.replace(/^https?:\/\//, ""));
      const nearby = idx >= 0 ? text.slice(Math.max(0, idx - 80), Math.min(text.length, idx + 140)) : "";
      if (/主\s*URL|主站|官网|官方网站|厂商\s*URL/i.test(nearby)) mainUrls.add(url);
      if (/漏洞范围|测试范围|可测范围|资产范围|域名|URL/i.test(nearby)) scopeUrls.add(url);
    }
    if (!mainUrls.size && all.length === 1) mainUrls.add(all[0]);
    return {
      main_urls: [...mainUrls].join(";"),
      scope_urls: [...scopeUrls].join(";"),
      all_detail_urls: all.join(";"),
    };
  }

  function rowContainerForSubmitButton(button) {
    let node = button;
    for (let depth = 0; depth < 10 && node; depth += 1, node = node.parentElement) {
      const rowText = textOf(node);
      const names = extractTargetNamesFromText(rowText);
      if (names.length && rowText.includes("提交漏洞") && rowText.length < 900) return { node, names, submitButton: button };
    }
    return null;
  }

  function findDetailHref(rowNode, name) {
    const links = [...rowNode.querySelectorAll("a")];
    const preferred = links.find((a) => textOf(a).includes(name) && a.href && !/javascript:/i.test(a.href));
    if (preferred) return preferred.href;
    const rewardLinks = links
      .map((a) => a.href || absoluteUrl(a.getAttribute("href") || ""))
      .filter(Boolean)
      .filter((href) => /\/Reward\/|\/reward\/|\/src\/|\/company\/|\/Enterprise\//i.test(href));
    return rewardLinks[0] || "";
  }

  function findNameClickTarget(rowNode, name) {
    const exact = [...rowNode.querySelectorAll("a,button,span,div")]
      .filter(isVisible)
      .find((el) => textOf(el) === name || textOf(el).includes(name));
    return exact || null;
  }

  function collectFromSubmitRows(pageIndex) {
    let count = 0;
    const submitButtons = [...document.querySelectorAll("button,a,span,div")]
      .filter(isVisible)
      .filter((el) => textOf(el) === "提交漏洞");
    for (const button of submitButtons) {
      const found = rowContainerForSubmitButton(button);
      if (!found) continue;
      const name = found.names[0];
      if (!looksLikeTargetName(name)) continue;
      const detailHref = findDetailHref(found.node, name);
      const key = `${name}||${detailHref}`;
      if (!rows.has(key)) {
        rows.set(key, {
          page: pageIndex,
          name,
          detail_href: detailHref,
          main_urls: "",
          scope_urls: "",
          all_detail_urls: "",
          detail_status: detailHref ? "pending_fetch" : "pending_submit_click",
          source: listSource,
        });
        count += 1;
      }
    }
    return count;
  }

  function collectFallbackLinks(pageIndex) {
    let count = 0;
    for (const el of [...document.querySelectorAll("a,span,div,p,td")].filter(isVisible)) {
      const names = extractTargetNamesFromText(textOf(el));
      for (const name of names) {
        const detailHref = el instanceof HTMLAnchorElement ? el.href : "";
        const key = `${name}||${detailHref}`;
        if (!rows.has(key)) {
          rows.set(key, {
            page: pageIndex,
            name,
            detail_href: detailHref,
            main_urls: "",
            scope_urls: "",
            all_detail_urls: "",
            detail_status: detailHref ? "pending_fetch" : "pending_submit_click",
            source: listSource,
          });
          count += 1;
        }
      }
    }
    return count;
  }

  function collectPage(pageIndex) {
    const primary = collectFromSubmitRows(pageIndex);
    const fallback = primary ? 0 : collectFallbackLinks(pageIndex);
    saveProgress();
    console.log(`page=${pageIndex} collected=${primary + fallback} total=${rows.size}`);
  }

  function pageNames() {
    const names = [
      ...[...document.querySelectorAll("button,a,span,div,p,td")]
        .filter(isVisible)
        .flatMap((el) => extractTargetNamesFromText(textOf(el))),
    ];
    return [...new Set(names)].sort();
  }

  function pageSignature() {
    const names = pageNames().join("|");
    const activePage = [...document.querySelectorAll(".active,[aria-current='page'],li,button,a")]
      .filter(isVisible)
      .map(textOf)
      .filter((value) => /^\d+$/.test(value))
      .slice(-3)
      .join(",");
    return `${activePage}::${names}`;
  }

  function disabled(el) {
    const text = [
      el.className || "",
      el.getAttribute("aria-disabled") || "",
      el.getAttribute("disabled") || "",
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
    const pathMatch = location.pathname.match(/\/Reward\/plan\/(\d+)/i);
    return pathMatch ? Number(pathMatch[1]) : 1;
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
        el.getAttribute("aria-label") || "",
        el.getAttribute("title") || "",
        String(el.className || ""),
      ].join(" ");
      return /下一页|next|btn-next|pagination-next|›|»|>/.test(value);
    }) || null;
    return found ? clickTarget(found) : null;
  }

  function findNextPageNumberButton() {
    const current = activePageNumber();
    const nextNumber = current + 1;
    const candidates = [...document.querySelectorAll("button,a,li,span")]
      .filter(isVisible)
      .filter((el) => !disabled(el))
      .filter((el) => numericPageOf(el) === nextNumber);
    return candidates[0] ? clickTarget(candidates[0]) : null;
  }

  async function waitForPageChange(before, beforeUrl = location.href) {
    for (let i = 0; i < 60; i += 1) {
      await sleep(400);
      if (location.href !== beforeUrl || pageSignature() !== before) {
        await sleep(800);
        return true;
      }
    }
    return false;
  }

  async function clickNextWithoutReload() {
    const before = pageSignature();
    const beforeUrl = location.href;
    let next = findNextButton();
    let mode = "next_button";
    if (!next) {
      next = findNextPageNumberButton();
      mode = "next_number";
    }
    if (next) {
      console.log(`turn_page mode=${mode} active=${activePageNumber()} target_text=${textOf(next) || next.className || ""}`);
      next.scrollIntoView({ block: "center", inline: "center" });
      await sleep(200);
      next.click();
      if (await waitForPageChange(before, beforeUrl)) return true;
      console.log(`${mode} did not change page; stop and export collected rows`);
    }
    return false;
  }

  async function fetchDetail(row) {
    if (!row.detail_href) return row;
    try {
      const resp = await fetch(row.detail_href, { credentials: "include" });
      const text = await resp.text();
      const urls = classifyDetailUrls(text);
      row.main_urls = urls.main_urls;
      row.scope_urls = urls.scope_urls;
      row.all_detail_urls = urls.all_detail_urls;
      row.detail_status = `fetch_${resp.status}_${row.all_detail_urls ? "urls_found" : "no_url"}`;
    } catch (error) {
      row.detail_status = `fetch_error_${String(error).slice(0, 120)}`;
    }
    return row;
  }

  function findCurrentRowForName(name) {
    const submitButtons = [...document.querySelectorAll("button,a,span,div")]
      .filter(isVisible)
      .filter((el) => textOf(el) === "提交漏洞");
    for (const button of submitButtons) {
      const found = rowContainerForSubmitButton(button);
      if (found?.names?.[0] === name) return found;
    }
    return null;
  }

  async function tryClickDetailForName(row) {
    if (row.main_urls || row.all_detail_urls || !clickMode) return row;
    const foundRow = findCurrentRowForName(row.name);
    const target = foundRow?.submitButton || null;
    if (!target) {
      row.detail_status = row.detail_status || "submit_click_target_not_found";
      return row;
    }
    const beforeUrl = location.href;
    const beforeText = document.body.innerText;
    const beforeNetworkCount = networkTexts.length;
    target.scrollIntoView({ block: "center", inline: "center" });
    await sleep(150);
    target.click();
    await sleep(Math.max(detailDelayMs, 1200));
    const recentNetwork = networkTexts.slice(beforeNetworkCount).map((x) => x.text).join("\n");
    const afterText = document.body.innerText;
    const combined = `${recentNetwork}\n${afterText}`;
    const urls = classifyDetailUrls(combined);
    row.main_urls = urls.main_urls;
    row.scope_urls = urls.scope_urls;
    row.all_detail_urls = urls.all_detail_urls;
    row.detail_href = row.detail_href || (location.href !== beforeUrl ? location.href : "");
    row.detail_status = row.all_detail_urls ? "submit_click_urls_found" : "submit_click_no_url";
    const close = [...document.querySelectorAll("button,a,span,i")]
      .filter(isVisible)
      .find((el) => /关闭|返回|×|取消|back/i.test(textOf(el) || el.getAttribute("aria-label") || el.className || ""));
    if (location.href !== beforeUrl) {
      history.back();
      await sleep(900);
    } else if (close && document.body.innerText !== beforeText) {
      close.click();
      await sleep(300);
    }
    return row;
  }

  async function enrichVisiblePageDetails() {
    if (!detailMode) return;
    const data = [...rows.values()].filter((row) => !row.all_detail_urls && !/^fetch_\d+_urls_found|click_urls_found|submit_click_urls_found/.test(row.detail_status || ""));
    for (const row of data) {
      if (row.detail_href) {
        await fetchDetail(row);
      }
      if (!row.all_detail_urls && clickMode) {
        await tryClickDetailForName(row);
      }
      rows.set(`${row.name}||${row.detail_href || ""}`, row);
      saveProgress();
      console.log(`detail name=${row.name} status=${row.detail_status} urls=${row.all_detail_urls || ""}`);
      await sleep(250);
    }
  }

  let pageIndex = 1;
  for (; pageIndex <= maxPages; pageIndex += 1) {
    await sleep(300);
    collectPage(pageIndex);
    await enrichVisiblePageDetails();
    window.scrollTo(0, document.body.scrollHeight);
    await sleep(250);
    const changed = await clickNextWithoutReload();
    if (!changed) {
      console.log("page did not change after all paging methods; stop");
      break;
    }
    await sleep(delayMs);
  }

  const data = [...rows.values()];
  downloadRows(data);
  sessionStorage.removeItem(STORAGE_KEY);
})();
