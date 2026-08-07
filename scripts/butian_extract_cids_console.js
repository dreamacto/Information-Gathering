// Paste into the browser DevTools Console on a Butian Reward plan list page.
// Purpose: extract cid mappings only, without opening submit/detail pages.
// It does not read cookies, tokens, localStorage, or sessionStorage except for its own progress cache.
//
// Output CSV columns:
// page,name,cid,submit_url,source,extract_method,row_text_sample

(async () => {
  const STORAGE_KEY = "__butian_cid_export_v1__";
  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const rows = new Map();

  const cached = sessionStorage.getItem(STORAGE_KEY);
  if (cached) {
    const choice = prompt("发现 cid 提取缓存：输入 1 直接导出缓存，输入 2 继续追加，输入 0 清空重来", "1");
    if (choice === "1") {
      return downloadRows(JSON.parse(cached || "[]"), "cached");
    }
    if (choice === "0") sessionStorage.removeItem(STORAGE_KEY);
    if (choice === "2") {
      for (const row of JSON.parse(cached || "[]")) rows.set(`${row.name}||${row.cid}`, row);
    }
  }

  const mode = prompt("提取范围：1=只提取当前页，2=低速自动翻列表页提取全部 cid（不打开详情页）", "1");
  const maxPagesInput = mode === "2" ? prompt("最多自动翻多少页？", "200") : "1";
  const maxPages = Math.max(1, Number(maxPagesInput || 1) || 1);
  const pageDelayInput = mode === "2" ? prompt("每次翻页后等待多少毫秒？建议 2500-5000", "3000") : "0";
  const pageDelayMs = Math.max(0, Number(pageDelayInput || 0) || 0);

  function textOf(el) {
    return (el?.innerText || el?.textContent || "").replace(/\s+/g, " ").trim();
  }

  function isVisible(el) {
    if (!el || !(el instanceof Element)) return false;
    const rect = el.getBoundingClientRect();
    const style = getComputedStyle(el);
    return rect.width > 0 && rect.height > 0 && style.display !== "none" && style.visibility !== "hidden";
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

  function cidFromText(value) {
    const text = String(value || "");
    const patterns = [
      /\/Loo\/submit\?cid=(\d+)/i,
      /[?&]cid=(\d+)/i,
      /["']cid["']\s*[:=]\s*["']?(\d+)/i,
      /\bcid\s*[:=]\s*["']?(\d+)/i,
      /company[_-]?id["']?\s*[:=]\s*["']?(\d+)/i,
      /companyId["']?\s*[:=]\s*["']?(\d+)/i,
      /vendor[_-]?id["']?\s*[:=]\s*["']?(\d+)/i,
    ];
    for (const pattern of patterns) {
      const match = text.match(pattern);
      if (match?.[1]) return { cid: match[1], method: `regex:${pattern}` };
    }
    return { cid: "", method: "" };
  }

  function attrText(el) {
    if (!el || !(el instanceof Element)) return "";
    const parts = [];
    for (const attr of [...el.attributes]) {
      parts.push(`${attr.name}=${attr.value}`);
    }
    try {
      parts.push(JSON.stringify(el.dataset || {}));
    } catch (_) {}
    return parts.join(" ");
  }

  function cidFromElementAndRelatives(el, rowNode) {
    const candidates = [];
    const related = [
      el,
      el?.closest?.("a"),
      el?.closest?.("button"),
      rowNode,
      ...[...(rowNode?.querySelectorAll?.("a,button,[href],[onclick],[data-cid],[data-id],[data-company-id]") || [])],
    ].filter(Boolean);

    for (const node of related) {
      candidates.push(node.href || "");
      candidates.push(node.getAttribute?.("href") || "");
      candidates.push(node.getAttribute?.("onclick") || "");
      candidates.push(attrText(node));
      candidates.push(node.outerHTML || "");
    }

    if (typeof getEventListeners === "function") {
      for (const node of related.slice(0, 8)) {
        try {
          const listeners = getEventListeners(node);
          candidates.push(JSON.stringify(listeners || {}));
        } catch (_) {}
      }
    }

    for (const candidate of candidates) {
      const found = cidFromText(candidate);
      if (found.cid) return found;
    }
    return { cid: "", method: "" };
  }

  function rowContainerForSubmitButton(button) {
    let node = button;
    for (let depth = 0; depth < 12 && node; depth += 1, node = node.parentElement) {
      const rowText = textOf(node);
      const names = extractTargetNamesFromText(rowText);
      if (names.length && rowText.includes("提交漏洞") && rowText.length < 1200) return { node, names, submitButton: button };
    }
    return null;
  }

  function submitControls() {
    const controls = [...document.querySelectorAll("a,button,span,div")]
      .filter(isVisible)
      .filter((el) => textOf(el) === "提交漏洞" || /\/Loo\/submit\?cid=/i.test(el.href || el.getAttribute?.("href") || el.outerHTML || ""));
    return [...new Set(controls)];
  }

  function pageNumberFallback(pageIndex) {
    const activeCandidates = [...document.querySelectorAll(".active,[aria-current='page'],.current,.cur,.on,.selected,.ant-pagination-item-active,.el-pager .active")]
      .filter(isVisible)
      .map((el) => textOf(el))
      .filter((value) => /^\d+$/.test(value));
    return activeCandidates.length ? Number(activeCandidates[activeCandidates.length - 1]) : pageIndex;
  }

  function collectPage(pageIndex) {
    const page = pageNumberFallback(pageIndex);
    let count = 0;
    for (const control of submitControls()) {
      const found = rowContainerForSubmitButton(control);
      if (!found) continue;
      const name = found.names[0];
      const cidResult = cidFromElementAndRelatives(control, found.node);
      const cid = cidResult.cid;
      const submitUrl = cid ? absoluteUrl(`/Loo/submit?cid=${cid}`) : "";
      const key = `${name}||${cid || textOf(found.node).slice(0, 80)}`;
      if (!rows.has(key)) {
        rows.set(key, {
          page,
          name,
          cid,
          submit_url: submitUrl,
          source: location.href,
          extract_method: cidResult.method || "cid_not_found_in_dom",
          row_text_sample: textOf(found.node).slice(0, 240),
        });
        count += 1;
      }
    }
    saveProgress();
    console.log(`page=${page} cid_rows_added=${count} total=${rows.size}`);
    return count;
  }

  function saveProgress() {
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify([...rows.values()]));
  }

  function downloadRows(data, suffix = "") {
    const headers = ["page", "name", "cid", "submit_url", "source", "extract_method", "row_text_sample"];
    const csvEscape = (value) => `"${String(value ?? "").replaceAll('"', '""')}"`;
    const csv = "\ufeff" + [
      headers.join(","),
      ...data.map((row) => headers.map((key) => csvEscape(row[key])).join(",")),
    ].join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    const a = document.createElement("a");
    const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
    a.href = URL.createObjectURL(blob);
    a.download = `butian_cids_${suffix ? suffix + "_" : ""}${stamp}.csv`;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 3000);
    a.remove();
    console.table(data);
    console.log(`done: exported ${data.length} cid rows`);
  }

  function pageNames() {
    return [...new Set([...document.querySelectorAll("button,a,span,div,p,td")]
      .filter(isVisible)
      .flatMap((el) => extractTargetNamesFromText(textOf(el))))].sort();
  }

  function pageSignature() {
    return `${location.href}::${pageNames().join("|")}`;
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
    return 1;
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
    const candidates = [...document.querySelectorAll("button,a,li,span")]
      .filter(isVisible)
      .filter((el) => !disabled(el))
      .filter((el) => numericPageOf(el) === current + 1);
    return candidates[0] ? clickTarget(candidates[0]) : null;
  }

  async function waitForPageChange(before) {
    for (let i = 0; i < 40; i += 1) {
      await sleep(300);
      if (pageSignature() !== before) {
        await sleep(600);
        return true;
      }
    }
    return false;
  }

  async function clickNextWithoutOpeningDetails() {
    const before = pageSignature();
    let next = findNextButton();
    if (!next) next = findNextPageNumberButton();
    if (!next) return false;
    next.scrollIntoView({ block: "center", inline: "center" });
    await sleep(150);
    next.click();
    return await waitForPageChange(before);
  }

  for (let pageIndex = 1; pageIndex <= maxPages; pageIndex += 1) {
    await sleep(250);
    collectPage(pageIndex);
    if (mode !== "2") break;
    window.scrollTo(0, document.body.scrollHeight);
    await sleep(250);
    const changed = await clickNextWithoutOpeningDetails();
    if (!changed) break;
    await sleep(pageDelayMs || 3000);
  }

  const data = [...rows.values()];
  downloadRows(data);
  sessionStorage.removeItem(STORAGE_KEY);
})();
