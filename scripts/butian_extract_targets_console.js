// Paste this into the browser DevTools Console on https://www.butian.net/Reward/plan/...
// Version 4: reads visible program/vendor rows, clicks pagination next or next page number,
// avoids full page navigation so the console script can finish and download CSV.
// Progress is backed up into sessionStorage; if a run errors, rerun and choose cache export/resume.
// It does not read or export cookies/tokens/localStorage.

(async () => {
  const STORAGE_KEY = "__butian_target_export_v4__";
  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const cached = sessionStorage.getItem(STORAGE_KEY);
  if (cached) {
    const choice = prompt("发现上次提取缓存：输入 1 直接导出缓存，输入 2 继续追加，输入 0 清空重来", "1");
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
  const delayMs = 900;
  const rows = new Map();
  if (cached && sessionStorage.getItem(STORAGE_KEY)) {
    for (const row of JSON.parse(cached || "[]")) {
      rows.set(`${row.name}||${row.href || ""}`, row);
    }
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

  function keyword() {
    const inputs = [...document.querySelectorAll("input")].filter(isVisible);
    const candidate = inputs.find((input) => (input.value || "").trim());
    return (candidate?.value || "butian").trim();
  }

  function saveProgress() {
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify([...rows.values()]));
  }

  function downloadRows(data, suffix = "") {
    const headers = ["page", "name", "href", "source"];
    const csvEscape = (value) => `"${String(value ?? "").replaceAll('"', '""')}"`;
    const csv = "\ufeff" + [
      headers.join(","),
      ...data.map((row) => headers.map((key) => csvEscape(row[key])).join(",")),
    ].join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    const a = document.createElement("a");
    const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
    a.href = URL.createObjectURL(blob);
    a.download = `butian_targets_${keyword() || "export"}${suffix ? "_" + suffix : ""}_${stamp}.csv`;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 3000);
    a.remove();
    console.table(data);
    console.log(`done: exported ${data.length} targets`);
  }

  function looksLikeTargetName(value) {
    const text = String(value || "").trim();
    if (text.length < 2 || text.length > 80) return false;
    if (!/[\u4e00-\u9fa5]/.test(text)) return false;
    if (/提交漏洞|补天|奖励|标准|帮助|公告|排行|登录|注册|搜索|更多详情|退出系统|项目大厅|综合排序|厂商信息|操作|公益SRC/.test(text)) return false;
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

  function rowContainerForSubmitButton(button) {
    let node = button;
    for (let depth = 0; depth < 10 && node; depth += 1, node = node.parentElement) {
      const rowText = textOf(node);
      const names = extractTargetNamesFromText(rowText);
      if (names.length && rowText.includes("提交漏洞") && rowText.length < 800) return { node, names };
    }
    return null;
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
      const link = [...found.node.querySelectorAll("a")].find((a) => textOf(a).includes(name));
      const href = link?.href || "";
      if (!looksLikeTargetName(name)) continue;
      const key = `${name}||${href}`;
      if (!rows.has(key)) {
        rows.set(key, {
          page: pageIndex,
          name,
          href,
          source: location.href,
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
        const href = el instanceof HTMLAnchorElement ? el.href : "";
        const key = `${name}||${href}`;
        if (!rows.has(key)) {
          rows.set(key, {
            page: pageIndex,
            name,
            href,
            source: location.href,
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
    const names = pageNames()
      .join("|");
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

  let pageIndex = 1;
  for (; pageIndex <= maxPages; pageIndex += 1) {
    await sleep(300);
    collectPage(pageIndex);
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
