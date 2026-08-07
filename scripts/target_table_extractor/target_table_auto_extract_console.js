// Paste into the target-list page console.
// Purpose: extract the visible paginated target table into CSV.
// Scope: reads the current page DOM and clicks pagination "next" slowly.
// It does not visit target URLs, does not submit forms, and does not export cookies/tokens.
//
// Expected columns may include:
// 靶标名称, 靶标状态, 防守单位, 所属单位, 靶标属性, 靶标类别, 靶标IP, 靶标域名, 靶标URL
//
// Optional before paste:
// window.__TARGET_TABLE_EXTRACT_CONFIG__ = { maxPages: 60, delayMs: 1800, partEveryPages: 10 };

(async () => {
  const CONFIG = {
    maxPages: 80,
    delayMs: 1800,
    waitPollMs: 250,
    waitLoops: 40,
    partEveryPages: 10,
    storageKey: "__target_table_extract_rows_v3__",
    stopKey: "__target_table_extract_stop_v3__",
    ...window.__TARGET_TABLE_EXTRACT_CONFIG__,
  };

  const DEFAULT_TARGET_HEADERS = [
    "靶标名称",
    "靶标状态",
    "防守单位",
    "所属单位",
    "靶标属性",
    "靶标类别",
    "靶标IP",
    "靶标域名",
    "靶标URL",
  ];
  const TARGET_HEADER_KEYWORDS = new Set(DEFAULT_TARGET_HEADERS);

  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const nowStamp = () => new Date().toISOString();
  const clean = (value) => String(value ?? "").replace(/\s+/g, " ").trim();

  function textOf(el) {
    return clean(el?.innerText || el?.textContent || "");
  }

  function looksLikeWatermark(value) {
    const text = clean(value);
    return (
      !text ||
      /^鹏城网络靶场/.test(text) ||
      /^19\d{8,}$/.test(text) ||
      /鹏城网络靶场广西分靶场/.test(text)
    );
  }

  function cellTextOf(el) {
    return clean(
      [...(el?.childNodes || [])]
        .map((node) => clean(node.innerText || node.textContent || ""))
        .filter((text) => text && !looksLikeWatermark(text))
        .join(" ")
    );
  }

  function normalizeCells(cells) {
    const cleaned = cells.map(clean).filter((value) => value && !looksLikeWatermark(value));
    if (cleaned.length > DEFAULT_TARGET_HEADERS.length && cleaned.some((value) => /^https?:\/\//i.test(value))) {
      return cleaned.slice(0, DEFAULT_TARGET_HEADERS.length);
    }
    return cleaned;
  }

  function isVisible(el) {
    if (!el || !(el instanceof Element)) return false;
    const rect = el.getBoundingClientRect();
    const style = getComputedStyle(el);
    return rect.width > 0 && rect.height > 0 && style.display !== "none" && style.visibility !== "hidden";
  }

  function isDisabled(el) {
    if (!el) return true;
    const text = [
      String(el.className || ""),
      el.getAttribute?.("aria-disabled") || "",
      el.getAttribute?.("disabled") || "",
      el.getAttribute?.("class") || "",
    ].join(" ");
    return Boolean(el.disabled) || /disabled|is-disabled|ant-pagination-disabled|true|不可用|禁用/.test(text);
  }

  function loadRows() {
    try {
      const rows = JSON.parse(sessionStorage.getItem(CONFIG.storageKey) || "[]");
      return Array.isArray(rows) ? rows : [];
    } catch (_) {
      return [];
    }
  }

  function rowKey(row) {
    const key = [
      row["靶标名称"],
      row["防守单位"],
      row["所属单位"],
      row["靶标IP"],
      row["靶标域名"],
      row["靶标URL"],
    ].map(clean).join("||");
    return key.replace(/\|/g, "") ? key : JSON.stringify(row);
  }

  function saveRows(rows) {
    const dedup = new Map();
    for (const row of rows) {
      const key = rowKey(row) || JSON.stringify(row);
      if (!dedup.has(key)) dedup.set(key, row);
    }
    const saved = [...dedup.values()];
    try {
      sessionStorage.setItem(CONFIG.storageKey, JSON.stringify(saved));
    } catch (error) {
      console.warn("[target-table] sessionStorage save failed; keeping in memory only", error);
    }
    window.__targetTableExtractRows = saved;
    return saved;
  }

  function tableScore(headers, rows) {
    const headerText = headers.join(" ");
    let score = rows.length * 5 + headers.length * 2;
    for (const kw of ["靶标名称", "防守单位", "所属单位", "靶标IP", "靶标域名", "靶标URL", "靶标类别"]) {
      if (headerText.includes(kw)) score += 30;
    }
    return score;
  }

  function extractFromNativeTables() {
    const candidates = [];
    for (const table of [...document.querySelectorAll("table")].filter(isVisible)) {
      let headers = normalizeCells([...table.querySelectorAll("thead th")].map(cellTextOf));
      const allRows = [...table.querySelectorAll("tbody tr, tr")]
        .filter((tr, idx, arr) => arr.indexOf(tr) === idx)
        .filter(isVisible)
        .map((tr) => {
          const dataCells = [...tr.querySelectorAll("td")];
          const cells = dataCells.length ? dataCells : [...tr.querySelectorAll("th,td")];
          return normalizeCells(cells.map(cellTextOf));
        })
        .filter((cells) => cells.length >= 3 && cells.some(Boolean));
      let bodyRows = allRows;
      if (!headers.length && allRows.length) {
        const firstCells = allRows[0];
        const headerHits = firstCells.filter((cell) => TARGET_HEADER_KEYWORDS.has(cell)).length;
        if (headerHits >= 3) {
          headers = firstCells;
          bodyRows = allRows.slice(1);
        } else {
          headers = DEFAULT_TARGET_HEADERS.slice(0, Math.min(DEFAULT_TARGET_HEADERS.length, Math.max(...allRows.map((r) => r.length))));
        }
      }
      if (headers.length >= 3 && bodyRows.length >= 1) {
        candidates.push({ headers, rows: bodyRows, score: tableScore(headers, bodyRows), source: "native_table" });
      }
    }
    candidates.sort((a, b) => b.score - a.score);
    return candidates[0] || null;
  }

  function extractFromGridLikeDom() {
    const headerSelectors = [
      ".el-table__header-wrapper th",
      ".ant-table-thead th",
      "[role='columnheader']",
      ".vxe-header--column",
    ];
    const rowSelectors = [
      ".el-table__body-wrapper tbody tr",
      ".ant-table-tbody tr",
      "[role='row']",
      ".vxe-body--row",
    ];
    let headers = normalizeCells([...new Set(headerSelectors.flatMap((selector) => [...document.querySelectorAll(selector)]))]
      .filter(isVisible)
      .map(cellTextOf));
    const rows = [...new Set(rowSelectors.flatMap((selector) => [...document.querySelectorAll(selector)]))]
      .filter(isVisible)
      .map((row) => {
        const cells = [...row.querySelectorAll("td,[role='cell'],.el-table__cell,.ant-table-cell,.vxe-body--column")]
          .filter(isVisible)
          .map(cellTextOf);
        return normalizeCells(cells);
      })
      .filter((cells) => cells.length >= 3 && cells.some(Boolean));
    if (!headers.length && rows.length) {
      headers = DEFAULT_TARGET_HEADERS.slice(0, Math.min(DEFAULT_TARGET_HEADERS.length, Math.max(...rows.map((r) => r.length))));
    }
    if (headers.length >= 3 && rows.length) return { headers, rows, score: tableScore(headers, rows), source: "grid_dom" };
    return null;
  }

  function normalizeHeaders(headers) {
    const normalized = headers.map((h, idx) => clean(h) || `列${idx + 1}`);
    const seen = new Map();
    return normalized.map((h) => {
      const count = (seen.get(h) || 0) + 1;
      seen.set(h, count);
      return count === 1 ? h : `${h}_${count}`;
    });
  }

  function extractCurrentPageRows(pageNo) {
    const table = extractFromNativeTables() || extractFromGridLikeDom();
    if (!table) throw new Error("没有识别到表格。请确认列表表格在当前页面可见。");
    const headers = normalizeHeaders(table.headers);
    const rows = table.rows.map((cells, index) => {
      const row = {};
      headers.forEach((header, i) => {
        row[header] = clean(cells[i] || "");
      });
      if (!row["靶标URL"]) {
        const urlCell = cells.find((cell) => /^https?:\/\//i.test(clean(cell)));
        if (urlCell) row["靶标URL"] = clean(urlCell);
      }
      if (!row["靶标域名"]) {
        const domainCell = cells.find((cell) => /^[a-z0-9.-]+\.[a-z]{2,}(:\d+)?$/i.test(clean(cell)));
        if (domainCell) row["靶标域名"] = clean(domainCell);
      }
      if (!row["靶标IP"]) {
        const ipCell = cells.find((cell) => /^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?$/.test(clean(cell)));
        if (ipCell) row["靶标IP"] = clean(ipCell);
      }
      row["__page"] = pageNo;
      row["__row_in_page"] = index + 1;
      row["__captured_at"] = nowStamp();
      row["__source"] = table.source;
      return row;
    });
    return { headers: [...headers, "__page", "__row_in_page", "__captured_at", "__source"], rows, source: table.source };
  }

  function currentSignature() {
    try {
      const current = extractCurrentPageRows(-1);
      return current.rows.map(rowKey).join("###").slice(0, 2000);
    } catch (_) {
      return textOf(document.body).slice(0, 2000);
    }
  }

  function directTextOf(el) {
    return clean(
      [...(el?.childNodes || [])]
        .filter((node) => node.nodeType === Node.TEXT_NODE)
        .map((node) => node.textContent || "")
        .join(" ")
    );
  }

  function classTextOf(el) {
    return clean([
      String(el?.className || ""),
      el?.getAttribute?.("class") || "",
      el?.getAttribute?.("role") || "",
      el?.getAttribute?.("aria-label") || "",
      el?.getAttribute?.("title") || "",
    ].join(" "));
  }

  function paginationContextScore(el) {
    let score = 0;
    let cur = el;
    for (let depth = 0; cur && depth < 7; depth += 1, cur = cur.parentElement) {
      const cls = classTextOf(cur);
      const text = textOf(cur).slice(0, 600);
      if (/pagination|pager|page-|page_|页码|分页|el-pagination|ant-pagination|ivu-page|arco-pagination|n-pagination/i.test(cls)) score += 80 - depth * 5;
      if (/共\s*\d+\s*条|条\/页|每页|前往|跳至|页/.test(text)) score += 30 - depth * 3;
      if (/\b1\b.*\b2\b.*\b3\b/.test(text)) score += 20 - depth * 2;
    }
    return score;
  }

  function clickableOf(el) {
    return el?.closest?.(
      "button,a,li,[role='button'],[tabindex],.ant-pagination-item,.ant-pagination-next,.el-pager li,.btn-next,.ivu-page-item,.ivu-page-next,.arco-pagination-item,.n-pagination-item"
    ) || el;
  }

  function safeClick(el) {
    const target = clickableOf(el);
    if (!target || isDisabled(target)) return false;
    const label = textOf(target) || classTextOf(target);
    if (/提交|删除|保存|启用|禁用|登录|注册/.test(label)) {
      console.warn("[target-table] refused to click suspicious control:", label);
      return false;
    }
    target.scrollIntoView({ block: "center", inline: "center" });
    for (const type of ["mouseover", "mousedown", "mouseup"]) {
      target.dispatchEvent(new MouseEvent(type, { bubbles: true, cancelable: true, view: window }));
    }
    if (typeof target.click === "function") target.click();
    return true;
  }

  function collectPaginationControls() {
    const selectors = [
      ".btn-next",
      ".el-pagination .btn-next",
      ".el-pagination button",
      ".el-pager li",
      ".ant-pagination-item",
      ".ant-pagination-item a",
      ".ant-pagination-next",
      ".ant-pagination-next button",
      ".ivu-page-item",
      ".ivu-page-next",
      ".arco-pagination-item",
      ".n-pagination-item",
      ".n-pagination-next",
      "[aria-label='下一页']",
      "[title='下一页']",
      "[class*='pagination']",
      "[class*='pager']",
      "[class*='next']",
      "button",
      "a",
      "li",
      "span",
    ];
    return [...new Set(selectors.flatMap((selector) => [...document.querySelectorAll(selector)]))]
      .filter(isVisible)
      .map((el) => ({
        el,
        clickable: clickableOf(el),
        text: textOf(el),
        directText: directTextOf(el),
        cls: classTextOf(el),
        score: paginationContextScore(el),
      }))
      .filter((item) => item.score > 0 && !isDisabled(item.clickable || item.el))
      .sort((a, b) => b.score - a.score);
  }

  function findPageNumberControl(pageNo) {
    const wanted = String(pageNo);
    const controls = collectPaginationControls().filter((item) => {
      const text = clean(item.directText || item.text);
      return text === wanted || item.text === wanted;
    });
    controls.sort((a, b) => b.score - a.score);
    return controls[0]?.el || null;
  }

  function findNextButton() {
    const controls = collectPaginationControls();
    const found = controls.find((item) => {
      const value = [item.text, item.directText, item.cls].join(" ");
      return /下一页|next|pagination-next|btn-next|pager-next|ivu-page-next|›|»|>/.test(value);
    });
    if (!found) return null;
    return found.el;
  }

  window.__targetTableDebugPagination = () => {
    const rows = collectPaginationControls().slice(0, 120).map((item, idx) => ({
      idx,
      score: item.score,
      text: item.text.slice(0, 80),
      directText: item.directText,
      class: item.cls.slice(0, 120),
      tag: item.el.tagName,
    }));
    console.table(rows);
    return rows;
  };

  function findLegacyNextButton() {
    const selectors = [
      ".btn-next",
      ".el-pagination .btn-next",
      ".ant-pagination-next",
      ".ant-pagination-next button",
      "[aria-label='下一页']",
      "[title='下一页']",
      "button",
      "a",
      "li",
    ];
    const candidates = [...new Set(selectors.flatMap((selector) => [...document.querySelectorAll(selector)]))]
      .filter(isVisible)
      .filter((el) => !isDisabled(el));
    const found = candidates.find((el) => {
      const value = [
        textOf(el),
        el.getAttribute?.("aria-label") || "",
        el.getAttribute?.("title") || "",
        String(el.className || ""),
      ].join(" ");
      return /下一页|next|pagination-next|btn-next|›|»|>/.test(value);
    });
    if (!found) return null;
    return found.querySelector?.("button:not([disabled]),a") || found;
  }

  async function waitForPageChange(beforeSignature) {
    for (let i = 0; i < Number(CONFIG.waitLoops || 40); i += 1) {
      await sleep(Number(CONFIG.waitPollMs || 250));
      if (currentSignature() !== beforeSignature) {
        await sleep(500);
        return true;
      }
    }
    return false;
  }

  async function clickNextAndWait(beforeSignature, nextPageNo) {
    const attempts = [
      ["page_number", findPageNumberControl(nextPageNo)],
      ["next_button", findNextButton()],
      ["legacy_next", findLegacyNextButton()],
    ].filter(([, el]) => Boolean(el));

    for (const [method, el] of attempts) {
      console.log(`[target-table] try pagination method=${method} target=${nextPageNo} label="${(textOf(el) || classTextOf(el)).slice(0, 80)}"`);
      if (!safeClick(el)) continue;
      if (await waitForPageChange(beforeSignature)) {
        console.log(`[target-table] pagination changed by ${method}`);
        return true;
      }
      console.warn(`[target-table] pagination method did not change page: ${method}`);
    }
    console.warn("[target-table] pagination controls not changed; run __targetTableDebugPagination() and send the table if it still fails");
    return false;
  }

  function downloadRows(rows, suffix = "captured") {
    if (!rows.length) {
      console.warn("[target-table] no rows to export");
      return;
    }
    const allHeaders = [];
    for (const row of rows) {
      for (const key of Object.keys(row)) {
        if (!allHeaders.includes(key)) allHeaders.push(key);
      }
    }
    const preferred = ["靶标名称", "靶标状态", "防守单位", "所属单位", "靶标属性", "靶标类别", "靶标IP", "靶标域名", "靶标URL"];
    const headers = [...preferred.filter((h) => allHeaders.includes(h)), ...allHeaders.filter((h) => !preferred.includes(h))];
    const csvEscape = (value) => `"${String(value ?? "").replaceAll('"', '""')}"`;
    const csv = "\ufeff" + [
      headers.join(","),
      ...rows.map((row) => headers.map((key) => csvEscape(row[key])).join(",")),
    ].join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    const a = document.createElement("a");
    const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
    a.href = URL.createObjectURL(blob);
    a.download = `target_table_${suffix}_${stamp}.csv`;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 3000);
    a.remove();
    console.log(`[target-table] exported ${rows.length} rows: ${a.download}`);
  }

  window.__targetTableStop = () => {
    sessionStorage.setItem(CONFIG.stopKey, "1");
    console.warn("[target-table] stop flag set");
  };
  window.__targetTableExport = () => downloadRows(loadRows(), "manual");
  window.__targetTableClear = () => {
    sessionStorage.removeItem(CONFIG.storageKey);
    sessionStorage.removeItem(CONFIG.stopKey);
    window.__targetTableExtractRows = [];
    console.log("[target-table] cache cleared");
  };

  const cached = loadRows();
  if (cached.length) {
    const choice = prompt(`发现缓存 ${cached.length} 条：1=继续追加，2=直接导出，0=清空重来`, "1");
    if (choice === "2") return downloadRows(cached, "cached");
    if (choice === "0") window.__targetTableClear();
  }
  sessionStorage.removeItem(CONFIG.stopKey);

  let allRows = loadRows();
  let lastPartAt = allRows.length;
  let pageNo = 1;
  console.log(`[target-table] start maxPages=${CONFIG.maxPages} delayMs=${CONFIG.delayMs}`);

  for (; pageNo <= Number(CONFIG.maxPages || 80); pageNo += 1) {
    if (sessionStorage.getItem(CONFIG.stopKey) === "1") {
      console.warn("[target-table] stopped by operator");
      break;
    }
    const before = currentSignature();
    const current = extractCurrentPageRows(pageNo);
    const beforeCount = allRows.length;
    allRows.push(...current.rows);
    allRows = saveRows(allRows);
    console.log(`[target-table] page=${pageNo} source=${current.source} page_rows=${current.rows.length} total=${allRows.length} added=${allRows.length - beforeCount}`);

    if (Number(CONFIG.partEveryPages || 0) > 0 && pageNo % Number(CONFIG.partEveryPages) === 0 && allRows.length > lastPartAt) {
      downloadRows(allRows.slice(lastPartAt), `part_${lastPartAt + 1}_${allRows.length}`);
      lastPartAt = allRows.length;
    }

    await sleep(Number(CONFIG.delayMs || 1800));
    const changed = await clickNextAndWait(before, pageNo + 1);
    if (!changed) {
      console.log("[target-table] no next page or page did not change; finishing");
      break;
    }
  }

  if (allRows.length > lastPartAt && Number(CONFIG.partEveryPages || 0) > 0) {
    downloadRows(allRows.slice(lastPartAt), `part_${lastPartAt + 1}_${allRows.length}_final`);
  }
  downloadRows(saveRows(allRows), "captured");
})();
