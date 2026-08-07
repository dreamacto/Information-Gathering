// Emergency exporter for iframe extractor cache/state.
// Paste into the same Butian tab console after a quota error.

(() => {
  const keys = [
    "__butian_submit_domain_iframe_extract_v2__",
    "__butian_submit_domain_iframe_extract_v1__",
  ];
  const globals = [
    "__butian_submit_domain_iframe_results_v2__",
  ];
  let rows = [];
  for (const name of globals) {
    if (Array.isArray(window[name]) && window[name].length > rows.length) rows = window[name];
  }
  for (const key of keys) {
    try {
      const parsed = JSON.parse(sessionStorage.getItem(key) || "[]");
      if (Array.isArray(parsed) && parsed.length > rows.length) rows = parsed;
    } catch (_) {}
  }
  const headers = ["index", "name", "company_id", "submit_url", "domain_or_ip", "normalized_target_url", "status", "error", "captured_at"];
  const csvEscape = (value) => `"${String(value ?? "").replaceAll('"', '""')}"`;
  const csv = "\ufeff" + [
    headers.join(","),
    ...rows.map((row) => headers.map((key) => csvEscape(row[key])).join(",")),
  ].join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const a = document.createElement("a");
  const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  a.href = URL.createObjectURL(blob);
  a.download = `butian_submit_domains_iframe_rescued_${stamp}.csv`;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 3000);
  a.remove();
  console.table(rows);
  console.log(`[butian-iframe-domain-rescue] exported ${rows.length} rows`);
})();
