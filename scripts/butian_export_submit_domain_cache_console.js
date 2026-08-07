// Emergency exporter for cached butian_submit_domains results.
// Paste into the same Butian tab console if the previous extractor stopped with "quota exceeded".

(() => {
  const STORAGE_KEY = "__butian_submit_domain_extract_v1__";
  const rows = JSON.parse(sessionStorage.getItem(STORAGE_KEY) || "[]");
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
  a.download = `butian_submit_domains_rescued_${stamp}.csv`;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 3000);
  a.remove();
  console.table(rows);
  console.log(`[butian-submit-domain-rescue] exported ${rows.length} cached rows`);
})();
