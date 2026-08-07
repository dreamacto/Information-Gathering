// Emergency exporter for iframe extractor cache/state.
// Paste into the same Butian tab console after a quota error.
// Output TXT format for this project runner: one target per line, "https://host|靶标名称".

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
  function cleanRunnerName(value) {
    return String(value || "").replace(/[|\r\n\t]+/g, " ").replace(/\s+/g, " ").trim();
  }
  function normalizedTargetUrl(value) {
    const raw = String(value || "").trim();
    if (!raw) return "";
    if (/^https?:\/\//i.test(raw)) return raw.replace(/\/$/, "");
    return `https://${raw}`.replace(/\/$/, "");
  }
  const seen = new Set();
  const lines = [
    "# Butian rescued targets for gov_exercise_runner.py / one_click_workflow.py",
    "# Format: URL|name",
    "# Lines starting with # are ignored by the runner.",
    `# Generated: ${new Date().toISOString()}`,
    "",
  ];
  let skipped = 0;
  for (const row of rows) {
    const url = String(row.normalized_target_url || normalizedTargetUrl(row.domain_or_ip) || "").trim();
    if (!/^https?:\/\//i.test(url)) {
      skipped += 1;
      continue;
    }
    const name = cleanRunnerName(row.name);
    const line = name ? `${url}|${name}` : url;
    const key = line.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    lines.push(line);
  }
  lines.push("");
  lines.push(`# Exported targets: ${seen.size}`);
  lines.push(`# Skipped rows without valid target URL: ${skipped}`);
  const blob = new Blob(["\ufeff" + lines.join("\n")], { type: "text/plain;charset=utf-8" });
  const a = document.createElement("a");
  const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  a.href = URL.createObjectURL(blob);
  a.download = `butian_targets_for_runner_rescued_${stamp}.txt`;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 3000);
  a.remove();
  console.table(rows);
  console.log(`[butian-iframe-domain-rescue] exported ${seen.size} runner targets from ${rows.length} cached rows, skipped ${skipped}`);
})();
