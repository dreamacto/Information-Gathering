// Clear old Butian extractor caches on the current tab.

(() => {
  const keys = [
    "__butian_submit_domain_extract_v1__",
    "__butian_submit_domain_extract_stop_v1__",
    "__butian_submit_domain_iframe_extract_v1__",
    "__butian_submit_domain_iframe_extract_v2__",
    "__butian_submit_domain_iframe_stop_v1__",
    "__butian_company_api_capture_v1__",
    "__butian_company_api_capture_stop_v1__",
    "__butian_cid_export_v1__",
    "__butian_target_url_export_v5__",
    "__butian_target_url_export_v6__",
  ];
  for (const key of keys) sessionStorage.removeItem(key);
  delete window.__butian_submit_domain_iframe_results_v2__;
  console.log(`[butian-clear] removed ${keys.length} known extractor cache keys`);
})();
