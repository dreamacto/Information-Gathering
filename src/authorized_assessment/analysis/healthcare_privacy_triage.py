"""Offline healthcare privacy triage.

Only endpoint paths and JSON field names are retained.  Values, response bodies,
tokens and patient records are deliberately excluded from all outputs.
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import argparse
import csv
import json
import re
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


TERMS = {
    "identity": ("patient", "patid", "patientid", "mpi", "empi", "mrn", "medicalrecord", "idcard", "certno", "姓名", "身份证", "患者", "病人", "病历号", "门诊号", "住院号", "手机号"),
    "clinical": ("encounter", "visit", "admission", "diagnosis", "icd", "prescription", "medication", "就诊", "诊断", "处方", "医嘱", "病历"),
    "lab_imaging": ("lis", "lab", "testresult", "report", "pacs", "dicom", "study", "image", "检验", "检查", "报告", "影像", "胶片"),
    "billing_insurance": ("billing", "invoice", "payment", "insurance", "medicare", "缴费", "发票", "医保", "结算"),
    "followup_mental": ("followup", "mental", "psych", "随访", "心理"),
}
SAFE_INPUT_NAMES = {
    "api_confirmed.jsonl", "api_interesting.jsonl", "api_endpoints.jsonl",
    "authenticated_api_results.jsonl", "authenticated_impact_candidates.jsonl",
    "impact_candidates.jsonl", "product_fingerprints.jsonl", "probe_results.jsonl",
}
URL_KEYS = {"url", "endpoint", "request_url", "final_url", "source_url", "base_url"}


def _categories(text: str) -> list[str]:
    compact = re.sub(r"[_\-\s./]", "", text).lower()
    return [category for category, words in TERMS.items() if any(word.lower() in compact for word in words)]


def _safe_url(value: object) -> str:
    if not isinstance(value, str):
        return ""
    try:
        parts = urlsplit(value)
    except ValueError:
        return ""
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        return ""
    # Query strings may contain patient values, so retain parameter names only.
    query_names = sorted({part.split("=", 1)[0] for part in parts.query.split("&") if part})
    query = "&".join(f"{name}=<redacted>" for name in query_names)
    try:
        port = parts.port
    except ValueError:
        return ""
    netloc = parts.hostname or ""
    if ":" in netloc and not netloc.startswith("["):
        netloc = f"[{netloc}]"
    if port is not None:
        netloc = f"{netloc}:{port}"
    return urlunsplit((parts.scheme, netloc, parts.path, query, ""))


def _walk_keys(value: object, prefix: str = "") -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            path = f"{prefix}.{key_text}" if prefix else key_text
            found.add(path)
            found.update(_walk_keys(child, path))
    elif isinstance(value, list):
        for child in value[:3]:
            found.update(_walk_keys(child, f"{prefix}[]" if prefix else "[]"))
    return found


def _iter_records(path: Path):
    if path.suffix.lower() == ".jsonl":
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                yield value
    else:
        try:
            value = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except (json.JSONDecodeError, OSError):
            return
        if isinstance(value, list):
            yield from (item for item in value if isinstance(item, dict))
        elif isinstance(value, dict):
            yield value


def build_triage(run_dir: Path) -> list[dict]:
    findings: dict[tuple[str, tuple[str, ...]], dict] = {}
    for path in run_dir.rglob("*"):
        if not path.is_file() or path.name not in SAFE_INPUT_NAMES:
            continue
        for record in _iter_records(path):
            keys = sorted(_walk_keys(record))
            sensitive_keys = sorted(key for key in keys if _categories(key))
            url = next((_safe_url(record.get(key)) for key in URL_KEYS if _safe_url(record.get(key))), "")
            categories = sorted(set(_categories(url) + [cat for key in sensitive_keys for cat in _categories(key)]))
            if not categories:
                continue
            identity = f"{url}|{path.name}" if url else path.name
            finding_key = (identity, tuple(sensitive_keys))
            findings[finding_key] = {
                "source_file": path.name,
                "endpoint": url,
                "categories": categories,
                "sensitive_field_paths": sensitive_keys,
                "field_count": len(sensitive_keys),
                "priority": "high" if "identity" in categories and len(categories) > 1 else "medium",
                "default_action": "manual_read_only_confirmation",
                "data_retention": "schema_and_endpoint_only_no_patient_values",
            }
    return sorted(findings.values(), key=lambda item: (item["priority"] != "high", item["endpoint"], item["source_file"]))


def write_outputs(run_dir: Path, findings: list[dict]) -> None:
    out = run_dir / "healthcare_privacy"
    out.mkdir(parents=True, exist_ok=True)
    with (out / "healthcare_sensitive_schema_candidates.jsonl").open("w", encoding="utf-8") as handle:
        for finding in findings:
            handle.write(json.dumps(finding, ensure_ascii=False) + "\n")
    fields = ["priority", "endpoint", "categories", "field_count", "source_file", "default_action", "data_retention"]
    with (out / "healthcare_manual_review_queue.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for finding in findings:
            row = dict(finding)
            row["categories"] = ";".join(finding["categories"])
            writer.writerow({key: row.get(key, "") for key in fields})
    counts = Counter(category for finding in findings for category in finding["categories"])
    summary = {
        "candidate_count": len(findings),
        "high_priority_count": sum(item["priority"] == "high" for item in findings),
        "categories": dict(counts),
        "collection_policy": "offline; endpoint paths and field names only; no patient values or response bodies",
        "prohibited_automatic_actions": ["export", "download", "bulk_record_read", "record_enumeration", "image_or_report_retrieval"],
    }
    (out / "healthcare_privacy_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline patient-information exposure triage")
    parser.add_argument("--run-dir", type=Path, required=True)
    args = parser.parse_args()
    findings = build_triage(args.run_dir)
    write_outputs(args.run_dir, findings)
    print(json.dumps({"candidate_count": len(findings)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
