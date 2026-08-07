"""Import the authorized healthcare workbook without modifying it.

The importer separates HTTP(S) targets from databases, PACS, VPNs and other
non-Web services.  It never contacts a target and never writes to the source
workbook.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import re
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import pandas as pd

import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


COLUMNS = [
    "system_name", "status", "organization", "owner", "exposure",
    "importance", "address", "domain", "url", "event",
]
URL_RE = re.compile(r"https?://[^\s，,；;]+", re.I)
HOST_PORT_RE = re.compile(r"(?<![\w.-])((?:\d{1,3}\.){3}\d{1,3})(?::(\d{1,5}))?")
HEALTH_CATEGORIES = {
    "his_emr": ("his", "emr", "病历", "电子病历", "临床"),
    "lis_lab": ("lis", "检验", "实验室"),
    "pacs_imaging": ("pacs", "dicom", "影像", "云胶片", "放射"),
    "patient_service": ("患者", "病人", "互联网医院", "健康卡", "体检", "随访", "心理"),
    "billing_insurance": ("收费", "缴费", "发票", "医保", "结算"),
    "oa_admin": ("oa", "办公", "协同"),
    "security_gateway": ("vpn", "防火墙", "网闸", "堡垒机"),
}


def _text(value: object) -> str:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return ""
    return str(value).strip()


def _normalize_url(raw: str) -> str | None:
    raw = raw.strip().rstrip(".)]}>、。")
    try:
        parts = urlsplit(raw)
    except ValueError:
        return None
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        return None
    netloc = parts.netloc.lower()
    return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, ""))


def _is_private_host(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host.lower() in {"localhost"} or host.lower().endswith((".local", ".lan"))
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved


def _category(text: str) -> list[str]:
    lowered = text.lower()
    matches = [name for name, words in HEALTH_CATEGORIES.items() if any(word.lower() in lowered for word in words)]
    return matches or ["other_health_system"]


def import_scope(xlsx: Path, output_dir: Path) -> dict:
    source_hash = hashlib.sha256(xlsx.read_bytes()).hexdigest()
    frame = pd.read_excel(xlsx, sheet_name=0, header=None, dtype=object)
    frame = frame.iloc[:, : len(COLUMNS)]
    frame.columns = COLUMNS[: frame.shape[1]]
    output_dir.mkdir(parents=True, exist_ok=True)

    assets: list[dict] = []
    public_web: set[str] = set()
    internal_web: set[str] = set()
    nonweb: list[dict] = []
    for index, row in frame.iterrows():
        record = {name: _text(row.get(name, "")) for name in COLUMNS}
        combined = " | ".join(record.values())
        urls = sorted(filter(None, (_normalize_url(value) for value in URL_RE.findall(combined))))
        public = [url for url in urls if not _is_private_host(urlsplit(url).hostname or "")]
        internal = [url for url in urls if _is_private_host(urlsplit(url).hostname or "")]
        public_web.update(public)
        internal_web.update(internal)
        url_hosts = {urlsplit(url).hostname for url in urls}
        endpoints = []
        for host, port in HOST_PORT_RE.findall(combined):
            if host in url_hosts:
                continue
            endpoints.append({"host": host, "port": int(port) if port else None})
        item = {
            "source_row": int(index) + 1,
            "system_name": record["system_name"],
            "organization": record["organization"],
            "importance": record["importance"],
            "categories": _category(combined),
            "public_web_urls": public,
            "internal_web_urls": internal,
            "nonweb_endpoints": endpoints,
        }
        assets.append(item)
        for endpoint in endpoints:
            nonweb.append({
                "source_row": item["source_row"],
                "system_name": item["system_name"],
                "organization": item["organization"],
                "categories": ";".join(item["categories"]),
                **endpoint,
                "default_action": "manual_queue_only",
                "reason": "non_web_or_explicit_service_validation_required",
            })

    def write_lines(name: str, values: set[str]) -> None:
        (output_dir / name).write_text("\n".join(sorted(values)) + ("\n" if values else ""), encoding="utf-8")

    write_lines("health_web_targets_public.txt", public_web)
    write_lines("health_web_targets_internal.txt", internal_web)
    write_lines("health_web_targets_all.txt", public_web | internal_web)
    with (output_dir / "health_nonweb_manual_queue.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        fields = ["source_row", "system_name", "organization", "categories", "host", "port", "default_action", "reason"]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(nonweb)
    manifest = {
        "source": str(xlsx),
        "source_sha256": source_hash,
        "source_modified": False,
        "rows": len(assets),
        "public_web_targets": len(public_web),
        "internal_web_targets": len(internal_web),
        "nonweb_endpoints": len(nonweb),
        "default_scan_input": "health_web_targets_public.txt",
        "internal_and_nonweb_policy": "separate_manual_or_explicitly_selected_queue",
        "privacy_policy": "asset metadata only; never collect patient values",
        "assets": assets,
    }
    (output_dir / "health_scope_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Create safe target queues from an authorized healthcare workbook")
    parser.add_argument("--xlsx", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    result = import_scope(args.xlsx, args.output_dir)
    print(json.dumps({key: value for key, value in result.items() if key != "assets"}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
