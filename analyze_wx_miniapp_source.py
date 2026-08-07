import argparse
import base64
import collections
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlparse


os.environ["PYTHONUTF8"] = "1"
os.environ["PYTHONIOENCODING"] = "utf-8"
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


TEXT_SUFFIXES = {
    ".js",
    ".json",
    ".wxml",
    ".wxss",
    ".ts",
    ".xml",
    ".html",
    ".css",
    ".txt",
    ".map",
}

URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
DOMAIN_RE = re.compile(r"(?<![A-Za-z0-9_-])(?:[A-Za-z0-9-]+\.)+(?:com|cn|net|org|gov|edu|io|top|cc|info|biz|app|dev|cloud|com\.cn|net\.cn|org\.cn|gov\.cn|edu\.cn)(?![A-Za-z0-9_-])", re.I)
WX_REQUEST_RE = re.compile(r"\bwx\.(request|uploadFile|downloadFile|connectSocket|requestPayment|login|getUserProfile|getUserInfo|chooseLocation|getLocation)\b")
STORAGE_RE = re.compile(r"\bwx\.(setStorageSync|getStorageSync|setStorage|getStorage|removeStorageSync|removeStorage)\s*\(\s*['\"]([^'\"]+)['\"]")
KEY_HINT_RE = re.compile(r"(token|secret|appid|appsecret|authorization|bearer|session|cookie|key|sign|password|passwd|pwd)", re.I)
PATH_RE = re.compile(r"['\"]((?:/[A-Za-z0-9_.~:@!$&'()*+,;=%-]+){2,}(?:\?[A-Za-z0-9_.~:/?#\[\]@!$&'()*+,;=%-]*)?)['\"]")


def read_text(path: Path) -> str:
    data = path.read_bytes()
    if len(data) > 5_000_000:
        return ""
    for encoding in ("utf-8", "utf-8-sig", "gbk", "cp936", "latin1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root)).replace("\\", "/")
    except ValueError:
        return str(path)


def maybe_json(path: Path) -> object | None:
    try:
        return json.loads(read_text(path))
    except Exception:
        return None


def redacted(value: str) -> str:
    if len(value) <= 12:
        return value
    return f"{value[:6]}...{value[-4:]}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    root = args.source_dir
    report = {
        "source_dir": str(root),
        "exists": root.exists(),
        "is_dir": root.is_dir() if root.exists() else False,
        "files": [],
        "summary": {},
        "app_json": None,
        "project_config": None,
        "urls": [],
        "domains": [],
        "api_paths": [],
        "wx_api_usage": [],
        "storage_keys": [],
        "sensitive_hints": [],
        "errors": [],
    }
    if not root.exists() or not root.is_dir():
        args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 1

    files = []
    for path in root.rglob("*"):
        try:
            if path.is_file():
                files.append(path)
        except OSError as exc:
            report["errors"].append({"path": str(path), "error": str(exc)})

    suffix_counts = collections.Counter(path.suffix.lower() or "<noext>" for path in files)
    report["summary"] = {
        "file_count": len(files),
        "suffix_counts": dict(suffix_counts.most_common(25)),
        "total_bytes": sum(path.stat().st_size for path in files if path.exists()),
    }
    report["files"] = [
        {"path": rel(path, root), "size": path.stat().st_size, "sha256_12": hashlib.sha256(path.read_bytes()[:8192]).hexdigest()[:12]}
        for path in sorted(files, key=lambda p: rel(p, root))[:500]
    ]

    for name in ("app.json", "project.config.json", "app-config.json", "app-service.js"):
        candidate = root / name
        if candidate.exists():
            if candidate.suffix == ".json":
                report["app_json" if name == "app.json" else "project_config"] = maybe_json(candidate)
            else:
                report["summary"][name] = {"size": candidate.stat().st_size}

    url_hits = {}
    domain_hits = {}
    path_hits = {}
    wx_hits = []
    storage_hits = []
    sensitive_hints = []
    for path in files:
        if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in {"app-service.js", "app-config.json"}:
            continue
        try:
            text = read_text(path)
        except Exception as exc:
            report["errors"].append({"path": rel(path, root), "error": str(exc)})
            continue
        if not text:
            continue
        r = rel(path, root)
        for match in URL_RE.finditer(text):
            value = match.group(0).rstrip(").,;'\"<>")
            url_hits.setdefault(value, set()).add(r)
            host = urlparse(value).hostname
            if host:
                domain_hits.setdefault(host.lower(), set()).add(r)
        for match in DOMAIN_RE.finditer(text):
            domain_hits.setdefault(match.group(0).lower(), set()).add(r)
        for match in PATH_RE.finditer(text):
            value = match.group(1)
            if not value.startswith("//"):
                path_hits.setdefault(value[:240], set()).add(r)
        for match in WX_REQUEST_RE.finditer(text):
            wx_hits.append({"api": match.group(0), "file": r})
        for match in STORAGE_RE.finditer(text):
            storage_hits.append({"key": match.group(2), "file": r})
        for line_no, line in enumerate(text.splitlines(), 1):
            if KEY_HINT_RE.search(line) and ("=" in line or ":" in line):
                compact = line.strip()
                if len(compact) > 260:
                    compact = compact[:260] + "..."
                sensitive_hints.append({"file": r, "line": line_no, "sample": compact})
                if len(sensitive_hints) >= 120:
                    break

    report["urls"] = [
        {"url": value, "files": sorted(paths)[:10]}
        for value, paths in sorted(url_hits.items(), key=lambda item: item[0])[:300]
    ]
    report["domains"] = [
        {"domain": value, "files": sorted(paths)[:10]}
        for value, paths in sorted(domain_hits.items(), key=lambda item: item[0])[:300]
    ]
    report["api_paths"] = [
        {"path": value, "files": sorted(paths)[:10]}
        for value, paths in sorted(path_hits.items(), key=lambda item: item[0])[:500]
    ]
    report["wx_api_usage"] = wx_hits[:500]
    report["storage_keys"] = storage_hits[:300]
    report["sensitive_hints"] = sensitive_hints[:120]

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print("== SUMMARY ==")
    print(json.dumps(report["summary"], ensure_ascii=False, indent=2))
    print("\n== APP JSON ==")
    if report["app_json"]:
        app = report["app_json"]
        print(json.dumps({
            "pages_count": len(app.get("pages", [])) if isinstance(app, dict) else None,
            "first_pages": app.get("pages", [])[:20] if isinstance(app, dict) else None,
            "subPackages": app.get("subPackages") or app.get("subpackages") if isinstance(app, dict) else None,
            "permission": app.get("permission") if isinstance(app, dict) else None,
            "plugins": app.get("plugins") if isinstance(app, dict) else None,
        }, ensure_ascii=False, indent=2))
    else:
        print("<missing>")
    print("\n== DOMAINS ==")
    for item in report["domains"][:80]:
        print(f"{item['domain']}  files={','.join(item['files'][:3])}")
    print("\n== URLS ==")
    for item in report["urls"][:80]:
        print(f"{item['url']}  files={','.join(item['files'][:3])}")
    print("\n== API PATHS SAMPLE ==")
    for item in report["api_paths"][:120]:
        print(f"{item['path']}  files={','.join(item['files'][:3])}")
    print("\n== STORAGE KEYS ==")
    for item in report["storage_keys"][:80]:
        print(f"{item['key']}  file={item['file']}")
    print("\n== SENSITIVE HINTS SAMPLE ==")
    for item in report["sensitive_hints"][:40]:
        sample = item["sample"]
        print(f"{item['file']}:{item['line']}: {sample}")
    print(f"\nReport: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
