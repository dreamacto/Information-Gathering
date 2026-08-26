from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import time
import urllib.request
import zipfile
from datetime import datetime
from pathlib import Path


if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(r"D:\PythonSource\PythonProjects\PythonProject4")
MANAGED = ROOT / "tools" / "managed"
DOWNLOADS = MANAGED / "_downloads"
USER_AGENT = "gx-health-exercise-tool-manager/1.0"
LOCK_FILE = ROOT / "managed_tools_lock.json"

SPECS = [
    {
        "name": "nuclei",
        "repo": "projectdiscovery/nuclei",
        "tag": "v3.8.0",
        "asset_patterns": [r"nuclei_3\.8\.0_windows_amd64\.zip$"],
    },
    {
        "name": "nuclei-templates",
        "repo": "projectdiscovery/nuclei-templates",
        "tag": "v10.4.4",
        "asset_patterns": [],
        "source_fallback": True,
    },
    {
        "name": "httpx",
        "repo": "projectdiscovery/httpx",
        "tag": "v1.9.0",
        "asset_patterns": [r"httpx_1\.9\.0_windows_amd64\.zip$"],
    },
    {
        "name": "katana",
        "repo": "projectdiscovery/katana",
        "tag": "v1.6.1",
        "asset_patterns": [r"katana_1\.6\.1_windows_amd64\.zip$"],
    },
    {
        "name": "afrog",
        "repo": "zan8in/afrog",
        "tag": "v3.5.3",
        "asset_patterns": [r"(?i).*windows.*amd64.*\.zip$", r"(?i).*windows.*amd64.*\.exe$"],
    },
    {
        "name": "shiroattack2",
        "repo": "SummerSec/ShiroAttack2",
        "tag": "v5.1.1",
        "asset_patterns": [
            r"(?i)shiro_attack-5\.1\.1.*jdk8.*\.jar$",
            r"(?i)shiro_attack-5\.1\.1.*\.jar$",
            r"(?i)shiro_attack-5\.1\.1.*bundle.*\.zip$",
        ],
    },
]


def load_lock() -> dict:
    try:
        data = json.loads(LOCK_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"managed tool lock is missing or invalid: {LOCK_FILE}") from exc
    if not isinstance(data.get("tools"), dict):
        raise RuntimeError("managed tool lock has no tools map")
    return data


LOCK = load_lock()


def request_json(url: str) -> dict:
    last_error: Exception | None = None
    for attempt in range(1, 4):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"})
            with urllib.request.urlopen(request, timeout=40) as response:
                return json.load(response)
        except Exception as exc:
            last_error = exc
            if attempt < 3:
                time.sleep(attempt * 2)
    raise RuntimeError(f"GitHub API request failed: {url}") from last_error


def download(url: str, destination: Path, expected_size: int | None = None) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        size_ok = expected_size is None or destination.stat().st_size == expected_size
        format_ok = destination.suffix.lower() != ".zip" or zipfile.is_zipfile(destination)
        if size_ok and format_ok:
            print(f"Using cached {destination.name} ({destination.stat().st_size} bytes)...", flush=True)
            return
        print(f"Discarding incomplete cache {destination.name}...", flush=True)
        destination.unlink()
    temporary = destination.with_suffix(destination.suffix + ".part")
    last_error: Exception | None = None
    for attempt in range(1, 5):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(request, timeout=120) as response, temporary.open("wb") as handle:
                shutil.copyfileobj(response, handle, length=1024 * 1024)
            if expected_size is not None and temporary.stat().st_size != expected_size:
                raise RuntimeError(
                    f"size mismatch for {destination.name}: {temporary.stat().st_size} != {expected_size}"
                )
            temporary.replace(destination)
            return
        except Exception as exc:
            last_error = exc
            temporary.unlink(missing_ok=True)
            if attempt < 4:
                print(f"Download attempt {attempt} failed: {exc}; retrying...", flush=True)
                time.sleep(attempt * 2)
    raise RuntimeError(f"download failed after 4 attempts: {url}") from last_error


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_extract(archive: Path, destination: Path) -> list[str]:
    extracted = []
    destination.mkdir(parents=True, exist_ok=True)
    root = destination.resolve()
    with zipfile.ZipFile(archive) as zf:
        for member in zf.infolist():
            target = (destination / member.filename).resolve()
            if root not in target.parents and target != root:
                raise RuntimeError(f"zip path escapes destination: {member.filename}")
        zf.extractall(destination)
        extracted = [member.filename for member in zf.infolist() if not member.is_dir()]
    return extracted


def select_asset(assets: list[dict], patterns: list[str]) -> dict:
    for pattern in patterns:
        for asset in assets:
            if re.search(pattern, asset.get("name", "")):
                return asset
    available = [asset.get("name") for asset in assets]
    raise RuntimeError(f"no matching asset; available={available}")


parser = argparse.ArgumentParser(description="Install pinned official security tool releases")
parser.add_argument("--only", action="append", default=[], help="Install only the named tool; repeatable")
args = parser.parse_args()
selected_names = set(args.only)

MANAGED.mkdir(parents=True, exist_ok=True)
manifest = {
    "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
    "policy": "official_release_assets_only; versioned; no live execution during install",
    "tools": [],
}

for spec in SPECS:
    if selected_names and spec["name"] not in selected_names:
        continue
    print(f"Resolving {spec['repo']} {spec['tag']}...", flush=True)
    release = request_json(f"https://api.github.com/repos/{spec['repo']}/releases/tags/{spec['tag']}")
    if spec.get("source_fallback"):
        asset = {
            "name": f"{spec['name']}-{spec['tag']}.zip",
            "browser_download_url": f"https://github.com/{spec['repo']}/archive/refs/tags/{spec['tag']}.zip",
            "size": None,
        }
    else:
        asset = select_asset(release.get("assets", []), spec["asset_patterns"])
    version = spec["tag"].lstrip("v")
    tool_dir = MANAGED / spec["name"] / version
    download_dir = DOWNLOADS / spec["name"] / version
    archive = download_dir / asset["name"]
    print(f"Downloading {asset['name']}...", flush=True)
    download(asset["browser_download_url"], archive, asset.get("size"))
    lock = LOCK.get("tools", {}).get(spec["name"], {})
    expected_sha = str(lock.get("expected_sha256") or "")
    expected_bytes = lock.get("expected_bytes")
    if not expected_sha:
        raise RuntimeError(f"refusing to install {spec['name']}: expected_sha256 is not pinned")
    if sha256(archive).lower() != expected_sha.lower():
        raise RuntimeError(f"hash mismatch for {spec['name']}: expected {expected_sha}")
    if expected_bytes is not None and archive.stat().st_size != int(expected_bytes):
        raise RuntimeError(f"size mismatch for {spec['name']}: expected {expected_bytes}")
    record = {
        "name": spec["name"],
        "repo": f"https://github.com/{spec['repo']}",
        "tag": spec["tag"],
        "release_url": release.get("html_url"),
        "published_at": release.get("published_at"),
        "asset": asset["name"],
        "asset_url": asset["browser_download_url"],
        "asset_bytes": archive.stat().st_size,
        "sha256": sha256(archive),
        "expected_sha256": expected_sha,
        "hash_status": "verified" if expected_sha else "hash_pending",
        "installed_dir": str(tool_dir),
        "extracted": [],
    }
    if archive.suffix.lower() == ".zip":
        if tool_dir.exists():
            # Only replace the same managed version; never touch legacy tools.
            shutil.rmtree(tool_dir)
        record["extracted"] = safe_extract(archive, tool_dir)
    else:
        tool_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(archive, tool_dir / archive.name)
        record["extracted"] = [archive.name]
    extracted = record.pop("extracted")
    record["extracted_file_count"] = len(extracted)
    record["extracted_samples"] = extracted[:20]
    manifest["tools"].append(record)
    print(json.dumps(record, ensure_ascii=False), flush=True)

(MANAGED / "tool_release_manifest.json").write_text(
    json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
    encoding="utf-8",
)
print(MANAGED / "tool_release_manifest.json")
