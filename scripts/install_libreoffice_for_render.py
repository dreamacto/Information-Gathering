from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.request import Request, urlopen

os.environ["PYTHONUTF8"] = "1"
os.environ["PYTHONIOENCODING"] = "utf-8"
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

VERSION = "26.2.4"
FILENAME = f"LibreOffice_{VERSION}_Win_x86-64.msi"
SOURCE_URL = f"https://download.documentfoundation.org/libreoffice/stable/{VERSION}/win/x86_64/{FILENAME}"
MIN_EXPECTED_BYTES = 300 * 1024 * 1024


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download_file(url: str, dest: Path, force: bool = False) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and dest.stat().st_size >= MIN_EXPECTED_BYTES and not force:
        print(f"download_exists {dest} bytes={dest.stat().st_size}")
        return
    tmp = dest.with_suffix(dest.suffix + ".part")
    if tmp.exists():
        tmp.unlink()
    request = Request(url, headers={"User-Agent": "Codex-LibreOffice-Installer/1.0"})
    print(f"download_start {url}")
    with urlopen(request, timeout=60) as response, tmp.open("wb") as handle:
        total = int(response.headers.get("Content-Length") or 0)
        downloaded = 0
        last_report = time.time()
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            handle.write(chunk)
            downloaded += len(chunk)
            if time.time() - last_report >= 5:
                pct = (downloaded / total * 100) if total else 0.0
                print(f"download_progress bytes={downloaded} total={total} pct={pct:.1f}")
                last_report = time.time()
    size = tmp.stat().st_size
    if size < MIN_EXPECTED_BYTES:
        raise RuntimeError(f"download too small: {size} bytes")
    tmp.replace(dest)
    print(f"download_done {dest} bytes={dest.stat().st_size} sha256={sha256_file(dest)}")


def extract_msi(msi: Path, extract_dir: Path, force: bool = False) -> Path:
    soffice = extract_dir / "program" / "soffice.exe"
    if soffice.exists() and not force:
        print(f"extract_exists {soffice}")
        return soffice
    if extract_dir.exists() and force:
        shutil.rmtree(extract_dir)
    extract_dir.mkdir(parents=True, exist_ok=True)
    msiexec = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "msiexec.exe"
    if not msiexec.exists():
        msiexec = Path("msiexec.exe")
    cmd = [
        str(msiexec),
        "/a",
        str(msi.resolve()),
        f"TARGETDIR={extract_dir.resolve()}",
        "/qn",
        "/norestart",
    ]
    print("extract_start " + json.dumps(cmd, ensure_ascii=False))
    proc = subprocess.run(cmd, text=True, encoding="utf-8", errors="replace", capture_output=True)
    print(f"extract_returncode {proc.returncode}")
    if proc.stdout.strip():
        print("extract_stdout " + proc.stdout.strip()[:2000])
    if proc.stderr.strip():
        print("extract_stderr " + proc.stderr.strip()[:2000])
    if proc.returncode != 0:
        raise RuntimeError(f"msiexec administrative extract failed: {proc.returncode}")
    matches = sorted(extract_dir.glob("**/soffice.exe"))
    if not matches:
        raise RuntimeError(f"soffice.exe not found under {extract_dir}")
    print(f"extract_done {matches[0]}")
    return matches[0]


def console_soffice_for(soffice: Path) -> Path:
    console = soffice.with_suffix(".com")
    return console if console.exists() else soffice


def probe_soffice(soffice: Path) -> tuple[Path, str]:
    probe_exe = console_soffice_for(soffice)
    env = os.environ.copy()
    env["PATH"] = str(probe_exe.parent) + os.pathsep + env.get("PATH", "")
    proc = subprocess.run(
        [str(probe_exe), "--version"],
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=90,
        env=env,
    )
    output = (proc.stdout or proc.stderr).strip()
    print(f"soffice_version_rc {proc.returncode}")
    print(f"soffice_version {output}")
    if proc.returncode != 0:
        raise RuntimeError("soffice --version failed")
    return probe_exe, output


def main() -> int:
    parser = argparse.ArgumentParser(description="Install project-local LibreOffice for DOCX render QA")
    parser.add_argument("--root", type=Path, default=Path("tools") / "libreoffice")
    parser.add_argument("--force-download", action="store_true")
    parser.add_argument("--force-extract", action="store_true")
    args = parser.parse_args()

    root = args.root.resolve()
    download_dir = root / "downloads"
    extract_dir = root / f"LibreOffice_{VERSION}"
    msi = download_dir / FILENAME
    download_file(SOURCE_URL, msi, force=args.force_download)
    soffice = extract_msi(msi, extract_dir, force=args.force_extract)
    console_soffice, version_text = probe_soffice(soffice)
    manifest = {
        "installed_at": now_iso(),
        "version": VERSION,
        "source_url": SOURCE_URL,
        "msi": str(msi),
        "msi_sha256": sha256_file(msi),
        "extract_dir": str(extract_dir),
        "soffice": str(soffice),
        "soffice_console": str(console_soffice),
        "soffice_program_dir": str(soffice.parent),
        "soffice_version": version_text,
        "install_mode": "project_local_msi_administrative_extract",
    }
    manifest_path = root / "libreoffice_render_manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"manifest {manifest_path}")
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
