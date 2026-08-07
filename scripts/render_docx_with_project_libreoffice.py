from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

os.environ["PYTHONUTF8"] = "1"
os.environ["PYTHONIOENCODING"] = "utf-8"
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def find_soffice(root: Path) -> Path:
    manifest = root / "tools" / "libreoffice" / "libreoffice_render_manifest.json"
    if manifest.exists():
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
            program_dir = Path(data["soffice_program_dir"])
            candidate = program_dir / "soffice.com"
            if candidate.exists():
                return candidate
        except Exception:
            pass
    matches = sorted((root / "tools" / "libreoffice").glob("**/program/soffice.com"))
    if matches:
        return matches[0]
    raise FileNotFoundError("tools/libreoffice/**/program/soffice.com not found")


def run(cmd: list[str], env: dict[str, str], timeout: int = 240) -> subprocess.CompletedProcess:
    proc = subprocess.run(cmd, text=True, encoding="utf-8", errors="replace", capture_output=True, env=env, timeout=timeout)
    print("cmd " + json.dumps(cmd, ensure_ascii=False))
    print(f"returncode {proc.returncode}")
    if proc.stdout.strip():
        print("stdout " + proc.stdout.strip()[-4000:])
    if proc.stderr.strip():
        print("stderr " + proc.stderr.strip()[-4000:])
    if proc.returncode != 0:
        raise RuntimeError(f"command failed: {proc.returncode}")
    return proc


def convert_docx_to_pdf(docx: Path, output_dir: Path, soffice: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["PATH"] = str(soffice.parent) + os.pathsep + env.get("PATH", "")
    with tempfile.TemporaryDirectory(prefix="lo_profile_") as profile:
        cmd = [
            str(soffice),
            "--headless",
            "--nologo",
            "--nofirststartwizard",
            "--nodefault",
            "--norestore",
            f"-env:UserInstallation=file:///{Path(profile).as_posix()}",
            "--convert-to",
            "pdf",
            "--outdir",
            str(output_dir.resolve()),
            str(docx.resolve()),
        ]
        run(cmd, env=env, timeout=300)
    pdf = output_dir / (docx.stem + ".pdf")
    if not pdf.exists() or pdf.stat().st_size <= 0:
        raise RuntimeError(f"PDF not created: {pdf}")
    return pdf


def find_pdftoppm() -> str | None:
    candidates = [
        r"C:\Users\ASUS\.cache\codex-runtimes\codex-primary-runtime\dependencies\native\poppler\Library\bin\pdftoppm.exe",
        r"C:\Users\ASUS\.cache\codex-runtimes\codex-primary-runtime\dependencies\bin\override\pdftoppm.exe",
        r"C:\Users\ASUS\.cache\codex-runtimes\codex-primary-runtime\dependencies\bin\fallback\pdftoppm.exe",
        shutil.which("pdftoppm.exe"),
        shutil.which("pdftoppm"),
    ]
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return candidate
    return None


def convert_pdf_to_png(pdf: Path, output_dir: Path, dpi: int) -> list[Path]:
    pdftoppm = find_pdftoppm()
    if not pdftoppm:
        print("pdftoppm_not_found")
        return []
    prefix = output_dir / "page"
    env = os.environ.copy()
    run([pdftoppm, "-r", str(dpi), "-png", str(pdf.resolve()), str(prefix.resolve())], env=env, timeout=300)
    pages = sorted(output_dir.glob("page-*.png"))
    print(f"png_pages {len(pages)}")
    return pages


def main() -> int:
    parser = argparse.ArgumentParser(description="Render DOCX via project-local LibreOffice soffice.com")
    parser.add_argument("docx", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--dpi", type=int, default=144)
    args = parser.parse_args()
    root = Path.cwd().resolve()
    soffice = find_soffice(root)
    print(f"soffice {soffice}")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    pdf = convert_docx_to_pdf(args.docx, args.output_dir, soffice)
    pages = convert_pdf_to_png(pdf, args.output_dir, args.dpi)
    print(json.dumps({
        "docx": str(args.docx),
        "pdf": str(pdf),
        "pages": [str(p) for p in pages],
        "page_count": len(pages),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
