import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path


os.environ["PYTHONUTF8"] = "1"
os.environ["PYTHONIOENCODING"] = "utf-8"
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


WORKSPACE = Path(r"D:\PythonSource\PythonProjects\PythonProject4")
RUN_DIR = WORKSPACE / "runs" / "20260728_115448_one_click_full_weak"
DESKTOP_BAT = Path(r"D:\Desktop\一键已有子域名后流程_含弱口令.bat")
FILES = [
    RUN_DIR / "subdomains_dedup.txt",
    RUN_DIR / "subdomains_for_next_run.txt",
    RUN_DIR / "subdomains_for_scope_confirmation.txt",
    RUN_DIR / "targets_with_auto_subdomains.txt",
]


def decode_bytes(raw: bytes) -> tuple[str, str]:
    for encoding in ("utf-8-sig", "utf-8", "gb18030", "cp936"):
        try:
            return raw.decode(encoding), encoding
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace"), "utf-8-replace"


def summarize_text_file(path: Path) -> dict:
    raw = path.read_bytes()
    text, encoding = decode_bytes(raw)
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return {
        "path": str(path),
        "exists": path.exists(),
        "size": len(raw),
        "encoding": encoding,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "nonempty_lines": len(lines),
        "unique_lines": len(dict.fromkeys(lines)),
        "first_five": lines[:5],
        "contains_pipe": sum("|" in line for line in lines),
        "contains_http": sum(line.lower().startswith(("http://", "https://")) for line in lines),
        "contains_space": sum(any(char.isspace() for char in line) for line in lines),
    }


def main() -> int:
    summaries = []
    for path in FILES:
        if path.exists():
            summaries.append(summarize_text_file(path))
        else:
            summaries.append({"path": str(path), "exists": False})

    bat_summary = {"path": str(DESKTOP_BAT), "exists": DESKTOP_BAT.exists()}
    if DESKTOP_BAT.exists():
        raw = DESKTOP_BAT.read_bytes()
        text, encoding = decode_bytes(raw)
        bat_summary.update(
            {
                "size": len(raw),
                "encoding": encoding,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "text": text,
            }
        )

    rg = subprocess.run(
        ["rg", "--files", "-g", "*.bat", str(WORKSPACE)],
        cwd=WORKSPACE,
        shell=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    matching = [
        line
        for line in rg.stdout.splitlines()
        if "子域名" in line or "完整流程" in line or "弱口令" in line
    ]
    print(
        json.dumps(
            {
                "target_files": summaries,
                "desktop_bat": bat_summary,
                "matching_workspace_bats": matching,
                "rg_returncode": rg.returncode,
                "rg_stderr": rg.stderr,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
