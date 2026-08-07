from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import zipfile
from datetime import datetime
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(r"D:\PythonSource\PythonProjects\PythonProject4")
MANAGED = ROOT / "tools" / "managed"
STATE = MANAGED / "_validation_state"
STATE.mkdir(parents=True, exist_ok=True)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def version(executable: Path, args: list[str]) -> dict:
    env = os.environ.copy()
    env.update({
        "PYTHONUTF8": "1",
        "PYTHONIOENCODING": "utf-8",
        "HOME": str(STATE),
        "USERPROFILE": str(STATE),
        "APPDATA": str(STATE / "AppData" / "Roaming"),
        "LOCALAPPDATA": str(STATE / "AppData" / "Local"),
    })
    try:
        process = subprocess.run(
            [str(executable), *args], cwd=STATE, env=env, shell=False,
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15,
        )
        output = "\n".join(part.strip() for part in (process.stdout, process.stderr) if part.strip())
        return {"returncode": process.returncode, "output": output[:1000]}
    except Exception as exc:
        return {"returncode": None, "error": f"{type(exc).__name__}: {exc}"}


specs = [
    {
        "name": "nuclei", "version": "3.8.0",
        "path": MANAGED / "nuclei" / "3.8.0" / "nuclei.exe",
        "release": "https://github.com/projectdiscovery/nuclei/releases/tag/v3.8.0",
        "args": ["-version", "-duc"],
    },
    {
        "name": "httpx", "version": "1.9.0",
        "path": MANAGED / "httpx" / "1.9.0" / "httpx.exe",
        "release": "https://github.com/projectdiscovery/httpx/releases/tag/v1.9.0",
        "args": ["-version"],
    },
    {
        "name": "katana", "version": "1.6.1",
        "path": MANAGED / "katana" / "1.6.1" / "katana.exe",
        "release": "https://github.com/projectdiscovery/katana/releases/tag/v1.6.1",
        "args": ["-version"],
    },
    {
        "name": "afrog", "version": "3.5.3",
        "path": MANAGED / "afrog" / "3.5.3" / "afrog.exe",
        "release": "https://github.com/zan8in/afrog/releases/tag/v3.5.3",
        "args": ["-version"],
    },
    {
        "name": "shiroattack2", "version": "5.1.1",
        "path": MANAGED / "shiroattack2" / "5.1.1" / "shiro_attack-5.1.1-zulu-8-jfx.jar",
        "release": "https://github.com/SummerSec/ShiroAttack2/releases/tag/v5.1.1",
        "args": None,
    },
]

records = []
for spec in specs:
    path = spec["path"]
    record = {key: value for key, value in spec.items() if key not in {"path", "args"}}
    record.update({"path": str(path), "installed": path.is_file()})
    if path.is_file():
        record.update({"bytes": path.stat().st_size, "sha256": digest(path)})
        if spec["args"] is not None:
            record["version_check"] = version(path, spec["args"])
        else:
            record["archive_integrity"] = zipfile.is_zipfile(path)
    records.append(record)

template_root = MANAGED / "nuclei-templates" / "10.4.4"
template_files = list(template_root.rglob("*.yaml")) + list(template_root.rglob("*.yml"))
records.append({
    "name": "nuclei-templates",
    "version": "10.4.4",
    "path": str(template_root),
    "installed": template_root.is_dir() and bool(template_files),
    "template_file_count": len(template_files),
    "release": "https://github.com/projectdiscovery/nuclei-templates/releases/tag/v10.4.4",
})

inventory = {
    "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
    "validation_mode": "offline_version_and_archive_checks_only; no target execution",
    "tools": records,
}
(MANAGED / "managed_inventory.json").write_text(json.dumps(inventory, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(json.dumps(inventory, ensure_ascii=False, indent=2))
