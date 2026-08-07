#!/usr/bin/env python3
"""Runtime helpers for controlled exercise workflows.

This module intentionally avoids importing the legacy config.py because that
file may be encoded incorrectly on some machines. Keep this layer boring and
predictable: paths, target parsing, run directories, and audit records.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, Sequence
from urllib.parse import urlparse


BASE_DIR = Path(__file__).resolve().parent
RUNS_DIR = BASE_DIR / "runs"
DEFAULT_CONFIG = BASE_DIR / "gov_exercise_config.json"

HEADER_TOKENS = {
    "url",
    "target",
    "targets",
    "host",
    "domain",
    "靶标url",
    "目标url",
    "网址",
    "域名",
}


@dataclass(frozen=True)
class Target:
    url: str
    name: str = ""
    host: str = ""
    scheme: str = ""
    port: int | None = None
    source_line: int = 0


@dataclass
class CommandRecord:
    timestamp: str
    purpose: str
    command: list[str]
    cwd: str
    returncode: int | None
    duration_seconds: float
    stdout_file: str
    stderr_file: str


def now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def read_json(path: Path) -> dict:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")


def append_jsonl(path: Path, item: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(item, ensure_ascii=False, sort_keys=True))
        f.write("\n")


def normalize_url(raw: str) -> str:
    raw = raw.strip().strip('"').strip("'")
    if not raw:
        return ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = "https://" + raw
    parsed = urlparse(raw)
    scheme = parsed.scheme.lower() or "https"
    host = (parsed.hostname or "").lower()
    if not host:
        return ""
    netloc = host
    try:
        port = parsed.port
    except ValueError:
        return ""
    if port:
        netloc = f"{host}:{parsed.port}"
    path = parsed.path or ""
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{scheme}://{netloc}{path}{query}"


def is_header_like_target(value: str) -> bool:
    cleaned = value.strip().strip('"').strip("'").strip().lower()
    compact = re.sub(r"[\s_:/\\|,\-]+", "", cleaned)
    if cleaned in HEADER_TOKENS or compact in HEADER_TOKENS:
        return True
    # Some copied spreadsheet headers arrive mojibaked, e.g. "靶标URL" can
    # become non-ASCII text ending in URL. Do not treat that as a live target.
    return "url" in compact and "." not in compact and not re.match(r"^[a-z][a-z0-9+.-]*://", cleaned)


def split_target_line(line: str) -> tuple[str, str]:
    if "|" in line:
        parts = [p.strip() for p in line.split("|")]
        return parts[0], parts[1] if len(parts) > 1 else ""
    if "," in line:
        try:
            row = next(csv.reader([line]))
        except csv.Error:
            row = [line]
        if row:
            return row[0].strip(), row[1].strip() if len(row) > 1 else ""
    return line.strip(), ""


def parse_target_line(line: str, line_no: int) -> Target | None:
    line = line.strip().lstrip("\ufeff")
    if not line or line.startswith("#"):
        return None
    raw_url, raw_name = split_target_line(line)
    if is_header_like_target(raw_url):
        return None
    url = normalize_url(raw_url)
    if not url:
        return None
    name = repair_mojibake(raw_name)
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if not host or is_header_like_target(host):
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    return Target(
        url=url,
        name=name,
        host=host,
        scheme=parsed.scheme.lower(),
        port=port,
        source_line=line_no,
    )


def repair_mojibake(value: str) -> str:
    """Best-effort repair for common UTF-8 text decoded as cp1252/gbk chains."""
    if not value:
        return value
    markers = ("Ã", "Â", "å", "æ", "ç", "è", "é", "涓", "骞", "鍖", "鏌", "鑷")
    if not any(marker in value for marker in markers):
        return value
    candidates = [value]
    transforms = [
        ("latin1", "utf-8"),
        ("cp1252", "utf-8"),
        ("gbk", "utf-8"),
    ]
    for src, dst in transforms:
        try:
            candidates.append(value.encode(src, errors="ignore").decode(dst, errors="ignore"))
        except Exception:
            pass
    return max(candidates, key=score_readable_text)


def score_readable_text(value: str) -> int:
    score = 0
    for ch in value:
        code = ord(ch)
        if 0x4E00 <= code <= 0x9FFF:
            score += 3
        elif ch.isascii() and (ch.isalnum() or ch in " -_()[]"):
            score += 1
        elif ch in "�\ufffd":
            score -= 5
    bad_markers = ("Ã", "Â", "å", "æ", "ç", "è", "é", "涓", "骞", "鍖", "鏌", "鑷")
    score -= sum(value.count(marker) * 2 for marker in bad_markers)
    return score


def load_targets(path: Path) -> list[Target]:
    targets: list[Target] = []
    seen: set[str] = set()
    if path.suffix.lower() == ".csv":
        with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as f:
            reader = csv.DictReader(f)
            for line_no, row in enumerate(reader, 2):
                raw_url = str(row.get("url") or row.get("target") or row.get("targets") or row.get("host") or row.get("domain") or "").strip()
                raw_name = str(row.get("name") or row.get("label") or row.get("organization") or row.get("单位") or "").strip()
                if not raw_url:
                    continue
                target = parse_target_line(f"{raw_url}|{raw_name}", line_no)
                if not target or target.url in seen:
                    continue
                targets.append(target)
                seen.add(target.url)
        return targets
    with path.open("r", encoding="utf-8-sig", errors="replace") as f:
        for line_no, line in enumerate(f, 1):
            target = parse_target_line(line, line_no)
            if not target or target.url in seen:
                continue
            targets.append(target)
            seen.add(target.url)
    return targets


def target_to_dict(target: Target) -> dict:
    return asdict(target)


def target_fingerprint(targets: Sequence[Target]) -> str:
    h = hashlib.sha256()
    for target in targets:
        h.update(target.url.encode("utf-8", "replace"))
        h.update(b"\n")
    return h.hexdigest()


def create_run_dir(label: str) -> Path:
    safe_label = re.sub(r"[^A-Za-z0-9_.-]+", "_", label).strip("_") or "run"
    run_dir = RUNS_DIR / f"{now_stamp()}_{safe_label}"
    run_dir.mkdir(parents=True, exist_ok=False)
    (run_dir / "logs").mkdir()
    (run_dir / "evidence").mkdir()
    (run_dir / "reports").mkdir()
    return run_dir


def write_targets(run_dir: Path, targets: Sequence[Target], source: Path) -> None:
    write_json(run_dir / "targets.json", {
        "source": str(source),
        "imported_at": now_iso(),
        "count": len(targets),
        "sha256": target_fingerprint(targets),
        "targets": [target_to_dict(t) for t in targets],
    })
    with (run_dir / "targets.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "name", "host", "scheme", "port", "source_line"])
        writer.writeheader()
        for target in targets:
            writer.writerow(target_to_dict(target))


def expand_template(value: str | Path | None, tianhu: Path | None = None) -> str:
    if value is None:
        return ""
    return str(value).replace("{base}", str(BASE_DIR)).replace("{tianhu}", str(tianhu or ""))


def find_executable(candidates: Iterable[str | Path]) -> str | None:
    for candidate in candidates:
        if not candidate:
            continue
        raw = str(candidate)
        found = shutil.which(raw)
        if found:
            return found
        path = Path(raw)
        if path.is_file():
            return str(path)
    return None


def executable_runs(path: str, args: Sequence[str] = ("--version",), timeout: int = 5) -> bool:
    try:
        result = subprocess.run(
            [path, *args],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            timeout=timeout,
            shell=False,
        )
        return result.returncode == 0
    except Exception:
        return False


def find_runnable_executable(candidates: Iterable[str | Path], args: Sequence[str] = ("--version",)) -> str | None:
    for candidate in candidates:
        expanded = find_executable([candidate])
        if expanded and executable_runs(expanded, args=args):
            return expanded
    return None


def default_tianhu_base(config: dict) -> Path | None:
    configured = config.get("tianhu_base") or os.environ.get("TIANHU_BASE")
    candidates: list[Path] = []
    if configured:
        candidates.append(Path(configured))
    user_profile = Path(os.environ.get("USERPROFILE", ""))
    if user_profile:
        desktop = user_profile / "Desktop"
        candidates.extend([
            desktop / "天狐渗透工具箱-社区版V3.0+4.0更新升级包" / "天狐渗透工具箱-社区版V3.0",
            desktop / "天狐渗透工具箱-社区版V3.0",
        ])
    for candidate in candidates:
        if candidate and candidate.exists():
            return candidate
    if candidates:
        return candidates[0]
    return None


def collect_runtime_inventory(config: dict) -> dict:
    tianhu = default_tianhu_base(config)
    python_candidates = [
        expand_template(config.get("python"), tianhu),
        tianhu / "python3" / "python.exe" if tianhu else None,
        BASE_DIR / ".venv" / "Scripts" / "python.exe",
        sys.executable,
        "python",
        "py",
    ]
    java_candidates = [
        expand_template(config.get("java"), tianhu),
        tianhu / "Java_path" / "Java_11_win" / "bin" / "java.exe" if tianhu else None,
        tianhu / "Java_path" / "Java_8_win" / "bin" / "java.exe" if tianhu else None,
        "java",
    ]
    tools = config.get("tools", {})
    resolved_tools = {}
    for name, candidates in tools.items():
        if isinstance(candidates, str):
            candidates = [candidates]
        expanded = []
        for item in candidates:
            expanded.append(expand_template(item, tianhu))
        resolved_tools[name] = find_executable(expanded)
    return {
        "checked_at": now_iso(),
        "base_dir": str(BASE_DIR),
        "tianhu_base": str(tianhu) if tianhu else "",
        "python": find_runnable_executable(python_candidates),
        "java": find_runnable_executable(java_candidates),
        "tools": resolved_tools,
    }


def run_command(
    command: Sequence[str],
    run_dir: Path,
    purpose: str,
    cwd: Path | None = None,
    timeout: int = 600,
) -> CommandRecord:
    started = datetime.now()
    logs = run_dir / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", purpose).strip("_")[:60] or "command"
    stdout_file = logs / f"{now_stamp()}_{slug}.out.txt"
    stderr_file = logs / f"{now_stamp()}_{slug}.err.txt"
    with stdout_file.open("wb") as out, stderr_file.open("wb") as err:
        try:
            result = subprocess.run(
                list(command),
                cwd=str(cwd or BASE_DIR),
                stdout=out,
                stderr=err,
                stdin=subprocess.DEVNULL,
                timeout=timeout,
                shell=False,
            )
            returncode = result.returncode
        except subprocess.TimeoutExpired:
            err.write(f"\nTIMEOUT after {timeout}s\n".encode("utf-8"))
            returncode = None
    elapsed = (datetime.now() - started).total_seconds()
    record = CommandRecord(
        timestamp=now_iso(),
        purpose=purpose,
        command=list(command),
        cwd=str(cwd or BASE_DIR),
        returncode=returncode,
        duration_seconds=elapsed,
        stdout_file=str(stdout_file),
        stderr_file=str(stderr_file),
    )
    append_jsonl(run_dir / "audit_commands.jsonl", asdict(record))
    return record
