from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
RUNS_DIR = BASE_DIR / "runs"
MINIAPP_BURP_DIR_NAME = "07_小程序Burp导入结果"
RUN_NAME_RE = re.compile(r"^(\d{8})_(\d{6})")


def safe_burp_label(path: Path) -> str:
    raw = path.stem or "小程序Burp"
    return re.sub(r"[^A-Za-z0-9_.\-\u4e00-\u9fff]+", "_", raw).strip("._-")[:80] or "小程序Burp"


def result_dir_for_export(run_dir: Path, export_path: Path) -> Path:
    return run_dir / MINIAPP_BURP_DIR_NAME / f"{safe_burp_label(export_path)}_导入结果"


def setup_console() -> None:
    os.environ.setdefault("PYTHONUTF8", "1")
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Import a Burp mini-program export into the latest one-click run")
    parser.add_argument("--burp-export", type=Path, required=True, help="Burp HTTP history XML/TXT export path, or a TXT pasted from copied HTTP history rows")
    parser.add_argument("--run-dir", type=Path, default=None, help="Override latest run directory")
    parser.add_argument("--delay", type=float, default=3.0, help="Delay for optional read-only API confirm")
    parser.add_argument("--no-api-confirm", action="store_true", help="Only import Burp URLs; do not run API confirm")
    return parser.parse_args()


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8", errors="replace"))


def run_sort_key(path: Path) -> tuple[int, str]:
    match = RUN_NAME_RE.match(path.name)
    if match:
        return int(match.group(1) + match.group(2)), path.name
    try:
        return int(path.stat().st_mtime), path.name
    except OSError:
        return 0, path.name


def run_candidates() -> list[Path]:
    if not RUNS_DIR.exists():
        return []
    return [
        path for path in RUNS_DIR.iterdir()
        if path.is_dir() and (path / "targets.json").exists()
    ]


def find_latest_run() -> tuple[Path, str]:
    candidates = run_candidates()
    if not candidates:
        raise SystemExit("找不到最近一次流程目录。请先运行桌面的一键完整流程或一键已有子域名后流程。")

    one_click = [path for path in candidates if "one_click" in path.name.lower()]
    if one_click:
        return max(one_click, key=run_sort_key), "latest_one_click_run_by_folder_timestamp"

    latest_by_name = max(candidates, key=run_sort_key)
    marker = RUNS_DIR / "last_one_click_run.txt"
    if marker.exists():
        candidate = Path(marker.read_text(encoding="utf-8", errors="replace").strip().strip('"'))
        if candidate.exists() and (candidate / "targets.json").exists():
            if run_sort_key(candidate) >= run_sort_key(latest_by_name):
                return candidate, "last_one_click_run_marker"
    return latest_by_name, "latest_run_by_folder_timestamp"


def target_file_for_run(run_dir: Path) -> Path:
    targets_json = run_dir / "targets.json"
    data = read_json(targets_json)
    source = Path(str(data.get("source") or ""))
    if source.exists() and source.is_file():
        return source
    rows = []
    for item in data.get("targets", []):
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "").strip()
        name = str(item.get("name") or "").strip()
        if not url:
            continue
        rows.append(f"{url}|{name}" if name else url)
    if not rows:
        raise SystemExit(f"无法从 {targets_json} 还原目标文件。")
    restored = run_dir / "resume_targets_from_run.local.txt"
    restored.write_text("\n".join(rows) + "\n", encoding="utf-8")
    return restored


def main() -> int:
    setup_console()
    args = parse_args()
    burp_export = args.burp_export.expanduser().resolve()
    if not burp_export.exists() or not burp_export.is_file():
        print(f"[!] Burp 导出文件不存在: {burp_export}", file=sys.stderr)
        return 2
    if args.run_dir:
        run_dir = args.run_dir.expanduser().resolve()
        selection_reason = "manual_run_dir"
    else:
        found_run, selection_reason = find_latest_run()
        run_dir = found_run.resolve()
    if not run_dir.exists() or not (run_dir / "targets.json").exists():
        print(f"[!] 流程目录无效: {run_dir}", file=sys.stderr)
        return 2
    targets = target_file_for_run(run_dir)

    print("[*] 小程序 Burp 导入到最近一次流程")
    print(f"[*] 最近流程目录: {run_dir}")
    print(f"[*] 选择原因: {selection_reason}")
    print(f"[*] 目标文件: {targets}")
    print(f"[*] Burp 导出: {burp_export}")
    print("[*] 行为: 导入 URL、区分范围内/待确认域名、追加安全 GET 候选到主流程")
    print("[*] 支持: Burp XML、普通 URL 列表、Raw HTTP 请求、从 HTTP history 复制后粘贴保存的 TXT")
    if args.no_api_confirm:
        print("[*] API 确认: 跳过")
    else:
        print(f"[*] API 确认: 启用，低频 GET，只确认范围内安全候选，delay={args.delay}s")
    print("")

    cmd = [
        sys.executable,
        str(BASE_DIR / "gov_exercise_runner.py"),
        "--targets",
        str(targets),
        "--resume-run-dir",
        str(run_dir),
        "--miniapp-burp-export",
        str(burp_export),
        "--delay",
        str(args.delay),
    ]
    if not args.no_api_confirm:
        cmd.append("--api-confirm")
    proc = subprocess.run(cmd, cwd=BASE_DIR, text=True, encoding="utf-8", errors="replace", capture_output=True)
    if proc.stdout:
        print(proc.stdout)
    if proc.stderr:
        print(proc.stderr, file=sys.stderr)
    if proc.returncode != 0:
        print(f"[!] 导入失败，returncode={proc.returncode}", file=sys.stderr)
        return proc.returncode

    result_dir = result_dir_for_export(run_dir, burp_export)
    print("[*] 导入完成，这次小程序 Burp 导入结果在这个目录：")
    print(f"    {result_dir}")
    print("[*] 进去后优先看：")
    print("    1. 小程序人工搜索与Burp导入.md")
    print("    2. burp_miniapp_in_scope_api_candidates.jsonl")
    print("    3. burp_miniapp_new_assets_pending.txt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
