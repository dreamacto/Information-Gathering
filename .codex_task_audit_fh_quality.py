from __future__ import annotations

import ast
import csv
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path


os.environ["PYTHONUTF8"] = "1"
os.environ["PYTHONIOENCODING"] = "utf-8"
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


BASE = Path(r"D:\PythonSource\PythonProjects\PythonProject4")
SKILL = BASE / "skill-deliverables" / "fh"
SCRIPT = SKILL / "scripts" / "init_postrun_review.py"
PY = Path(sys.executable)
CHECK = BASE / ".codex_fh_quality_check"


def cleanup() -> None:
    if not CHECK.exists():
        return
    resolved = CHECK.resolve()
    root = BASE.resolve()
    if root not in resolved.parents and resolved != root:
        raise RuntimeError(f"refuse cleanup outside workspace: {resolved}")
    shutil.rmtree(CHECK)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig", errors="replace")


def check_static() -> list[str]:
    issues: list[str] = []
    if "name: fh" not in read_text(SKILL / "SKILL.md").splitlines()[:4]:
        issues.append("SKILL.md frontmatter name is not fh")
    for path in SKILL.glob("scripts/*.py"):
        ast.parse(read_text(path), filename=str(path))
    link_re = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
    for path in SKILL.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in {".md", ".yaml", ".yml"}:
            continue
        for match in link_re.finditer(read_text(path)):
            target = match.group(1).split("#", 1)[0].strip()
            if not target or re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", target):
                continue
            resolved = path.parent / target
            if target.startswith(("references/", "scripts/")):
                resolved = SKILL / target
            if not resolved.exists():
                issues.append(f"broken reference {path.relative_to(SKILL).as_posix()} -> {target}")
    skill_text = read_text(SKILL / "SKILL.md")
    for required in [
        "target_review_queue.csv",
        "Review every row",
        "Concurrency: 1",
        "Delay: at least 3 seconds",
        "explicit approval",
    ]:
        if required not in skill_text:
            issues.append(f"SKILL.md missing required phrase: {required}")
    return issues


def run_init(case: str, run_arg: str, extra: list[str] | None = None) -> tuple[Path, str, list[dict[str, str]], dict]:
    out = CHECK / case
    args = [str(PY), str(SCRIPT)]
    if run_arg:
        args.append(run_arg)
    args.extend(["--output", str(out)])
    if extra:
        args.extend(extra)
    proc = subprocess.run(args, text=True, capture_output=True, shell=False)
    if proc.returncode != 0:
        raise RuntimeError(f"{case} failed: {proc.stdout}{proc.stderr}")
    with (out / "target_review_queue.csv").open("r", encoding="utf-8-sig", newline="") as handle:
        targets = list(csv.DictReader(handle))
    inventory = json.loads((out / "run_inventory.json").read_text(encoding="utf-8-sig"))
    return out, proc.stdout, targets, inventory


def validate_case(case: str, out: Path, stdout: str, targets: list[dict[str, str]], inventory: dict, min_targets: int) -> list[str]:
    issues: list[str] = []
    for rel in [
        "review_plan.md",
        "target_review_queue.csv",
        "target_review_index.md",
        "review_ledger.csv",
        "findings_ledger.csv",
        "approval_gates.md",
        "run_inventory.json",
    ]:
        if not (out / rel).is_file():
            issues.append(f"{case}: missing {rel}")
    if len(targets) < min_targets:
        issues.append(f"{case}: expected at least {min_targets} targets, got {len(targets)}")
    if inventory.get("valuable_target_count") != len(targets):
        issues.append(f"{case}: inventory target count mismatch")
    orders = [int(row["review_order"]) for row in targets]
    if orders != list(range(1, len(targets) + 1)):
        issues.append(f"{case}: target order is not contiguous")
    ids = [row["target_id"] for row in targets]
    duplicates = [item for item, count in Counter(ids).items() if count > 1]
    if duplicates:
        issues.append(f"{case}: duplicate target ids {duplicates[:3]}")
    for row in targets[: min(10, len(targets))]:
        safe_host = re.sub(r"[^a-zA-Z0-9.-]+", "_", row["host"]).strip("._")[:80]
        dossier = out / "target_reviews" / f"{int(row['review_order']):04d}_{safe_host}.md"
        if not dossier.is_file():
            issues.append(f"{case}: missing dossier {dossier.name}")
    plan = read_text(out / "review_plan.md")
    if "Do not randomly sample targets" not in plan:
        issues.append(f"{case}: plan lacks no-sampling instruction")
    if "concurrency=1" not in plan or "delay>=3s" not in plan:
        issues.append(f"{case}: plan lacks low-rate controls")
    return issues


def main() -> int:
    cleanup()
    CHECK.mkdir(parents=True, exist_ok=True)
    issues: list[str] = []
    issues.extend(check_static())
    cases = [
        (
            "parallel",
            r"D:\PythonSource\PythonProjects\PythonProject4\runs\20260805_115051_one_click_subdomains_parallel_b001",
            50,
        ),
        (
            "full",
            r"D:\PythonSource\PythonProjects\PythonProject4\runs\20260804_093323_one_click_full_weak",
            50,
        ),
        (
            "miniapp_extract",
            r"D:\PythonSource\PythonProjects\PythonProject4\runs\20260806_120952_wxapkg_extract",
            0,
        ),
    ]
    for name, run_arg, minimum in cases:
        out, stdout, targets, inventory = run_init(name, run_arg)
        print(f"{name}: {stdout.strip()} targets={len(targets)}")
        issues.extend(validate_case(name, out, stdout, targets, inventory, minimum))
        if name == "miniapp_extract":
            noisy = [
                row["host"] for row in targets
                if any(part in row["host"] for part in ["prototype", "document.", "window.", "console."])
            ]
            if noisy:
                issues.append(f"miniapp_extract: noisy code-like hosts became targets: {noisy[:5]}")

    # Re-run the same output directory with a different run to detect stale target dossiers.
    stale_out, _, first_targets, _ = run_init(
        "stale_output",
        r"D:\PythonSource\PythonProjects\PythonProject4\runs\20260805_115051_one_click_subdomains_parallel_b001",
    )
    _, _, second_targets, _ = run_init(
        "stale_output",
        r"D:\PythonSource\PythonProjects\PythonProject4\runs\20260804_093323_one_click_full_weak",
    )
    dossier_count = len(list((stale_out / "target_reviews").glob("*.md")))
    if dossier_count != len(second_targets):
        issues.append(
            f"stale_output: target_reviews has {dossier_count} files but queue has {len(second_targets)} after rerun"
        )
    if issues:
        print("QUALITY_FAILED")
        for issue in issues:
            print(f"issue={issue}")
        return 1
    print("QUALITY_OK")
    cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
