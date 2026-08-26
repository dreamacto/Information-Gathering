#!/usr/bin/env python3
"""Compare canonical .agents skills with client copies."""
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL_FILES = {".md", ".yaml", ".yml", ".py"}

def files(root: Path) -> dict[str, str]:
    result = {}
    for p in root.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in SKILL_FILES or "__pycache__" in p.parts:
            continue
        rel = p.relative_to(root).as_posix()
        result[rel] = hashlib.sha256(p.read_bytes()).hexdigest()
    return result

def compare(canonical: dict[str, str], other: dict[str, str]) -> dict[str, list[str]]:
    return {"missing": sorted(set(canonical)-set(other)), "extra": sorted(set(other)-set(canonical)),
            "changed": sorted(k for k in set(canonical)&set(other) if canonical[k] != other[k])}

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    canonical = files(ROOT / ".agents" / "skills")
    # authorized-pentest-workflow is a project-only policy reference, not a client copy.
    canonical = {k: v for k, v in canonical.items() if not k.startswith("authorized-pentest-workflow/")}
    result = {name: compare(canonical, files(ROOT / name / "skills")) for name in (".claude", ".opencode")}
    ok = all(not any(values.values()) for values in result.values())
    payload = {"canonical": ".agents/skills", "files": len(canonical), "comparisons": result, "status": "ok" if ok else "drift"}
    print(json.dumps(payload, ensure_ascii=False, indent=2) if args.json else json.dumps(payload, ensure_ascii=False))
    return 0 if ok else 1
if __name__ == "__main__":
    raise SystemExit(main())
