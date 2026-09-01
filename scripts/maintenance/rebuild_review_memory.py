#!/usr/bin/env python3
"""Rebuild review-memory JSONL files from an explicit feedback input."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from authorized_assessment.analysis.review_feedback_ingest import ingest_feedback


def read_rows(path: Path) -> list[dict]:
    rows = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            rows.append(value)
    return rows


def rebuild(input_path: Path, knowledge_base_dir: Path) -> dict:
    """Replace derived memory from explicit input while preserving no external state."""
    kb = knowledge_base_dir.resolve()
    kb.mkdir(parents=True, exist_ok=True)
    feedback_path = kb / "review_feedback.jsonl"
    for derived in (feedback_path, kb / "false_positive_patterns.jsonl", kb / "fingerprint_precision.jsonl"):
        if derived.exists():
            derived.unlink()
    return ingest_feedback(read_rows(input_path), kb)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="explicit feedback JSONL")
    parser.add_argument("--knowledge-base", type=Path, required=True, help="output knowledge-base directory")
    args = parser.parse_args(argv)
    if not args.input.is_file():
        parser.error(f"input does not exist: {args.input}")
    result = rebuild(args.input, args.knowledge_base)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
