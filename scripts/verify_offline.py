#!/usr/bin/env python3
"""Run safe, offline project checks only.

Interpreter note (operator decision batch6_4 ⑦): the tests check always runs pytest
under sys.executable (no hardcoded .venv path). If pytest is not importable under the
current interpreter, the check fails with an explicit message instead of a confusing
ModuleNotFoundError. Recommended runtime is the project venv (.venv/Scripts/python.exe);
launchers already prefer .venv first.
"""
from __future__ import annotations
import argparse, json, subprocess, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

def run(label, cmd):
    try:
        p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=180)
        return {"name": label, "ok": p.returncode == 0, "returncode": p.returncode, "output": (p.stdout+p.stderr)[-4000:]}
    except Exception as e:
        return {"name": label, "ok": False, "returncode": -1, "output": str(e)}

def pytest_probe():
    try:
        import pytest  # noqa: F401
        return True, ""
    except ImportError:
        return False, sys.executable

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--json',action='store_true'); ap.add_argument('--compile-only',action='store_true'); ap.add_argument('--tests-only',action='store_true'); args=ap.parse_args()
    checks=[]
    if not args.tests_only:
        checks.append(run('compile', [sys.executable,'-m','compileall','-q','policy_engine.py','artifact_manifest.py','deletion_audit.py','tests','scripts']))
        checks.append(run('skill-drift', [sys.executable,'scripts/check_skill_drift.py']))
        checks.append(run('doc-drift', [sys.executable,'scripts/check_doc_drift.py']))
    if not args.compile_only:
        has_pytest, where = pytest_probe()
        if has_pytest:
            checks.append(run('tests', [sys.executable,'-m','pytest','-q']))
        else:
            checks.append({
                "name": "tests",
                "ok": False,
                "returncode": -1,
                "output": (
                    f"pytest is not available under interpreter: {where}. "
                    "Run this script with the project venv (recommended): "
                    ".venv/Scripts/python.exe scripts/verify_offline.py --json"
                ),
            })
    payload={"status":"ok" if all(x['ok'] for x in checks) else "failed", "checks":checks}
    print(json.dumps(payload,ensure_ascii=False,indent=2) if args.json else '\n'.join(f"{'PASS' if x['ok'] else 'FAIL'} {x['name']}" for x in checks))
    return 0 if payload['status']=='ok' else 1
if __name__=='__main__': raise SystemExit(main())
