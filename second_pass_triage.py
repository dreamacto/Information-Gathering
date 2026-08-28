"""Compatibility entrypoint for the packaged second-pass triage stage."""
from __future__ import annotations
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from authorized_assessment.triage.second_pass_triage import *  # noqa: F401,F403,E402
from authorized_assessment.triage.second_pass_triage import main as _main

if __name__ == "__main__":
    raise SystemExit(_main())
