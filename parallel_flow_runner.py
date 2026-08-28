"""Compatibility entrypoint for the packaged parallel workflow launcher."""
from __future__ import annotations
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from authorized_assessment.orchestration.parallel_flow_runner import *  # noqa: F401,F403,E402
from authorized_assessment.orchestration.parallel_flow_runner import main as _main

if __name__ == "__main__":
    raise SystemExit(_main())
