"""Compatibility entrypoint for the packaged healthcare privacy triage stage."""
from __future__ import annotations
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from authorized_assessment.analysis.healthcare_privacy_triage import (  # noqa: E402
    _safe_url,
    build_triage,
    write_outputs,
)


if __name__ == "__main__":
    from authorized_assessment.analysis.healthcare_privacy_triage import main as _main
    raise SystemExit(_main())
