"""Compatibility entrypoint for the packaged deletion audit implementation."""
from __future__ import annotations
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from authorized_assessment.artifacts.deletion_audit import *  # noqa: F401,F403,E402
