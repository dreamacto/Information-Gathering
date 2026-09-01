"""Package facade for the repository-root run health calculator."""
from __future__ import annotations
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from run_health import build_health, build_health_outputs, main, pct, write_markdown  # noqa: E402

__all__ = ["build_health", "build_health_outputs", "main", "pct", "write_markdown"]
