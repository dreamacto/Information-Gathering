"""Package facade for the repository-root run health calculator."""
from __future__ import annotations
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from run_health import *  # noqa: F401,F403,E402
