"""Package facade for bounded authenticated review and auth handoff."""
from __future__ import annotations
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from authenticated_session_review import *  # noqa: F401,F403,E402
