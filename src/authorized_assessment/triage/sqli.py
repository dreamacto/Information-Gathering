"""Package facade for the repository-root SQLi candidate triage stage.

The root module remains the single implementation because existing tests and
callers patch its request adapter by module path.
"""
from __future__ import annotations
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from sqli_triage import *  # noqa: F401,F403,E402
