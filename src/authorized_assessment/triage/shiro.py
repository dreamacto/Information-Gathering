"""Package facade for the root Shiro triage implementation.

The root module remains canonical so its request adapter can continue to be
monkeypatched by existing tests and callers.
"""
from __future__ import annotations
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from shiro_triage import *  # noqa: F401,F403,E402
