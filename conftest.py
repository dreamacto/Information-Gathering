"""Test path setup: make src/ packages importable alongside root modules.

Root-level compatibility modules resolve through CWD (python -m pytest);
src/authorized_assessment.* packages need src/ on sys.path.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
