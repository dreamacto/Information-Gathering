"""Compatibility entrypoint for the packaged fingerprint ingest stage."""
from __future__ import annotations
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from authorized_assessment.artifacts.fingerprint_ingest import *  # noqa: F401,F403,E402
from authorized_assessment.artifacts import fingerprint_ingest as _impl

# Keep legacy module-level overrides working for existing callers and tests.
LIB_PATH = _impl.LIB_PATH
VIEW_DIR = _impl.VIEW_DIR


def _sync_legacy_paths() -> None:
    _impl.LIB_PATH = LIB_PATH
    _impl.VIEW_DIR = VIEW_DIR


def load_library():
    _sync_legacy_paths()
    return _impl.load_library()


def main(argv=None):
    _sync_legacy_paths()
    return _impl.main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
