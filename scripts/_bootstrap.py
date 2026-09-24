"""Shared bootstrap for scripts/: importable package without installation."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

try:
    import aghc_s128  # noqa: F401
except ImportError:
    sys.path.insert(0, str(REPO_ROOT / "src"))
