"""Shared pytest configuration.

Makes ``aghc_s128`` importable from ``src/`` (works without installing the
package) and the baseline reference importable from ``tests/``.
"""

from __future__ import annotations

import sys
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
SRC_DIR = REPO_ROOT / "src"

for entry in (str(SRC_DIR), str(TESTS_DIR)):
    if entry not in sys.path:
        sys.path.insert(0, entry)
