#!/usr/bin/env python
"""Validate the local environment: versions, imports, algorithm self-check.

Usage (from the repository root):

    python scripts/validate_environment.py

Equivalent to ``aghc-s128 validate`` but runnable without installing the
package.  Exits 0 when every check passes.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _bootstrap  # noqa: F401,E402

from aghc_s128.cli import main as cli_main  # noqa: E402


def main() -> int:
    print("machine-readable environment summary (JSON) follows on stderr")
    from aghc_s128.metadata import runtime_environment_summary

    print(json.dumps(runtime_environment_summary(), indent=2), file=sys.stderr)
    return cli_main(["validate"])


if __name__ == "__main__":
    sys.exit(main())
