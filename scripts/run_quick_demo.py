#!/usr/bin/env python
"""Quick AGHC-S128 reproduction demo (no Google Colab required).

Usage (from the repository root):

    python scripts/run_quick_demo.py [--config configs/quick_demo.yaml]

Runs encrypt -> decrypt -> round-trip verification -> Mode A statistical
metrics -> histogram/entropy figures, writing logs/tables/figures under
``results/example_outputs/``.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _bootstrap  # noqa: F401,E402

from aghc_s128.experiments import load_config, run_quick_demo  # noqa: E402


def main() -> int:
    default_config = Path(__file__).resolve().parents[1] / "configs" / "quick_demo.yaml"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config", type=Path, default=default_config, help="experiment YAML config"
    )
    args = parser.parse_args()

    config = load_config(args.config)
    payload = run_quick_demo(config)
    print()
    print(f"round trip ok : {payload.get('round_trip_ok')}")
    for key, value in payload.get("outputs", {}).items():
        print(f"{key:<14}: {value}")
    if not payload.get("round_trip_ok"):
        print("ERROR: round trip failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
