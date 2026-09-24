#!/usr/bin/env python
"""Mode A statistical evaluation over binary inputs.

Usage (from the repository root):

    export AGHC_PASSWORD='...'          # or edit the config's demo password
    python scripts/run_binary_experiments.py [--config CONFIG] [--input FILE ...]

Config default: configs/binary_experiments.yaml.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _bootstrap  # noqa: F401,E402

from aghc_s128.experiments import load_config, run_binary_experiments  # noqa: E402


def main() -> int:
    default_config = (
        Path(__file__).resolve().parents[1] / "configs" / "binary_experiments.yaml"
    )
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=default_config)
    parser.add_argument(
        "--input",
        type=Path,
        action="append",
        default=None,
        help="override config inputs (repeatable)",
    )
    parser.add_argument("--n", type=int, default=None, help="override n_input")
    args = parser.parse_args()

    config = load_config(args.config)
    if args.input:
        config["inputs"] = [str(p) for p in args.input]
    if args.n is not None:
        config["n_input"] = args.n

    payload = run_binary_experiments(config)
    runs = payload.get("runs", [])
    failed = [r for r in runs if not r["round_trip_ok"]]
    print(f"\ninputs processed : {len(runs)}")
    print(f"round trips ok   : {len(runs) - len(failed)}/{len(runs)}")
    for key, value in payload.get("outputs", {}).items():
        print(f"{key:<16}: {value}")
    if failed:
        print("ERROR: round trip failed for some inputs", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
