#!/usr/bin/env python
"""Mode A statistical evaluation over image files (+ pixel-correlation figure).

Usage (from the repository root):

    export AGHC_PASSWORD='...'
    python scripts/run_image_experiments.py [--config CONFIG] [--input FILE ...]

Config default: configs/image_experiments.yaml.  Original paper images
(USC-SIPI, MRI, PDF) are NOT redistributed — see data/README.md and
configs/paper_results_mapping.md for how to place them under data/external/.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _bootstrap  # noqa: F401,E402

from aghc_s128.experiments import load_config, run_image_experiments  # noqa: E402


def main() -> int:
    default_config = (
        Path(__file__).resolve().parents[1] / "configs" / "image_experiments.yaml"
    )
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=default_config)
    parser.add_argument("--input", type=Path, action="append", default=None)
    parser.add_argument("--n", type=int, default=None)
    args = parser.parse_args()

    config = load_config(args.config)
    if args.input:
        config["inputs"] = [str(p) for p in args.input]
    if args.n is not None:
        config["n_input"] = args.n

    payload = run_image_experiments(config)
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
