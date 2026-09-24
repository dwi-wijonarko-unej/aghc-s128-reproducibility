#!/usr/bin/env python
"""Mode B key-sensitivity experiment: one plaintext, two passwords.

Usage (from the repository root):

    export AGHC_PASSWORD_A='...'
    export AGHC_PASSWORD_B='...'
    python scripts/run_key_sensitivity.py [--config CONFIG]

Config default: configs/key_sensitivity.yaml.  Without the environment
variables the config's demo passwords are used (public test vectors).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _bootstrap  # noqa: F401,E402

from aghc_s128.experiments import load_config, run_key_sensitivity  # noqa: E402


def main() -> int:
    default_config = (
        Path(__file__).resolve().parents[1] / "configs" / "key_sensitivity.yaml"
    )
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=default_config)
    parser.add_argument("--input", type=Path, default=None)
    parser.add_argument("--n", type=int, default=None)
    args = parser.parse_args()

    config = load_config(args.config)
    if args.input is not None:
        config["input"] = str(args.input)
    if args.n is not None:
        config["n_input"] = args.n

    payload = run_key_sensitivity(config)
    print()
    for key, value in payload["metrics"].items():
        print(f"{key:<40}: {value:.4f}")
    for key, value in payload.get("outputs", {}).items():
        print(f"{key:<16}: {value}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
