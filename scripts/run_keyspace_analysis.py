#!/usr/bin/env python
"""MODE C: password key-space and brute-force time estimation (pure math).

Usage (from the repository root):

    python scripts/run_keyspace_analysis.py --charset ascii95 --length 16
    python scripts/run_keyspace_analysis.py --charset-size 62 --length 12 [--json OUT]

This reproduces the notebook's MODE C analysis.  IMPORTANT interpretation
caveat (docs/KNOWN_ISSUES.md): the result estimates the *password alphabet*
search space; the cipher's password-derived perturbation/chaos seeds fold
into a 32-bit numeric seed, so this is NOT the effective key space of the
cipher.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _bootstrap  # noqa: F401,E402

from aghc_s128.experiments import CHARSETS, keyspace_analysis  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--charset",
        choices=sorted(CHARSETS),
        help="named character set",
    )
    group.add_argument("--charset-size", type=int, help="custom alphabet size (>= 2)")
    parser.add_argument("--length", type=int, required=True, help="password length")
    parser.add_argument(
        "--json",
        type=Path,
        default=None,
        help="also write the structured result to this JSON file",
    )
    args = parser.parse_args()

    charset_size = args.charset_size or len(CHARSETS[args.charset])
    result = keyspace_analysis(args.length, charset_size)

    print("=" * 70)
    print("KEY SPACE ANALYSIS (password alphabet estimation)")
    print("=" * 70)
    print(f"password length   : {result['password_length']}")
    print(f"charset size      : {result['charset_size']}")
    print(f"keyspace          : {result['keyspace_scientific']}")
    print(f"entropy           : {result['password_entropy_bits']:.4f} bits")
    print(f"classification    : {result['password_entropy_classification']}")
    print()
    print("brute-force estimates (keyspace / rate):")
    for label, estimate in result["brute_force_estimates"].items():
        print(f"  {label:<24} {estimate['human_readable']}")
    print()
    print(f"caveat: {result['caveat']}")

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        print(f"\nstructured result: {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
