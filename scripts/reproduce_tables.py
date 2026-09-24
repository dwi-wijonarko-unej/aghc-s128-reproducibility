#!/usr/bin/env python
"""Aggregate ``results/logs/*.json`` into flat CSV tables.

Usage (from the repository root):

    python scripts/reproduce_tables.py [--logs-dir results/logs]
                                       [--out results/tables/reproduced_summary.csv]

Each experiment runner writes a structured JSON log; this script flattens
them into one row per (run, input) with the paper-relevant metric columns.
Numbers are only ever *recorded run outputs* — never invented placeholders;
runs whose inputs were unavailable simply do not appear.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

COLUMNS = [
    "log_file",
    "kind",
    "started_utc",
    "input",
    "size_bytes",
    "n_input",
    "effective_n",
    "trial_index",
    "round_trip_ok",
    "entropy_original",
    "entropy_encrypted",
    "adjacent_byte_correlation_original",
    "adjacent_byte_correlation_encrypted",
    "npcr_plain_vs_cipher_percent",
    "uaci_plain_vs_cipher_percent",
    "bit_difference_ratio_plain_vs_cipher_percent",
    "chi_square_encrypted",
    "chi_square_p_value_encrypted",
    "monobit_p_value_encrypted",
    "monobit_verdict_encrypted",
    "encryption_time_seconds",
    "decryption_time_seconds",
]


def iter_rows(logs_dir: Path):
    for log_file in sorted(logs_dir.glob("*.json")):
        try:
            payload = json.loads(log_file.read_text())
        except json.JSONDecodeError as exc:
            print(f"warning: skipping invalid log {log_file}: {exc}", file=sys.stderr)
            continue

        kind = payload.get("kind", "unknown")
        metrics = payload.get("metrics") or {}
        if metrics:
            # single-run records (quick_demo, key_sensitivity)
            if "input" in payload and isinstance(payload["input"], dict):
                yield _row(
                    log_file, payload, kind,
                    input_path=payload["input"].get("path", ""),
                    size=payload["input"].get("size_bytes"),
                    n=payload.get("encryption", {}).get("n_input"),
                    effective_n=payload.get("encryption", {}).get("effective_n"),
                    trial=payload.get("encryption", {}).get("trial_index"),
                    round_trip=payload.get("round_trip_ok"),
                    metrics=metrics,
                )
            elif kind == "key_sensitivity":
                yield _row(
                    log_file, payload, kind,
                    input_path=payload.get("input", {}).get("path", ""),
                    size=payload.get("input", {}).get("size_bytes"),
                    n=payload.get("config", {}).get("n_input"),
                    effective_n=None,
                    trial=payload.get("ciphertext_a", {}).get("trial_index"),
                    round_trip=None,
                    metrics=metrics,
                )
            continue

        for run in payload.get("runs", []):
            yield _row(
                log_file, payload, kind,
                input_path=run.get("input", ""),
                size=run.get("size_bytes"),
                n=run.get("n_input"),
                effective_n=run.get("effective_n"),
                trial=run.get("trial_index"),
                round_trip=run.get("round_trip_ok"),
                metrics=run.get("metrics", {}),
            )


def _row(log_file, payload, kind, *, input_path, size, n, effective_n, trial,
         round_trip, metrics):
    row = {column: "" for column in COLUMNS}
    row.update(
        {
            "log_file": log_file.name,
            "kind": kind,
            "started_utc": payload.get("started_utc", ""),
            "input": input_path,
            "size_bytes": size,
            "n_input": n,
            "effective_n": effective_n,
            "trial_index": trial,
            "round_trip_ok": round_trip,
            **{key: value for key, value in metrics.items() if key in COLUMNS},
        }
    )
    return row


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--logs-dir", type=Path, default=REPO_ROOT / "results" / "logs")
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "results" / "tables" / "reproduced_summary.csv",
    )
    args = parser.parse_args()

    if not args.logs_dir.is_dir():
        print(f"error: logs directory not found: {args.logs_dir}", file=sys.stderr)
        return 2

    rows = list(iter_rows(args.logs_dir))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"wrote {args.out} ({len(rows)} rows from {args.logs_dir})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
