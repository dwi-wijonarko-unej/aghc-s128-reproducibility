#!/usr/bin/env python
"""Rebuild summary figures from recorded experiment logs.

Usage (from the repository root):

    python scripts/reproduce_figures.py [--logs-dir results/logs]
                                        [--out-dir results/figures]

Reads every ``results/logs/*.json`` and regenerates aggregate figures that do
not need the original byte data (entropy comparison, runtime).  Histogram
figures are produced by the experiment runners themselves (they need the
actual streams); this script notes that when relevant inputs are missing.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _bootstrap  # noqa: F401,E402

from aghc_s128.visualization import plot_entropy_comparison, plot_runtime  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]


def collect(logs_dir: Path):
    entries = []
    for log_file in sorted(logs_dir.glob("*.json")):
        try:
            payload = json.loads(log_file.read_text())
        except json.JSONDecodeError:
            continue
        metrics = payload.get("metrics") or {}
        if metrics and "entropy_encrypted" in metrics:
            label = Path(str(payload.get("input", {}).get("path", log_file.stem))).stem
            entries.append(
                {
                    "label": label,
                    "entropy_original": metrics.get("entropy_original"),
                    "entropy_encrypted": metrics.get("entropy_encrypted"),
                    "kind": payload.get("kind"),
                }
            )
        for run in payload.get("runs", []):
            run_metrics = run.get("metrics", {})
            if "entropy_encrypted" in run_metrics:
                entries.append(
                    {
                        "label": Path(str(run.get("input", "?"))).stem,
                        "entropy_original": run_metrics.get("entropy_original"),
                        "entropy_encrypted": run_metrics.get("entropy_encrypted"),
                        "kind": payload.get("kind"),
                    }
                )
    return entries


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--logs-dir", type=Path, default=REPO_ROOT / "results" / "logs")
    parser.add_argument("--out-dir", type=Path, default=REPO_ROOT / "results" / "figures")
    args = parser.parse_args()

    if not args.logs_dir.is_dir():
        print(f"error: logs directory not found: {args.logs_dir}", file=sys.stderr)
        return 2

    entries = collect(args.logs_dir)
    if not entries:
        print("no log entries with entropy metrics found; nothing to plot")
        return 0

    labels = [f"{e['label']} ({which})" for e in entries for which in ("orig", "enc")]
    values = [
        value
        for e in entries
        for value in (e["entropy_original"], e["entropy_encrypted"])
    ]
    entropy_path = plot_entropy_comparison(
        labels, values, args.out_dir / "reproduced_entropy.png",
        title="Reproduced entropy (original vs encrypted) from experiment logs",
    )
    print(f"wrote {entropy_path}")

    runtime_labels = [e["label"] for e in entries]
    # runtime per entry is only present in run records; degrade gracefully
    times = []
    for log_file in sorted(args.logs_dir.glob("*.json")):
        payload = json.loads(log_file.read_text())
        for run in payload.get("runs", []):
            if "encryption_time_seconds" in run:
                times.append(run["encryption_time_seconds"])
    if times:
        runtime_path = plot_runtime(
            runtime_labels[: len(times)],
            times,
            args.out_dir / "reproduced_runtime.png",
            title="Encryption wall-clock time (hardware-dependent)",
        )
        print(f"wrote {runtime_path}")
    else:
        print("note: per-input runtimes not present in logs; runtime figure skipped")

    print(
        "note: histogram/pixel-correlation figures are produced by the "
        "experiment runners (they need the original byte streams)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
