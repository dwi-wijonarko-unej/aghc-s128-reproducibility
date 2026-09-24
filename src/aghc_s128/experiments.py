"""Experiment orchestration driven by YAML configs.

Each runner consumes a config dictionary (loaded by :func:`load_config`),
executes the baseline pipeline through the library API, and writes:

* ``results/logs/<kind>_<timestamp>.json`` — full structured record
  (config snapshot, environment, per-input metrics, runtimes, checksums);
* ``results/tables/<kind>_<timestamp>.csv`` — flat table for paper builds;
* ``results/figures/*.png`` — figures from :mod:`aghc_s128.visualization`.

No Google-Colab hooks, no hardcoded local paths, no invented paper numbers:
runs that depend on unavailable original datasets must be marked
``[PENDING ORIGINAL INPUT DATA]`` in configs (see
configs/paper_results_mapping.md).
"""

from __future__ import annotations

import csv
import json
import math
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import numpy as np
import yaml

from .constants import ALGORITHM_ID, ALGORITHM_VERSION
from .core import decrypt_bytes, encrypt_bytes
from .integrity import hash_bytes_sha3_256, hash_file_sha3_256
from .io_utils import read_binary_file
from .metadata import runtime_environment_summary
from . import metrics
from . import visualization

__all__ = [
    "CHARSETS",
    "ConfigError",
    "human_time",
    "classify_password_entropy",
    "keyspace_analysis",
    "load_config",
    "resolve_repo_root",
    "run_quick_demo",
    "run_binary_experiments",
    "run_image_experiments",
    "run_key_sensitivity",
]

# ---------------------------------------------------------------------------
# MODE C — keyspace / brute-force estimation (pure math, no cipher execution)
# ---------------------------------------------------------------------------

CHARSETS: Dict[str, str] = {
    "numeric": "0123456789",
    "lowercase": "abcdefghijklmnopqrstuvwxyz",
    "uppercase": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "alphanumeric": (
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    ),
    "ascii95": "".join(chr(i) for i in range(32, 127)),
    "ascii128": "".join(chr(i) for i in range(128)),
}

ATTACK_RATES: Dict[str, float] = {
    "laptop_1e6": 1e6,
    "gpu_cluster_1e9": 1e9,
    "supercomputer_1e12": 1e12,
    "hypothetical_1e15": 1e15,
}


def human_time(seconds: float) -> str:
    """Baseline MODE C human-readable duration."""
    minute, hour, day = 60, 3600, 86400
    year = 365.25 * day
    if seconds < minute:
        return f"{seconds:.2f} seconds"
    if seconds < hour:
        return f"{seconds / minute:.2f} minutes"
    if seconds < day:
        return f"{seconds / hour:.2f} hours"
    if seconds < year:
        return f"{seconds / day:.2f} days"
    return f"{seconds / year:.2e} years"


def classify_password_entropy(entropy_bits: float) -> str:
    """Baseline MODE C classification of *password alphabet entropy*.

    Note: this classifies the password space, not the effective cipher key
    space — see docs/KNOWN_ISSUES.md on the 32-bit seed bottleneck.
    """
    if entropy_bits < 40:
        return "Very Weak"
    if entropy_bits < 64:
        return "Weak"
    if entropy_bits < 80:
        return "Moderate"
    if entropy_bits < 112:
        return "Strong"
    if entropy_bits < 128:
        return "Very Strong"
    return "Cryptographically Strong"


def keyspace_analysis(password_length: int, charset_size: int) -> Dict[str, Any]:
    """Structured MODE C analysis (baseline math, no prints).

    Returns keyspace, password entropy in bits, classification label, and
    brute-force time estimates for the baseline attack-rate ladder.
    """
    if password_length < 1:
        raise ValueError("password_length must be >= 1")
    if charset_size < 2:
        raise ValueError("charset_size must be >= 2")
    keyspace = charset_size**password_length
    entropy_bits = password_length * math.log2(charset_size)
    return {
        "password_length": password_length,
        "charset_size": charset_size,
        "keyspace": keyspace,
        "keyspace_scientific": f"{keyspace:.4e}",
        "password_entropy_bits": entropy_bits,
        "password_entropy_classification": classify_password_entropy(entropy_bits),
        "brute_force_estimates": {
            label: {
                "rate_keys_per_second": rate,
                "seconds": keyspace / rate,
                "human_readable": human_time(keyspace / rate),
            }
            for label, rate in ATTACK_RATES.items()
        },
        "caveat": (
            "This estimates the password-alphabet search space, not the "
            "effective key space; password-derived perturbation and chaos "
            "seeds collapse to a 32-bit numeric seed (see KNOWN_ISSUES.md)."
        ),
    }


# ---------------------------------------------------------------------------
# Config loading and paths
# ---------------------------------------------------------------------------


class ConfigError(ValueError):
    """Raised for malformed or unsupported experiment configs."""


def resolve_repo_root(start: PathLike = None) -> Path:
    """Walk upward from ``start`` (default: this file) to the directory
    containing ``pyproject.toml`` — the repository root."""
    current = Path(start) if start else Path(__file__).resolve()
    current = current.parent if current.is_file() else current
    for candidate in (current, *current.parents):
        if (candidate / "pyproject.toml").is_file():
            return candidate
    raise ConfigError("could not locate repository root (no pyproject.toml above)")


def load_config(path: PathLike) -> Dict[str, Any]:
    """Load and minimally validate a YAML experiment config."""
    config_path = Path(path)
    if not config_path.is_file():
        raise FileNotFoundError(f"no such config file: {config_path}")
    with open(config_path, "r", encoding="utf-8") as handle:
        config = yaml.safe_load(handle)
    if not isinstance(config, dict):
        raise ConfigError(f"config must be a YAML mapping: {config_path}")
    kind = config.get("kind")
    if kind not in {"quick_demo", "binary_experiments", "image_experiments", "key_sensitivity"}:
        raise ConfigError(
            f"config field 'kind' must be one of quick_demo, "
            f"binary_experiments, image_experiments, key_sensitivity "
            f"(got {kind!r}) in {config_path}"
        )
    config["_config_path"] = str(config_path)
    config["_repo_root"] = str(resolve_repo_root(config_path.parent))
    return config


def _resolve(config: Dict[str, Any], path_value: str) -> Path:
    """Resolve a config path: absolute as-is, else relative to the repo root."""
    candidate = Path(path_value)
    if candidate.is_absolute():
        return candidate
    return Path(config["_repo_root"]) / candidate


def _password_from_config(config: Dict[str, Any], key: str = "password") -> str:
    """Resolve a password for an experiment run.

    Priority: environment variable named by ``<key>_env`` wins; otherwise the
    inline ``<key>`` demo value is used (configs must only ever carry public
    test vectors inline).  Raises ``ConfigError`` when neither is available.
    """
    env_name = config.get(f"{key}_env")
    if env_name:
        value = os.environ.get(env_name)
        if value:
            return value
    inline = config.get(key)
    if inline:
        return str(inline)
    raise ConfigError(
        f"no password available for '{key}': set the environment variable "
        f"{env_name or f'{key}_env'.upper()} or add an inline demo value to "
        "the config (public test vectors only)."
    )


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------


def _write_json_log(output_dir: Path, kind: str, payload: Dict[str, Any]) -> Path:
    logs_dir = output_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    target = logs_dir / f"{kind}_{_timestamp()}.json"
    target.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n")
    return target


def _write_table(
    output_dir: Path, kind: str, fieldnames: Sequence[str], rows: List[Dict[str, Any]]
) -> Path:
    tables_dir = output_dir / "tables"
    tables_dir.mkdir(parents=True, exist_ok=True)
    target = tables_dir / f"{kind}_{_timestamp()}.csv"
    with open(target, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fieldnames))
        writer.writeheader()
        writer.writerows(rows)
    return target


def _run_header(config: Dict[str, Any], kind: str) -> Dict[str, Any]:
    return {
        "kind": kind,
        "algorithm": ALGORITHM_ID,
        "algorithm_version": ALGORITHM_VERSION,
        "started_utc": _utc_now(),
        "config": {
            key: value for key, value in config.items() if not key.startswith("_")
        },
        "runtime_environment": runtime_environment_summary(),
    }


# ---------------------------------------------------------------------------
# Mode A metric bundle (baseline cells 2-3), returned as structured data
# ---------------------------------------------------------------------------


def _mode_a_metrics(original: np.ndarray, encrypted: np.ndarray) -> Dict[str, Any]:
    chi_value, chi_p = metrics.chi_square_uniformity(encrypted)
    monobit_p = metrics.monobit_frequency_test(encrypted)
    return {
        "entropy_original": metrics.shannon_entropy(original),
        "entropy_encrypted": metrics.shannon_entropy(encrypted),
        "adjacent_byte_correlation_original": metrics.adjacent_byte_correlation(original),
        "adjacent_byte_correlation_encrypted": metrics.adjacent_byte_correlation(encrypted),
        "npcr_plain_vs_cipher_percent": metrics.npcr(original, encrypted),
        "uaci_plain_vs_cipher_percent": metrics.uaci(original, encrypted),
        "bit_difference_ratio_plain_vs_cipher_percent": metrics.bit_difference_ratio(
            original, encrypted
        ),
        "chi_square_encrypted": chi_value,
        "chi_square_p_value_encrypted": chi_p,
        "monobit_p_value_encrypted": monobit_p,
        "monobit_verdict_encrypted": metrics.monobit_verdict(monobit_p),
    }


# ---------------------------------------------------------------------------
# Runners
# ---------------------------------------------------------------------------


def run_quick_demo(config: Dict[str, Any]) -> Dict[str, Any]:
    """Quick reproduction: encrypt + decrypt one sample, verify round trip,
    compute Mode A metrics, emit one figure set and one log/CSV row."""
    root = Path(config["_repo_root"])
    output_dir = _resolve(config, config.get("output_dir", "results/example_outputs"))
    n_input = int(config.get("n_input", 8))
    password = _password_from_config(config)
    input_path = _resolve(config, config.get("input", "data/sample/sample_text.txt"))

    plaintext = read_binary_file(input_path)
    enc = encrypt_bytes(plaintext, n_input, password)
    dec = decrypt_bytes(enc.ciphertext, n_input, password, trial_index=enc.trial_index)
    round_trip = dec.plaintext_sha3_256 == enc.plaintext_sha3_256

    mode_a = _mode_a_metrics(plaintext, enc.ciphertext)
    integrity = metrics.round_trip_integrity(
        plaintext, dec.plaintext
    )

    figure_dir = output_dir / "figures"
    histogram_path = visualization.plot_histogram_comparison(
        plaintext,
        enc.ciphertext,
        figure_dir / f"{input_path.stem}_histogram.png",
        title=f"Quick demo — {input_path.name} (n={n_input}, N={enc.effective_n})",
    )
    entropy_path = visualization.plot_entropy_comparison(
        [f"{input_path.stem} (original)", f"{input_path.stem} (encrypted)"],
        [mode_a["entropy_original"], mode_a["entropy_encrypted"]],
        figure_dir / f"{input_path.stem}_entropy.png",
    )

    payload = _run_header(config, "quick_demo")
    payload["input"] = {
        "path": str(input_path),
        "sha3_256": hash_file_sha3_256(input_path),
        "size_bytes": int(plaintext.size),
    }
    payload["encryption"] = {
        "n_input": n_input,
        "effective_n": enc.effective_n,
        "hill_length": enc.hill_length,
        "residual_length": enc.residual_length,
        "trial_index": enc.trial_index,
        "encryption_time_seconds": enc.encryption_time_seconds,
        "plaintext_sha3_256": enc.plaintext_sha3_256,
        "ciphertext_sha3_256": enc.ciphertext_sha3_256,
    }
    payload["decryption"] = {
        "trial_index_used": dec.trial_index_used,
        "trial_index_source": dec.trial_index_source,
        "decryption_time_seconds": dec.decryption_time_seconds,
    }
    payload["round_trip_ok"] = bool(round_trip and integrity["identical"])
    payload["metrics"] = mode_a
    payload["outputs"] = {
        "histogram": str(histogram_path),
        "entropy_figure": str(entropy_path),
    }

    log_path = _write_json_log(output_dir, "quick_demo", payload)
    table_path = _write_table(
        output_dir,
        "quick_demo",
        [
            "input",
            "size_bytes",
            "n_input",
            "effective_n",
            "trial_index",
            "round_trip_ok",
            "entropy_original",
            "entropy_encrypted",
            "npcr_percent",
            "uaci_percent",
            "monobit_verdict",
            "encryption_time_seconds",
            "decryption_time_seconds",
        ],
        [
            {
                "input": input_path.name,
                "size_bytes": int(plaintext.size),
                "n_input": n_input,
                "effective_n": enc.effective_n,
                "trial_index": enc.trial_index,
                "round_trip_ok": payload["round_trip_ok"],
                "entropy_original": mode_a["entropy_original"],
                "entropy_encrypted": mode_a["entropy_encrypted"],
                "npcr_percent": mode_a["npcr_plain_vs_cipher_percent"],
                "uaci_percent": mode_a["uaci_plain_vs_cipher_percent"],
                "monobit_verdict": mode_a["monobit_verdict_encrypted"],
                "encryption_time_seconds": enc.encryption_time_seconds,
                "decryption_time_seconds": dec.decryption_time_seconds,
            }
        ],
    )
    payload["outputs"]["log"] = str(log_path)
    payload["outputs"]["table"] = str(table_path)
    return payload


def _iter_inputs(config: Dict[str, Any]) -> List[Path]:
    inputs = config.get("inputs")
    if not inputs or not isinstance(inputs, list):
        raise ConfigError("config field 'inputs' must be a non-empty list of paths")
    resolved = [_resolve(config, entry) for entry in inputs]
    for path in resolved:
        if not path.is_file():
            raise FileNotFoundError(
                f"input file not found: {path}. If this is an original paper "
                "dataset, see data/README.md and configs/paper_results_mapping.md "
                "[PENDING ORIGINAL INPUT DATA]."
            )
    return resolved


def run_binary_experiments(config: Dict[str, Any]) -> Dict[str, Any]:
    """Mode A over a list of binary inputs: encrypt/decrypt each file, verify
    integrity, compute the full metric bundle, write figures + CSV + log."""
    output_dir = _resolve(config, config.get("output_dir", "results"))
    n_input = int(config.get("n_input", 8))
    password = _password_from_config(config)
    inputs = _iter_inputs(config)

    payload = _run_header(config, "binary_experiments")
    rows: List[Dict[str, Any]] = []
    figure_dir = output_dir / "figures"

    for input_path in inputs:
        started = time.perf_counter()
        plaintext = read_binary_file(input_path)
        enc = encrypt_bytes(plaintext, n_input, password)
        dec = decrypt_bytes(enc.ciphertext, n_input, password, trial_index=enc.trial_index)
        mode_a = _mode_a_metrics(plaintext, enc.ciphertext)
        integrity_ok = dec.plaintext_sha3_256 == enc.plaintext_sha3_256
        wall = time.perf_counter() - started

        visualization.plot_histogram_comparison(
            plaintext,
            enc.ciphertext,
            figure_dir / f"{input_path.stem}_histogram.png",
            title=f"{input_path.name} (n={n_input}, N={enc.effective_n})",
        )

        record = {
            "input": str(input_path),
            "input_sha3_256": hash_file_sha3_256(input_path),
            "size_bytes": int(plaintext.size),
            "n_input": n_input,
            "effective_n": enc.effective_n,
            "hill_length": enc.hill_length,
            "residual_length": enc.residual_length,
            "trial_index": enc.trial_index,
            "round_trip_ok": integrity_ok,
            "encryption_time_seconds": enc.encryption_time_seconds,
            "decryption_time_seconds": dec.decryption_time_seconds,
            "wall_time_seconds": wall,
            "metrics": mode_a,
        }
        payload.setdefault("runs", []).append(record)
        rows.append(
            {
                "input": input_path.name,
                "size_bytes": int(plaintext.size),
                "n_input": n_input,
                "effective_n": enc.effective_n,
                "trial_index": enc.trial_index,
                "round_trip_ok": integrity_ok,
                **{key: value for key, value in mode_a.items()},
                "encryption_time_seconds": enc.encryption_time_seconds,
                "decryption_time_seconds": dec.decryption_time_seconds,
            }
        )

    table_path = _write_table(output_dir, "binary_experiments", list(rows[0].keys()), rows)
    log_path = _write_json_log(output_dir, "binary_experiments", payload)
    payload["outputs"] = {"table": str(table_path), "log": str(log_path)}
    return payload


def run_image_experiments(config: Dict[str, Any]) -> Dict[str, Any]:
    """Mode A on image files plus image-specific adjacent-pixel correlation.

    Byte-stream metrics treat the file exactly like any binary input
    (baseline behavior).  The pixel-correlation scatter is an explicit
    image-specific extension (baseline notebook had none) and decodes the
    image with matplotlib's PNG reader (first channel for RGB).
    """
    output_dir = _resolve(config, config.get("output_dir", "results"))
    n_input = int(config.get("n_input", 8))
    password = _password_from_config(config)
    inputs = _iter_inputs(config)

    payload = _run_header(config, "image_experiments")
    rows: List[Dict[str, Any]] = []
    figure_dir = output_dir / "figures"

    for input_path in inputs:
        plaintext = read_binary_file(input_path)
        enc = encrypt_bytes(plaintext, n_input, password)
        dec = decrypt_bytes(enc.ciphertext, n_input, password, trial_index=enc.trial_index)
        mode_a = _mode_a_metrics(plaintext, enc.ciphertext)
        integrity_ok = dec.plaintext_sha3_256 == enc.plaintext_sha3_256

        image_metrics: Dict[str, Any] = {}
        try:
            import matplotlib.image as mpimg

            image = np.asarray(mpimg.imread(input_path))
            if image.ndim == 3:
                gray = image[:, :, 0]
            else:
                gray = image
            if gray.dtype.kind == "f":  # normalize to 0..255 when needed
                gray = np.clip(gray * 255.0, 0, 255)
            scatter_path = visualization.plot_correlation_scatter(
                gray,
                figure_dir / f"{input_path.stem}_pixel_correlation.png",
                direction="horizontal",
            )
            image_metrics["pixel_correlation_figure"] = str(scatter_path)
        except Exception as exc:  # image decoding is best-effort, never fatal
            image_metrics["pixel_correlation_figure"] = None
            image_metrics["pixel_correlation_error"] = f"{type(exc).__name__}: {exc}"

        visualization.plot_histogram_comparison(
            plaintext,
            enc.ciphertext,
            figure_dir / f"{input_path.stem}_histogram.png",
            title=f"{input_path.name} (n={n_input}, N={enc.effective_n})",
        )

        record = {
            "input": str(input_path),
            "input_sha3_256": hash_file_sha3_256(input_path),
            "size_bytes": int(plaintext.size),
            "n_input": n_input,
            "effective_n": enc.effective_n,
            "trial_index": enc.trial_index,
            "round_trip_ok": integrity_ok,
            "encryption_time_seconds": enc.encryption_time_seconds,
            "decryption_time_seconds": dec.decryption_time_seconds,
            "metrics": mode_a,
            "image_specific": image_metrics,
        }
        payload.setdefault("runs", []).append(record)
        rows.append(
            {
                "input": input_path.name,
                "size_bytes": int(plaintext.size),
                "n_input": n_input,
                "effective_n": enc.effective_n,
                "trial_index": enc.trial_index,
                "round_trip_ok": integrity_ok,
                **{key: value for key, value in mode_a.items()},
                "encryption_time_seconds": enc.encryption_time_seconds,
                "decryption_time_seconds": dec.decryption_time_seconds,
            }
        )

    table_path = _write_table(output_dir, "image_experiments", list(rows[0].keys()), rows)
    log_path = _write_json_log(output_dir, "image_experiments", payload)
    payload["outputs"] = {"table": str(table_path), "log": str(log_path)}
    return payload


def run_key_sensitivity(config: Dict[str, Any]) -> Dict[str, Any]:
    """Mode B: one plaintext under two different passwords; compare
    ciphertexts with key-sensitivity / NPCR / UACI / bit-difference."""
    output_dir = _resolve(config, config.get("output_dir", "results"))
    n_input = int(config.get("n_input", 8))
    password_a = _password_from_config(config, "password_a")
    password_b = _password_from_config(config, "password_b")
    input_path = _resolve(config, config.get("input", "data/sample/sample_text.txt"))

    plaintext = read_binary_file(input_path)
    enc_a = encrypt_bytes(plaintext, n_input, password_a)
    enc_b = encrypt_bytes(plaintext, n_input, password_b)

    mode_b = {
        "key_sensitivity_percent": metrics.key_sensitivity(
            enc_a.ciphertext, enc_b.ciphertext
        ),
        "npcr_cipherA_vs_cipherB_percent": metrics.npcr(
            enc_a.ciphertext, enc_b.ciphertext
        ),
        "uaci_cipherA_vs_cipherB_percent": metrics.uaci(
            enc_a.ciphertext, enc_b.ciphertext
        ),
        "bit_difference_ratio_percent": metrics.bit_difference_ratio(
            enc_a.ciphertext, enc_b.ciphertext
        ),
    }

    figure_dir = output_dir / "figures"
    figure_path = visualization.plot_key_sensitivity_comparison(
        enc_a.ciphertext,
        enc_b.ciphertext,
        figure_dir / f"{input_path.stem}_key_sensitivity.png",
        metrics=mode_b,
    )

    payload = _run_header(config, "key_sensitivity")
    payload["input"] = {
        "path": str(input_path),
        "sha3_256": hash_file_sha3_256(input_path),
        "size_bytes": int(plaintext.size),
    }
    payload["ciphertext_a"] = {
        "trial_index": enc_a.trial_index,
        "sha3_256": enc_a.ciphertext_sha3_256,
        "encryption_time_seconds": enc_a.encryption_time_seconds,
    }
    payload["ciphertext_b"] = {
        "trial_index": enc_b.trial_index,
        "sha3_256": enc_b.ciphertext_sha3_256,
        "encryption_time_seconds": enc_b.encryption_time_seconds,
    }
    payload["metrics"] = mode_b
    payload["outputs"] = {"figure": str(figure_path)}

    table_path = _write_table(
        output_dir,
        "key_sensitivity",
        ["input", "size_bytes", "n_input", "trial_a", "trial_b", *mode_b.keys()],
        [
            {
                "input": input_path.name,
                "size_bytes": int(plaintext.size),
                "n_input": n_input,
                "trial_a": enc_a.trial_index,
                "trial_b": enc_b.trial_index,
                **mode_b,
            }
        ],
    )
    log_path = _write_json_log(output_dir, "key_sensitivity", payload)
    payload["outputs"]["table"] = str(table_path)
    payload["outputs"]["log"] = str(log_path)
    return payload


_ = hash_bytes_sha3_256  # available for callers extending the runners
