"""Command-line interface for AGHC-S128.

Password policy: passwords are never accepted as command-line arguments (they
would leak into shell history).  Use ``--password-env VAR`` (default
``AGHC_PASSWORD``) or ``--prompt`` for an interactive ``getpass`` prompt.

Commands
--------
::

    aghc-s128 encrypt   INPUT  [-o OUT] --n N [--no-metadata] [--max-trials T]
    aghc-s128 decrypt   INPUT  [-o OUT] [--n N] [--trial T] [--metadata PATH]
                              [--verify]
    aghc-s128 analyze   ORIGINAL ENCRYPTED [--decrypted PATH] --output-dir DIR
    aghc-s128 key-sensitivity CIPHER_A CIPHER_B --output-dir DIR
    aghc-s128 reproduce --config configs/quick_demo.yaml
    aghc-s128 validate
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path
from typing import Optional, Sequence

import numpy as np

from . import __version__
from . import metrics, visualization
from .constants import ALGORITHM_ID
from .core import decrypt_file, encrypt_file
from .experiments import (
    load_config,
    run_binary_experiments,
    run_image_experiments,
    run_key_sensitivity,
    run_quick_demo,
)
from .integrity import compare_file_hashes
from .io_utils import read_binary_file
from .residual import shift128_decrypt, shift128_encrypt

DEFAULT_PASSWORD_ENV = "AGHC_PASSWORD"


class CliError(RuntimeError):
    """User-facing CLI error (message printed without traceback)."""


def _resolve_password(args: argparse.Namespace) -> str:
    if getattr(args, "prompt", False):
        password = getpass.getpass("AGHC-S128 password: ")
        if not password:
            raise CliError("empty password entered")
        return password
    env_name = getattr(args, "password_env", DEFAULT_PASSWORD_ENV) or DEFAULT_PASSWORD_ENV
    password = os.environ.get(env_name)
    if not password:
        raise CliError(
            f"password not available: environment variable {env_name} is not set. "
            f"Either `export {env_name}=...` (recommended) or pass --prompt."
        )
    return password


def _print_header(title: str) -> None:
    print("=" * 72)
    print(f"{ALGORITHM_ID} — {title}")
    print("=" * 72)


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------


def _cmd_encrypt(args: argparse.Namespace) -> int:
    password = _resolve_password(args)
    result = encrypt_file(
        args.input,
        args.output,
        n_input=args.n,
        password=password,
        write_metadata_sidecar=not args.no_metadata,
        max_trials=args.max_trials,
    )
    _print_header("ENCRYPTION COMPLETE")
    print(f"input            : {result.input_path}")
    print(f"output           : {result.output_path}")
    print(f"n_input          : {result.n_input}  (effective N = {result.effective_n})")
    print(f"hill / residual  : {result.hill_length} / {result.residual_length} bytes")
    print(f"trial index      : {result.trial_index}  (store it: decryption needs it)")
    print(f"encryption time  : {result.encryption_time_seconds:.4f} s")
    print(f"plaintext sha3-256 : {result.plaintext_sha3_256}")
    print(f"ciphertext sha3-256: {result.ciphertext_sha3_256}")
    if result.metadata_path:
        print(f"metadata sidecar : {result.metadata_path}")
    return 0


def _cmd_decrypt(args: argparse.Namespace) -> int:
    password = _resolve_password(args)
    result = decrypt_file(
        args.input,
        args.output,
        n_input=args.n,
        password=password,
        trial_index=args.trial,
        metadata_path=args.metadata,
    )
    _print_header("DECRYPTION COMPLETE")
    print(f"input            : {result.input_path}")
    print(f"output           : {result.output_path}")
    print(f"n_input          : {result.n_input}  (effective N = {result.effective_n})")
    print(f"trial index      : {result.trial_index_used}  ({result.trial_index_source})")
    print(f"decryption time  : {result.decryption_time_seconds:.4f} s")
    print(f"plaintext sha3-256 : {result.plaintext_sha3_256}")

    if args.verify:
        from .metadata import read_metadata, sidecar_path_for

        sidecar = Path(args.metadata) if args.metadata else sidecar_path_for(args.input)
        expected = read_metadata(sidecar).get("plaintext_sha3_256")
        ok = expected == result.plaintext_sha3_256
        print(f"round-trip check : {'VALID' if ok else 'FAILED'}"
              f" (expected {expected})")
        if not ok:
            return 1
    return 0


def _cmd_analyze(args: argparse.Namespace) -> int:
    original = read_binary_file(args.original)
    encrypted = read_binary_file(args.encrypted)
    report: dict = {
        "algorithm": ALGORITHM_ID,
        "original": str(args.original),
        "encrypted": str(args.encrypted),
    }

    chi_value, chi_p = metrics.chi_square_uniformity(encrypted)
    monobit_p = metrics.monobit_frequency_test(encrypted)
    report["metrics"] = {
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

    if args.decrypted:
        integrity = compare_file_hashes(args.original, args.decrypted)
        report["integrity"] = {
            "algorithm": integrity.algorithm,
            "original_sha3_256": integrity.hash_a,
            "decrypted_sha3_256": integrity.hash_b,
            "identical": integrity.identical,
        }

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / f"analysis_{args.original.stem}.json"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    figure_path = visualization.plot_histogram_comparison(
        original,
        encrypted,
        output_dir / f"{args.original.stem}_histogram.png",
        title=f"Mode A analysis — {args.original.name}",
    )

    _print_header("MODE A ANALYSIS")
    print(json.dumps(report["metrics"], indent=2))
    if args.decrypted:
        print(f"integrity        : {'VALID' if report['integrity']['identical'] else 'FAILED'}")
    print(f"report           : {json_path}")
    print(f"figure           : {figure_path}")
    return 0


def _cmd_key_sensitivity(args: argparse.Namespace) -> int:
    cipher_a = read_binary_file(args.cipher_a)
    cipher_b = read_binary_file(args.cipher_b)
    report = {
        "algorithm": ALGORITHM_ID,
        "cipher_a": str(args.cipher_a),
        "cipher_b": str(args.cipher_b),
        "metrics": {
            "key_sensitivity_percent": metrics.key_sensitivity(cipher_a, cipher_b),
            "npcr_cipherA_vs_cipherB_percent": metrics.npcr(cipher_a, cipher_b),
            "uaci_cipherA_vs_cipherB_percent": metrics.uaci(cipher_a, cipher_b),
            "bit_difference_ratio_percent": metrics.bit_difference_ratio(cipher_a, cipher_b),
        },
    }
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "key_sensitivity.json"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    figure_path = visualization.plot_key_sensitivity_comparison(
        cipher_a,
        cipher_b,
        output_dir / "key_sensitivity.png",
        metrics=report["metrics"],
    )
    _print_header("MODE B KEY SENSITIVITY")
    print(json.dumps(report["metrics"], indent=2))
    print(f"report           : {json_path}")
    print(f"figure           : {figure_path}")
    return 0



def _cmd_reproduce(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    kind = config["kind"]
    _print_header(f"REPRODUCE: {kind}")
    if kind == "quick_demo":
        payload = run_quick_demo(config)
    elif kind == "binary_experiments":
        payload = run_binary_experiments(config)
    elif kind == "image_experiments":
        payload = run_image_experiments(config)
    elif kind == "key_sensitivity":
        payload = run_key_sensitivity(config)
    else:  # pragma: no cover - load_config validates kind
        raise CliError(f"unsupported kind: {kind}")

    print(f"round trip ok    : {payload.get('round_trip_ok', 'n/a')}")
    for key, value in payload.get("outputs", {}).items():
        print(f"{key:<17}: {value}")
    return 0


def _cmd_validate(_: argparse.Namespace) -> int:
    """Self-check: deterministic key, inverse correctness, full byte round trip."""
    from .core import decrypt_bytes, encrypt_bytes
    from .key_generation import generate_valid_key
    from .modular_arithmetic import verify_inverse

    _print_header("ENVIRONMENT VALIDATION")
    from .metadata import runtime_environment_summary

    print(json.dumps(runtime_environment_summary(), indent=2))

    n_input = 4
    password = "aghc-s128-validation-vector"
    key_a = generate_valid_key(n_input, password)
    key_b = generate_valid_key(n_input, password)
    checks = {
        "deterministic key generation": np.array_equal(key_a.matrix, key_b.matrix),
        "trial index reproducible": key_a.trial_index == key_b.trial_index,
        "matrix inverse verifies": verify_inverse(key_a.matrix, key_a.inverse),
        "shift-128 full byte round trip": np.array_equal(
            np.arange(256, dtype=np.uint8),
            shift128_decrypt(shift128_encrypt(np.arange(256, dtype=np.uint8))),
        ),
    }

    data = (np.arange(1000) % 256).astype(np.uint8)
    enc = encrypt_bytes(data, n_input, password)
    dec = decrypt_bytes(enc.ciphertext, n_input, password, trial_index=enc.trial_index)
    checks["hill+residual round trip (n=4, 1000 B)"] = np.array_equal(dec.plaintext, data)
    checks["round-trip sha3-256 match"] = (
        dec.plaintext_sha3_256 == enc.plaintext_sha3_256
    )

    all_ok = True
    print("-" * 72)
    for name, ok in checks.items():
        print(f"[{'PASS' if ok else 'FAIL'}] {name}")
        all_ok = all_ok and ok
    print("-" * 72)
    print("RESULT:", "ALL CHECKS PASSED" if all_ok else "VALIDATION FAILED")
    return 0 if all_ok else 1


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aghc-s128",
        description=(
            f"{ALGORITHM_ID} — reproducibility implementation CLI. "
            "Research prototype; see docs/SECURITY_SCOPE.md before use."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_password_options(sub: argparse.ArgumentParser) -> None:
        sub.add_argument(
            "--password-env",
            default=DEFAULT_PASSWORD_ENV,
            help=f"environment variable holding the password (default: {DEFAULT_PASSWORD_ENV})",
        )
        sub.add_argument(
            "--prompt",
            action="store_true",
            help="prompt for the password interactively (getpass)",
        )

    encrypt = subparsers.add_parser("encrypt", help="encrypt a file")
    encrypt.add_argument("input", type=Path)
    encrypt.add_argument("-o", "--output", type=Path, default=None)
    encrypt.add_argument("--n", type=int, required=True, help="n_input; effective N = 2*n")
    encrypt.add_argument("--no-metadata", action="store_true", help="skip JSON sidecar")
    encrypt.add_argument(
        "--max-trials", type=int, default=None, help="cap key-generation retries"
    )
    add_password_options(encrypt)
    encrypt.set_defaults(func=_cmd_encrypt)

    decrypt = subparsers.add_parser("decrypt", help="decrypt a file")
    decrypt.add_argument("input", type=Path)
    decrypt.add_argument("-o", "--output", type=Path, default=None)
    decrypt.add_argument(
        "--n", type=int, default=None, help="n_input (read from metadata if omitted)"
    )
    decrypt.add_argument(
        "--trial", type=int, default=None, help="trial index (read from metadata if omitted)"
    )
    decrypt.add_argument(
        "--metadata", type=Path, default=None, help="explicit metadata sidecar path"
    )
    decrypt.add_argument(
        "--verify",
        action="store_true",
        help="compare decrypted SHA3-256 against the sidecar and fail on mismatch",
    )
    add_password_options(decrypt)
    decrypt.set_defaults(func=_cmd_decrypt)

    analyze = subparsers.add_parser(
        "analyze", help="Mode A statistical analysis (original vs encrypted)"
    )
    analyze.add_argument("original", type=Path)
    analyze.add_argument("encrypted", type=Path)
    analyze.add_argument("--decrypted", type=Path, default=None)
    analyze.add_argument(
        "--output-dir", type=Path, default=Path("results/analysis"), help="output directory"
    )
    analyze.set_defaults(func=_cmd_analyze)

    key_sens = subparsers.add_parser(
        "key-sensitivity", help="Mode B comparison of two ciphertexts"
    )
    key_sens.add_argument("cipher_a", type=Path)
    key_sens.add_argument("cipher_b", type=Path)
    key_sens.add_argument(
        "--output-dir", type=Path, default=Path("results/analysis"), help="output directory"
    )
    key_sens.set_defaults(func=_cmd_key_sensitivity)

    reproduce = subparsers.add_parser("reproduce", help="run an experiment config")
    reproduce.add_argument("--config", type=Path, required=True)
    reproduce.set_defaults(func=_cmd_reproduce)

    validate = subparsers.add_parser("validate", help="environment + algorithm self-check")
    validate.set_defaults(func=_cmd_validate)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
