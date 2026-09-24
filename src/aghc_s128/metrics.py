"""Statistical evaluation metrics for AGHC-S128 (baseline-faithful).

Every function returns structured values; nothing is printed.  These are
*statistical evaluation* helpers reproducing the notebook's analysis cells —
they are not a cryptographic security proof (see docs/SECURITY_SCOPE.md).

Length policy
-------------
The notebook silently truncated mismatched inputs to ``min(len)`` in NPCR,
UACI, key sensitivity, and bit-difference.  This module inverts that default:
mismatched lengths raise ``ValueError``.  Pass ``allow_truncate=True`` to
reproduce the notebook's exact numbers on mismatched inputs.

Naming policy
-------------
* NPCR / UACI / bit-difference are generic byte-stream metrics.  Mode A uses
  them on (plaintext, ciphertext); Mode B on (ciphertext A, ciphertext B).
  The semantics come from the *call site*, documented in experiments.
* ``adjacent_byte_correlation`` measures stream-adjacent bytes.  It is NOT
  "pixel correlation" unless the input is an image and a pixel-pair sampling
  scheme is defined (image-specific helpers live in visualization.py).
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Tuple, Union

import numpy as np
from scipy.stats import chisquare, norm, pearsonr

from .constants import MONOBIT_ALPHA
from .integrity import hash_bytes_sha3_256, hash_file_sha3_256

__all__ = [
    "shannon_entropy",
    "adjacent_byte_correlation",
    "npcr",
    "uaci",
    "bit_difference_ratio",
    "key_sensitivity",
    "chi_square_uniformity",
    "monobit_frequency_test",
    "monobit_verdict",
    "mean_max_abs_difference",
    "round_trip_integrity",
    "byte_histogram",
]

PathLike = Union[str, Path]


# ---------------------------------------------------------------------------
# Input coercion / validation
# ---------------------------------------------------------------------------


def _as_byte_array(data, name: str) -> np.ndarray:
    if isinstance(data, (str, Path)):
        raise TypeError(
            f"{name} must be a byte array, not a path; read it with "
            "aghc_s128.io_utils.read_binary_file first"
        )
    if isinstance(data, (bytes, bytearray, memoryview)):
        return np.frombuffer(bytes(data), dtype=np.uint8)
    arr = np.asarray(data)
    if arr.ndim != 1:
        raise ValueError(f"{name} must be 1-D, got shape {arr.shape}")
    if not np.issubdtype(arr.dtype, np.integer):
        raise TypeError(f"{name} must be an integer/bytes array, got {arr.dtype}")
    if arr.size and (int(arr.min()) < 0 or int(arr.max()) > 255):
        raise ValueError(f"{name} values must be in [0, 255]")
    return arr.astype(np.uint8, copy=False)


def _coerce_pair(a, b, allow_truncate: bool, name_a: str, name_b: str):
    left = _as_byte_array(a, name_a)
    right = _as_byte_array(b, name_b)
    if left.size != right.size:
        if not allow_truncate:
            raise ValueError(
                f"length mismatch: {name_a} has {left.size} bytes, "
                f"{name_b} has {right.size} bytes. Pass allow_truncate=True "
                "to reproduce the notebook's silent truncation behavior."
            )
        n = min(left.size, right.size)
        left = left[:n]
        right = right[:n]
    return left, right


def byte_histogram(data) -> np.ndarray:
    """256-bin byte histogram (``np.bincount(data, minlength=256)``)."""
    arr = _as_byte_array(data, "data")
    return np.bincount(arr, minlength=256)


# ---------------------------------------------------------------------------
# Information-theoretic / distribution metrics
# ---------------------------------------------------------------------------


def shannon_entropy(data) -> float:
    """Shannon entropy over the byte histogram, in bits/byte (max 8).

    Baseline formula: ``-sum(p * log2(p))`` over non-zero byte probabilities.
    Raises ``ValueError`` on empty input (the notebook returned ``nan``).
    """
    histogram = byte_histogram(data)
    total = histogram.sum()
    if total == 0:
        raise ValueError("entropy is undefined for empty input")
    probability = histogram / total
    probability = probability[probability > 0]
    return float(-np.sum(probability * np.log2(probability)))


def chi_square_uniformity(data) -> Tuple[float, float]:
    """Chi-square goodness-of-fit of the byte histogram against uniform.

    Returns ``(chi_square, p_value)`` — identical to the notebook's
    ``scipy.stats.chisquare(hist, expected)`` with uniform expected counts.
    """
    arr = _as_byte_array(data, "data")
    if arr.size == 0:
        raise ValueError("chi-square is undefined for empty input")
    histogram = np.bincount(arr, minlength=256).astype(np.float64)
    expected = np.ones(256, dtype=np.float64) * (arr.size / 256)
    chi_value, p_value = chisquare(histogram, expected)
    return float(chi_value), float(p_value)


def monobit_frequency_test(data) -> float:
    """Monobit frequency test p-value.

    Baseline formula: ``s = |ones - zeros| / sqrt(n)`` over the unpacked bit
    stream and ``p = 2 * (1 - Phi(s))`` via ``scipy.stats.norm.cdf``.

    Divergence from the notebook (documented in KNOWN_ISSUES.md): the
    notebook computed ``ones - zeros`` in numpy *unsigned* integers, which
    underflows to a huge value whenever zeros > ones and forces p to 0.0.
    This implementation evaluates the same formula with exact integer
    arithmetic, i.e. the formula the notebook intended.
    """
    arr = _as_byte_array(data, "data")
    bits = np.unpackbits(arr)
    n = bits.size
    if n == 0:
        raise ValueError("monobit test is undefined for empty input")
    ones = int(np.sum(bits))
    zeros = n - ones
    s = abs(ones - zeros) / np.sqrt(n)
    p_value = 2 * (1 - norm.cdf(s))
    return float(p_value)


def monobit_verdict(p_value: float, alpha: float = MONOBIT_ALPHA) -> str:
    """Baseline reporting rule: ``p > alpha`` -> ``"pass"`` else ``"fail"``."""
    return "pass" if p_value > alpha else "fail"


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------


def adjacent_byte_correlation(data) -> float:
    """Pearson correlation between stream-adjacent bytes ``data[:-1]``/``data[1:]``.

    Returns ``0.0`` for inputs shorter than 2 bytes (the guard used by the
    notebook's later cells).  Constant inputs yield ``nan`` (scipy semantics,
    accompanied by a ConstantInputWarning) exactly like the notebook.  This
    is a byte-stream metric; do not report it as "pixel correlation" for
    images.
    """
    arr = _as_byte_array(data, "data")
    if arr.size < 2:
        return 0.0
    x = arr[:-1].astype(np.float64)
    y = arr[1:].astype(np.float64)
    corr, _ = pearsonr(x, y)
    return float(corr)


# ---------------------------------------------------------------------------
# Differential-style metrics (Mode A: plain vs cipher; Mode B: cipher vs cipher)
# ---------------------------------------------------------------------------


def npcr(a, b, *, allow_truncate: bool = False) -> float:
    """Number of Pixels/Bytes Change Rate in percent.

    ``NPCR = (count(a[i] != b[i]) / n) * 100``.  Lengths must match unless
    ``allow_truncate=True`` (legacy notebook behavior).
    """
    left, right = _coerce_pair(a, b, allow_truncate, "a", "b")
    if left.size == 0:
        raise ValueError("NPCR is undefined for empty input")
    return float(np.sum(left != right) / left.size * 100)


def uaci(a, b, *, allow_truncate: bool = False) -> float:
    """Unified Average Changing Intensity in percent.

    ``UACI = mean(|a - b| / 255) * 100`` (baseline divisor 255).  The
    "~33% ideal" reference value is defined for image encryption; interpret
    with care on arbitrary binary data.
    """
    left, right = _coerce_pair(a, b, allow_truncate, "a", "b")
    if left.size == 0:
        raise ValueError("UACI is undefined for empty input")
    left64 = left.astype(np.float64)
    right64 = right.astype(np.float64)
    return float(np.mean(np.abs(left64 - right64) / 255.0) * 100)


def bit_difference_ratio(a, b, *, allow_truncate: bool = False) -> float:
    """Percentage of differing bits between two byte streams.

    Vectorized equivalent of the notebook's ``avalanche_effect`` /
    ``bit_difference`` loops: ``sum(popcount(a ^ b)) / (8 * n) * 100``.
    The notebook called the plaintext-vs-ciphertext variant "avalanche
    effect"; that name is avoided here because no keyed input-difference
    experiment is involved.
    """
    left, right = _coerce_pair(a, b, allow_truncate, "a", "b")
    if left.size == 0:
        raise ValueError("bit difference is undefined for empty input")
    xor_bits = np.unpackbits(left ^ right)
    return float(np.sum(xor_bits) / xor_bits.size * 100)


def key_sensitivity(cipher_a, cipher_b, *, allow_truncate: bool = False) -> float:
    """Key sensitivity in percent: share of differing bytes between two
    ciphertexts produced from the same plaintext under different keys.

    Numerically identical to :func:`npcr` (same formula); kept as a distinct
    name because Mode B semantics (ciphertext-vs-ciphertext) differ from
    Mode A (plaintext-vs-ciphertext).
    """
    left, right = _coerce_pair(cipher_a, cipher_b, allow_truncate, "cipher_a", "cipher_b")
    if left.size == 0:
        raise ValueError("key sensitivity is undefined for empty input")
    return float(np.sum(left != right) / left.size * 100)


def mean_max_abs_difference(a, b, *, allow_truncate: bool = False) -> Tuple[float, int]:
    """Mean and maximum absolute byte difference (notebook's differential analysis)."""
    left, right = _coerce_pair(a, b, allow_truncate, "a", "b")
    if left.size == 0:
        raise ValueError("difference statistics are undefined for empty input")
    diff = np.abs(left.astype(np.int32) - right.astype(np.int32))
    return float(np.mean(diff)), int(np.max(diff))


# ---------------------------------------------------------------------------
# Integrity
# ---------------------------------------------------------------------------


def round_trip_integrity(
    original, decrypted, *, original_path: PathLike = None, decrypted_path: PathLike = None
) -> Dict[str, object]:
    """SHA3-256 round-trip integrity report.

    Either pass byte arrays (``original``/``decrypted``) or file paths via
    ``original_path``/``decrypted_path``.  Returns a dict with both hashes
    and an ``identical`` flag — the baseline's SHA3-256 integrity check.
    """
    if original_path is not None:
        hash_original = hash_file_sha3_256(original_path)
    else:
        hash_original = hash_bytes_sha3_256(_as_byte_array(original, "original"))
    if decrypted_path is not None:
        hash_decrypted = hash_file_sha3_256(decrypted_path)
    else:
        hash_decrypted = hash_bytes_sha3_256(_as_byte_array(decrypted, "decrypted"))
    return {
        "algorithm": "sha3_256",
        "original_sha3_256": hash_original,
        "decrypted_sha3_256": hash_decrypted,
        "identical": hash_original == hash_decrypted,
    }
