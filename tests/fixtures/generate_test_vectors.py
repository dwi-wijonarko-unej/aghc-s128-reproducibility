"""Generate regression test vectors from the verbatim baseline reference.

Run from the repository root:

    .venv/bin/python tests/fixtures/generate_test_vectors.py

The script executes ``tests/baseline_reference.py`` (the frozen port of the
original Colab cell 0) plus verbatim notebook metric formulas, and stores
expected values in ``tests/fixtures/test_vectors.json``.  The refactored
package must reproduce every value in that file exactly (see
``tests/test_regression_baseline.py``).

All passwords here are public test vectors — never real secrets.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import numpy as np
from scipy.stats import chisquare, norm, pearsonr

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import baseline_reference as baseline  # noqa: E402

FIXTURES = HERE / "test_vectors.json"


def deterministic_plaintext(size: int) -> bytes:
    """Documented, dependency-free plaintext pattern: ``(31*i + 7) % 256``."""
    return bytes((31 * i + 7) % 256 for i in range(size))


# --- verbatim notebook metric formulas (oracle implementations) ------------


def nb_entropy(data):
    hist = np.bincount(data, minlength=256)
    prob = hist / np.sum(hist)
    prob = prob[prob > 0]
    return float(-np.sum(prob * np.log2(prob)))


def nb_correlation(data):
    if len(data) < 2:
        return 0
    x = data[:-1].astype(np.float64)
    y = data[1:].astype(np.float64)
    corr, _ = pearsonr(x, y)
    return float(corr)


def nb_npcr(a, b):
    length = min(len(a), len(b))
    a, b = a[:length], b[:length]
    return float(np.sum(a != b) / length * 100)


def nb_uaci(a, b):
    length = min(len(a), len(b))
    a = a[:length].astype(np.int32)
    b = b[:length].astype(np.int32)
    return float(np.mean(np.abs(a - b) / 255.0) * 100)


def nb_bit_difference(a, b):
    length = min(len(a), len(b))
    a, b = a[:length], b[:length]
    total_bits = length * 8
    diff_bits = sum(bin(x ^ y).count("1") for x, y in zip(a, b))
    return float(diff_bits / total_bits * 100)


def nb_chisquare(data):
    hist = np.bincount(data, minlength=256)
    expected = np.ones(256) * (len(data) / 256)
    chi_value, p_value = chisquare(hist, expected)
    return float(chi_value), float(p_value)


def nb_monobit(data):
    bits = np.unpackbits(data)
    n = len(bits)
    ones = np.sum(bits)
    zeros = n - ones
    s = abs(ones - zeros) / np.sqrt(n)
    return float(2 * (1 - norm.cdf(s)))


def sha3(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()


def find_nonzero_trial_password(n_input: int, candidates: int = 60) -> dict | None:
    """Find a password whose key generation needs trial index > 0."""
    for i in range(candidates):
        password = f"aghc-trial-search-{i}"
        record = {"password": password, "n_input": n_input}
        matrix, _ = baseline.generate_valid_key(2 * n_input, password)
        k = baseline.generate_ai_graph_key(2 * n_input, password + "0")
        if not _invertible(k):
            record["trial_index"] = _trial_of(password, n_input)
            if record["trial_index"] and record["trial_index"] > 0:
                return record
        else:
            trial = _trial_of(password, n_input)
            if trial is not None and trial > 0:
                record["trial_index"] = trial
                return record
    return None


def _invertible(matrix) -> bool:
    try:
        baseline.mod_inverse_matrix(matrix)
        return True
    except ValueError:
        return False


def _trial_of(password: str, n_input: int):
    trial = 0
    while trial <= 50:
        k = baseline.generate_ai_graph_key(2 * n_input, password + str(trial))
        if _invertible(k):
            return trial
        trial += 1
    return None


def main() -> None:
    vectors = []

    cases = [
        # (password, n_input, plaintext_size)
        ("aghc-s128-test-vector-1", 2, 0),   # empty input (defined behavior)
        ("aghc-s128-test-vector-1", 2, 3),   # size < N=4  -> all residual
        ("aghc-s128-test-vector-1", 2, 4),   # size == N   -> all Hill
        ("aghc-s128-test-vector-1", 2, 7),   # mixed hill+residual
        ("aghc-s128-test-vector-1", 2, 12),  # multiple of N
        ("aghc-s128-test-vector-2", 4, 5),   # size < N=8
        ("aghc-s128-test-vector-2", 4, 8),   # size == N
        ("aghc-s128-test-vector-2", 4, 20),  # mixed, N=8
        ("aghc-s128-test-vector-2", 4, 64),  # multiple of N
        ("aghc-s128-test-vector-3", 8, 16),  # size == N=16
        ("aghc-s128-test-vector-3", 8, 33),  # mixed, N=16
        ("aghc-s128-test-vector-3", 8, 64),  # multiple of N
    ]

    for password, n_input, size in cases:
        plaintext = np.frombuffer(deterministic_plaintext(size), dtype=np.uint8)
        ciphertext = baseline.baseline_encrypt_bytes(plaintext, n_input, password)
        decrypted = baseline.baseline_decrypt_bytes(ciphertext, n_input, password)
        k_matrix, k_inverse = baseline.generate_valid_key(2 * n_input, password)

        assert np.array_equal(decrypted, plaintext), f"baseline round trip failed: {password}/{n_input}/{size}"
        assert np.array_equal(
            (k_matrix.astype(np.int64) @ k_inverse.astype(np.int64)) % 256,
            np.eye(2 * n_input, dtype=np.int64),
        )

        vectors.append(
            {
                "password": password,
                "n_input": n_input,
                "effective_n": 2 * n_input,
                "plaintext_size": size,
                "plaintext_hex": plaintext.tobytes().hex(),
                "trial_index": _trial_of(password, n_input),
                "key_matrix_sha3_256": sha3(k_matrix.astype(np.uint8).tobytes()),
                "key_inverse_sha3_256": sha3(k_inverse.astype(np.uint8).tobytes()),
                "plaintext_sha3_256": sha3(plaintext.tobytes()),
                "ciphertext_sha3_256": sha3(ciphertext.tobytes()),
                "ciphertext_hex": ciphertext.tobytes().hex() if size <= 64 else None,
            }
        )

    # A vector with a nonzero trial index, if any candidate needs one.
    nonzero = find_nonzero_trial_password(2)
    if nonzero is not None:
        password = nonzero["password"]
        n_input = nonzero["n_input"]
        plaintext = np.frombuffer(deterministic_plaintext(10), dtype=np.uint8)
        ciphertext = baseline.baseline_encrypt_bytes(plaintext, n_input, password)
        decrypted = baseline.baseline_decrypt_bytes(ciphertext, n_input, password)
        assert np.array_equal(decrypted, plaintext)
        k_matrix, k_inverse = baseline.generate_valid_key(2 * n_input, password)
        vectors.append(
            {
                "password": password,
                "n_input": n_input,
                "effective_n": 2 * n_input,
                "plaintext_size": 10,
                "plaintext_hex": plaintext.tobytes().hex(),
                "trial_index": _trial_of(password, n_input),
                "key_matrix_sha3_256": sha3(k_matrix.astype(np.uint8).tobytes()),
                "key_inverse_sha3_256": sha3(k_inverse.astype(np.uint8).tobytes()),
                "plaintext_sha3_256": sha3(plaintext.tobytes()),
                "ciphertext_sha3_256": sha3(ciphertext.tobytes()),
                "ciphertext_hex": ciphertext.tobytes().hex(),
            }
        )

    # Metric oracle vectors: notebook formulas on fixed byte patterns.
    metric_inputs = {
        "low_entropy": (bytes([7] * 64), bytes([((i * 5) % 256) for i in range(64)])),
        "mixed": (
            deterministic_plaintext(50),
            bytes(((i * 37 + 11) % 256) for i in range(50)),
        ),
        "shift_only": (
            deterministic_plaintext(32),
            bytes((b + 128) % 256 for b in deterministic_plaintext(32)),
        ),
    }
    metric_vectors = {}
    for name, (a, b) in metric_inputs.items():
        arr_a = np.frombuffer(a, dtype=np.uint8)
        arr_b = np.frombuffer(b, dtype=np.uint8)
        chi, p = nb_chisquare(arr_b)
        metric_vectors[name] = {
            "a_hex": a.hex(),
            "b_hex": b.hex(),
            "entropy_a": nb_entropy(arr_a),
            "entropy_b": nb_entropy(arr_b),
            "correlation_a": nb_correlation(arr_a),
            "correlation_b": nb_correlation(arr_b),
            "npcr": nb_npcr(arr_a, arr_b),
            "uaci": nb_uaci(arr_a, arr_b),
            "bit_difference": nb_bit_difference(arr_a, arr_b),
            "chi_square": chi,
            "chi_square_p": p,
            "monobit_b": nb_monobit(arr_b),
        }

    # Truncation oracle: mismatched lengths under notebook min-length behavior.
    long_a = np.frombuffer(deterministic_plaintext(40), dtype=np.uint8)
    short_b = np.frombuffer(deterministic_plaintext(25), dtype=np.uint8)
    metric_vectors["truncation_case"] = {
        "a_hex": long_a.tobytes().hex(),
        "b_hex": short_b.tobytes().hex(),
        "npcr_truncated": nb_npcr(long_a, short_b),
        "uaci_truncated": nb_uaci(long_a, short_b),
        "bit_difference_truncated": nb_bit_difference(long_a, short_b),
    }

    payload = {
        "generator": "tests/fixtures/generate_test_vectors.py",
        "baseline_source": "collab/[2]_AI_GHC+Shift128Cipher_(AGHC_S128)+SecurityAnalysisS,A,B,C_alya_(works).ipynb",
        "note": (
            "Expected values produced by the verbatim baseline reference; "
            "passwords are public test vectors. Plaintext pattern: (31*i+7)%256."
        ),
        "cipher_vectors": vectors,
        "metric_vectors": metric_vectors,
    }
    FIXTURES.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(f"wrote {FIXTURES} with {len(vectors)} cipher vectors, "
          f"{len(metric_vectors)} metric vectors")
    for vector in vectors:
        print(f"  n={vector['n_input']:>2} size={vector['plaintext_size']:>3} "
              f"trial={vector['trial_index']} cipher={vector['ciphertext_sha3_256'][:16]}...")


if __name__ == "__main__":
    main()
