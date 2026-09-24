"""Verbatim algorithmic port of the original AGHC-S128 Colab notebook (cell 0).

Source of truth:
``collab/[2]_AI_GHC+Shift128Cipher_(AGHC_S128)+SecurityAnalysisS,A,B,C_alya_(works).ipynb``

This module exists ONLY as a regression oracle for
``tests/test_regression_baseline.py``. It must stay byte-for-byte faithful to
the baseline crypto functions: same RNG usage (global ``random`` module, as in
the original), same dtypes, same reshape orientation, same trial retry loop.

Deliberate deviations from the notebook (non-algorithmic, required to run
outside Colab):

* ``google.colab`` imports, ``input()``, ``print()`` statements and file
  upload/download flows are removed.
* ``encrypt_file`` / ``decrypt_file`` are reduced to byte-array functions
  ``baseline_encrypt_bytes`` / ``baseline_decrypt_bytes`` performing exactly
  the same split/Hill/Shift/merge sequence on in-memory arrays.

Do NOT use this module in the library. Do NOT "improve" it. It is frozen.
"""

from __future__ import annotations

import hashlib
import random

import numpy as np

# ----------------------------------------------------------------------
# MD5 (legacy; kept because the baseline used it - not used by the library)
# ----------------------------------------------------------------------


def md5_bytes(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


# ----------------------------------------------------------------------
# LOGISTIC MAP (baseline: r = 3.99, warm-up 1000, int((x * 10**6) % 256))
# ----------------------------------------------------------------------


def logistic_map(seed, size):
    x = seed
    output = []

    # warm-up
    for _ in range(1000):
        x = 3.99 * x * (1 - x)

    for _ in range(size):
        x = 3.99 * x * (1 - x)
        value = int((x * 10**6) % 256)
        output.append(value)

    return np.array(output, dtype=np.int32)


# ----------------------------------------------------------------------
# COMPLETE GRAPH MATRIX
# ----------------------------------------------------------------------


def complete_graph_matrix(N):
    A = np.ones((N, N), dtype=np.int32)
    A -= np.eye(N, dtype=np.int32)
    return A % 256


# ----------------------------------------------------------------------
# AI-ASSISTED GRAPH PERTURBATION (baseline uses the *global* random module)
# ----------------------------------------------------------------------


def ai_graph_perturbation(N, seed):
    random.seed(seed)

    P = np.zeros((N, N), dtype=np.int32)

    for i in range(N):
        for j in range(i + 1, N):
            value = (((i + 1) * (j + 1)) + random.randint(0, 255)) % 256

            # avoid even determinant problems
            if value % 2 == 0:
                value += 1

            P[i, j] = value
            P[j, i] = value

    return P % 256


# ----------------------------------------------------------------------
# CHAOS MATRIX
# ----------------------------------------------------------------------


def chaos_matrix(N, seed):
    total = N * N
    chaos = logistic_map(seed, total)
    C = chaos.reshape((N, N))
    np.fill_diagonal(C, 0)
    return C % 256


# ----------------------------------------------------------------------
# GENERATE AI GRAPH KEY
# ----------------------------------------------------------------------


def generate_ai_graph_key(N, password):
    A = complete_graph_matrix(N)

    password_hash = hashlib.sha256(password.encode()).hexdigest()
    numeric_seed = int(password_hash[:8], 16)

    x0 = (numeric_seed % 1000000) / 1000000

    if x0 == 0:
        x0 = 0.54321

    P = ai_graph_perturbation(N, numeric_seed)
    C = chaos_matrix(N, x0)

    K = (
        A.astype(np.int32)
        + P.astype(np.int32)
        + C.astype(np.int32)
    ) % 256

    # FORCE ODD DIAGONAL
    for i in range(N):
        if K[i, i] % 2 == 0:
            K[i, i] += 1

    K %= 256

    return K


# ----------------------------------------------------------------------
# MODULAR MATRIX INVERSE (Gauss-Jordan mod 256)
# ----------------------------------------------------------------------


def mod_inverse_matrix(A, mod=256):
    n = A.shape[0]

    A = A.astype(np.int64)
    I = np.eye(n, dtype=np.int64)
    aug = np.concatenate((A, I), axis=1)

    for col in range(n):
        pivot = -1

        for row in range(col, n):
            value = int(aug[row, col])
            if np.gcd(value, mod) == 1:
                pivot = row
                break

        if pivot == -1:
            raise ValueError("Matrix not invertible modulo {}".format(mod))

        if pivot != col:
            aug[[col, pivot]] = aug[[pivot, col]]

        pivot_value = int(aug[col, col])
        inv_pivot = pow(pivot_value, -1, mod)

        aug[col] = (aug[col] * inv_pivot) % mod

        for row in range(n):
            if row != col:
                factor = aug[row, col]
                aug[row] = (aug[row] - factor * aug[col]) % mod

    inverse = aug[:, n:]
    return inverse.astype(np.int32)


# ----------------------------------------------------------------------
# FIND VALID INVERTIBLE MATRIX (trial = password + str(trial))
# ----------------------------------------------------------------------


def generate_valid_key(N, password):
    trial = 0

    while True:
        try:
            K = generate_ai_graph_key(N, password + str(trial))
            K_inv = mod_inverse_matrix(K)
            return K, K_inv
        except Exception:
            trial += 1


# ----------------------------------------------------------------------
# SHIFT128
# ----------------------------------------------------------------------


def shift128_encrypt(data):
    return (data.astype(np.int32) + 128) % 256


def shift128_decrypt(data):
    return (data.astype(np.int32) - 128) % 256


# ----------------------------------------------------------------------
# ENCRYPTION / DECRYPTION on byte arrays (file I/O stripped, logic identical)
# ----------------------------------------------------------------------


def baseline_encrypt_bytes(plaintext: np.ndarray, n_input: int, password: str):
    """Baseline encrypt_file minus file I/O and prints. Returns (ciphertext, trial)."""
    N = 2 * n_input

    len_shift = plaintext.size % N
    len_hill = plaintext.size - len_shift

    K, _ = generate_valid_key(N, password)

    hill_plain = plaintext[:len_hill]
    hill_plain = hill_plain.reshape((N, int(len_hill / N)))

    hill_cipher = np.dot(K.astype(np.int32), hill_plain.astype(np.int32)) % 256
    hill_cipher = hill_cipher.astype(np.uint8)

    shift_plain = plaintext[len_hill:]
    shift_cipher = shift128_encrypt(shift_plain).astype(np.uint8)

    hill_cipher_1d = hill_cipher.reshape(len_hill)

    ciphertext = np.zeros(plaintext.size, dtype=np.uint8)
    ciphertext[:len_hill] = hill_cipher_1d
    ciphertext[len_hill:] = shift_cipher

    return ciphertext


def baseline_decrypt_bytes(ciphertext: np.ndarray, n_input: int, password: str):
    """Baseline decrypt_file minus file I/O and prints."""
    N = 2 * n_input

    len_shift = ciphertext.size % N
    len_hill = ciphertext.size - len_shift

    _, K_inv = generate_valid_key(N, password)

    hill_cipher = ciphertext[:len_hill]
    hill_cipher = hill_cipher.reshape((N, int(len_hill / N)))

    hill_plain = np.dot(K_inv.astype(np.int32), hill_cipher.astype(np.int32)) % 256
    hill_plain = hill_plain.astype(np.uint8)

    shift_cipher = ciphertext[len_hill:]
    shift_plain = shift128_decrypt(shift_cipher) % 256
    shift_plain = shift_plain.astype(np.uint8)

    hill_plain_1d = hill_plain.reshape(len_hill)

    plaintext = np.zeros(ciphertext.size, dtype=np.uint8)
    plaintext[:len_hill] = hill_plain_1d
    plaintext[len_hill:] = shift_plain

    return plaintext
