"""Key-material generation for AGHC-S128 (baseline-faithful port).

Construction (frozen from the original Colab notebook)::

    K = (A + P + C) mod 256   ->   odd-diagonal adjustment

where

* ``A`` is the complete-graph adjacency matrix (off-diagonal 1, diagonal 0);
* ``P`` is the adaptive graph perturbation: seeded Mersenne-Twister stream
  from the 32-bit numeric seed derived from the password; for ``i < j`` the
  weight is ``((i + 1) * (j + 1) + randint(0, 255)) % 256``, even values are
  bumped to odd, and the matrix is mirrored symmetric;
* ``C`` is a logistic-map chaos matrix (r = 3.99, 1000 warm-up iterations,
  ``int((x * 10**6) % 256)`` per element, zero diagonal).

The only intentional deviation from the notebook is the use of an isolated
``random.Random(seed)`` instance instead of the global ``random`` module: the
emitted stream is identical, but global RNG state is no longer mutated.  This
is verified byte-for-byte by ``tests/test_regression_baseline.py``.
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field
from typing import Optional

import numpy as np

from .constants import (
    ALGORITHM_VERSION,
    CHAOS_SEED_DIVISOR,
    DEFAULT_FALLBACK_X0,
    LOGISTIC_R,
    LOGISTIC_SCALE,
    LOGISTIC_WARMUP,
    MODULUS,
    SHA256_SEED_HEX_CHARS,
    effective_matrix_size,
)
from .modular_arithmetic import MatrixNotInvertibleError, mod_inverse_matrix

__all__ = [
    "KeyMaterial",
    "KeyGenerationError",
    "derive_numeric_seed",
    "derive_chaos_seed",
    "logistic_map",
    "complete_graph_matrix",
    "adaptive_graph_perturbation",
    "chaos_matrix",
    "build_key_matrix",
    "generate_valid_key",
]


class KeyGenerationError(RuntimeError):
    """Raised when no invertible key matrix is found within ``max_trials``."""


def derive_numeric_seed(password: str) -> int:
    """Derive the baseline 32-bit numeric seed from a password.

    ``numeric_seed = int(sha256(password.encode()).hexdigest()[:8], 16)``

    Note: this folds the full SHA-256 digest into 32 bits.  This is baseline
    behavior and a documented key-space limitation (KNOWN_ISSUES).
    """
    if not isinstance(password, str):
        raise TypeError("password must be a str")
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    return int(password_hash[:SHA256_SEED_HEX_CHARS], 16)


def derive_chaos_seed(numeric_seed: int) -> float:
    """Fold ``numeric_seed`` into the logistic-map initial state ``x0``.

    ``x0 = (numeric_seed % 1_000_000) / 1_000_000``; if the result is exactly
    zero the baseline fallback ``0.54321`` is used.
    """
    x0 = (numeric_seed % CHAOS_SEED_DIVISOR) / CHAOS_SEED_DIVISOR
    if x0 == 0:
        x0 = DEFAULT_FALLBACK_X0
    return x0


def logistic_map(
    seed: float,
    size: int,
    r: float = LOGISTIC_R,
    warmup: int = LOGISTIC_WARMUP,
) -> np.ndarray:
    """Generate ``size`` bytes from the logistic map.

    Baseline-faithful: a pure-Python scalar loop (no vectorization) so the
    IEEE-754 double rounding sequence is identical to the notebook.

    Parameters
    ----------
    seed:
        Initial state ``x0`` in (0, 1).
    size:
        Number of output values.
    r:
        Control parameter (baseline 3.99).
    warmup:
        Discarded warm-up iterations (baseline 1000).

    Returns
    -------
    numpy.ndarray
        int32 array with values in [0, 255].
    """
    if size < 0:
        raise ValueError("size must be >= 0")
    x = float(seed)
    output: list[int] = []

    for _ in range(warmup):
        x = r * x * (1.0 - x)

    for _ in range(size):
        x = r * x * (1.0 - x)
        value = int((x * LOGISTIC_SCALE) % MODULUS)
        output.append(value)

    return np.array(output, dtype=np.int32)


def complete_graph_matrix(matrix_size: int) -> np.ndarray:
    """Complete-graph adjacency matrix: off-diagonal 1, diagonal 0 (int32)."""
    if matrix_size < 1:
        raise ValueError("matrix_size must be >= 1")
    a = np.ones((matrix_size, matrix_size), dtype=np.int32)
    a -= np.eye(matrix_size, dtype=np.int32)
    return a % MODULUS


def adaptive_graph_perturbation(matrix_size: int, numeric_seed: int) -> np.ndarray:
    """Adaptive graph perturbation matrix ``P``.

    For every pair ``i < j`` (row-major order, one draw per pair)::

        value = ((i + 1) * (j + 1) + randint(0, 255)) % 256
        if value is even: value += 1

    The value is mirrored to both ``[i, j]`` and ``[j, i]``; the diagonal
    stays zero.  Uses an isolated ``random.Random(numeric_seed)`` instance
    whose stream is identical to the baseline's global-``random`` usage.
    """
    if matrix_size < 1:
        raise ValueError("matrix_size must be >= 1")
    rng = random.Random(numeric_seed)
    p = np.zeros((matrix_size, matrix_size), dtype=np.int32)

    for i in range(matrix_size):
        for j in range(i + 1, matrix_size):
            value = ((i + 1) * (j + 1) + rng.randint(0, 255)) % MODULUS
            if value % 2 == 0:
                value += 1
            p[i, j] = value
            p[j, i] = value

    return p % MODULUS


def chaos_matrix(matrix_size: int, chaos_seed: float) -> np.ndarray:
    """Chaos matrix ``C``: logistic-map stream reshaped row-major, zero diagonal."""
    if matrix_size < 1:
        raise ValueError("matrix_size must be >= 1")
    chaos = logistic_map(chaos_seed, matrix_size * matrix_size)
    c = chaos.reshape((matrix_size, matrix_size))
    np.fill_diagonal(c, 0)
    return c % MODULUS


def build_key_matrix(matrix_size: int, password: str) -> np.ndarray:
    """Build the raw key matrix ``K = (A + P + C) mod 256`` for a password.

    ``matrix_size`` is the *effective* dimension ``N = 2 x n_input``.
    Includes the baseline odd-diagonal adjustment (``+1 mod 256`` on even
    diagonal entries).  The result is not guaranteed invertible; use
    :func:`generate_valid_key` for the retry loop.
    """
    if matrix_size < 1:
        raise ValueError("matrix_size must be >= 1")

    a = complete_graph_matrix(matrix_size)
    numeric_seed = derive_numeric_seed(password)
    x0 = derive_chaos_seed(numeric_seed)
    p = adaptive_graph_perturbation(matrix_size, numeric_seed)
    c = chaos_matrix(matrix_size, x0)

    k = (
        a.astype(np.int32)
        + p.astype(np.int32)
        + c.astype(np.int32)
    ) % MODULUS

    for i in range(matrix_size):
        if k[i, i] % 2 == 0:
            k[i, i] += 1

    k %= MODULUS
    return k


@dataclass
class KeyMaterial:
    """Everything needed to encrypt/decrypt with one validated key.

    Security notes
    --------------
    * ``base_password`` is intentionally NOT a field: key material must never
      be serialized with the password.  Metadata sidecars never store it.
    * ``numeric_seed``/``chaos_seed`` are debugging aids derived from the
      password; treat them as sensitive if the password is sensitive.  They
      are kept in memory only and are excluded from metadata output.
    """

    matrix: np.ndarray
    inverse: np.ndarray
    n_input: int
    effective_n: int
    trial_index: int
    chaos_seed: float
    algorithm_version: str = ALGORITHM_VERSION
    numeric_seed: Optional[int] = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.effective_n != 2 * self.n_input:
            raise ValueError(
                "effective_n must equal 2 * n_input "
                f"(got n_input={self.n_input}, effective_n={self.effective_n})"
            )


def generate_valid_key(
    n_input: int,
    password: str,
    max_trials: Optional[int] = None,
) -> KeyMaterial:
    """Generate an invertible key matrix for ``n_input``.

    Mirrors the baseline retry loop: candidate passwords are
    ``password + str(trial)`` for ``trial = 0, 1, 2, ...`` until the built
    matrix is invertible modulo 256.  The winning ``trial_index`` must be
    transported to decryption (via metadata sidecar or explicit argument)
    so the identical key is rebuilt.

    Parameters
    ----------
    n_input:
        User parameter ``n``; the effective matrix size is ``N = 2 x n_input``.
    password:
        Base password (never stored on the result).
    max_trials:
        Optional cap on retry attempts (baseline: unlimited).  Provided for
        CLI/safety; the default preserves baseline behavior.

    Raises
    ------
    KeyGenerationError
        If ``max_trials`` is exceeded without finding an invertible matrix.
    """
    if not isinstance(n_input, (int, np.integer)) or n_input < 1:
        raise ValueError("n_input must be an integer >= 1")
    if max_trials is not None and max_trials < 0:
        raise ValueError("max_trials must be >= 0 or None")

    effective_n = effective_matrix_size(int(n_input))
    trial = 0

    while True:
        trial_password = password + str(trial)
        numeric_seed = derive_numeric_seed(trial_password)
        try:
            matrix = build_key_matrix(effective_n, trial_password)
            inverse = mod_inverse_matrix(matrix, MODULUS)
        except MatrixNotInvertibleError:
            if max_trials is not None and trial >= max_trials:
                raise KeyGenerationError(
                    f"no invertible key found within {max_trials + 1} "
                    f"attempts (n_input={n_input})"
                ) from None
            trial += 1
            continue

        return KeyMaterial(
            matrix=matrix,
            inverse=inverse,
            n_input=int(n_input),
            effective_n=effective_n,
            trial_index=trial,
            chaos_seed=derive_chaos_seed(numeric_seed),
            numeric_seed=numeric_seed,
        )
