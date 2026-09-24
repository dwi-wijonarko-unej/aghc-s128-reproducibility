"""Modular matrix arithmetic for AGHC-S128.

Port of the baseline ``mod_inverse_matrix`` (Gauss-Jordan elimination modulo
256).  The elimination order, pivot rule, and arithmetic dtype match the
baseline exactly so inverses are bit-identical.
"""

from __future__ import annotations

import numpy as np

from .constants import MODULUS

__all__ = [
    "MatrixNotInvertibleError",
    "NonSquareMatrixError",
    "mod_inverse_matrix",
    "is_invertible_mod",
    "verify_inverse",
]


class MatrixNotInvertibleError(ValueError):
    """Raised when a matrix has no inverse modulo the given modulus."""


class NonSquareMatrixError(ValueError):
    """Raised when a matrix is not square."""


def _validated_square(matrix: np.ndarray) -> np.ndarray:
    arr = np.asarray(matrix)
    if arr.ndim != 2 or arr.shape[0] != arr.shape[1]:
        raise NonSquareMatrixError(
            f"matrix must be square, got shape {arr.shape}"
        )
    return arr


def mod_inverse_matrix(
    matrix: np.ndarray, modulus: int = MODULUS
) -> np.ndarray:
    """Invert ``matrix`` modulo ``modulus`` with Gauss-Jordan elimination.

    Baseline-faithful behavior:

    * augmented ``[A | I]`` in int64;
    * pivot search from the current column downward, accepting the first row
      whose entry satisfies ``gcd(entry, modulus) == 1``;
    * pivot inverse via ``pow(pivot, -1, modulus)``;
    * row reduction ``row = (row - factor * pivot_row) % modulus``.

    Parameters
    ----------
    matrix:
        Square integer matrix.
    modulus:
        Reduction modulus (baseline: 256).

    Returns
    -------
    numpy.ndarray
        The inverse matrix (int32), with entries in ``[0, modulus)``.

    Raises
    ------
    NonSquareMatrixError
        If ``matrix`` is not square.
    MatrixNotInvertibleError
        If no valid pivot exists in some column.
    ValueError
        If a pivot has no modular inverse (cannot happen for gcd-1 pivots,
        kept as a defensive check).
    """
    a = _validated_square(matrix)
    n = a.shape[0]

    a = a.astype(np.int64)
    identity = np.eye(n, dtype=np.int64)
    aug = np.concatenate((a, identity), axis=1)

    for col in range(n):
        pivot = -1
        for row in range(col, n):
            value = int(aug[row, col])
            if np.gcd(value, modulus) == 1:
                pivot = row
                break

        if pivot == -1:
            raise MatrixNotInvertibleError(
                f"Matrix not invertible modulo {modulus} "
                f"(no valid pivot in column {col})"
            )

        if pivot != col:
            aug[[col, pivot]] = aug[[pivot, col]]

        pivot_value = int(aug[col, col])
        try:
            inv_pivot = pow(pivot_value, -1, modulus)
        except ValueError as exc:  # pragma: no cover - gcd check guards this
            raise MatrixNotInvertibleError(
                f"pivot {pivot_value} has no inverse modulo {modulus}"
            ) from exc

        aug[col] = (aug[col] * inv_pivot) % modulus

        for row in range(n):
            if row != col:
                factor = aug[row, col]
                aug[row] = (aug[row] - factor * aug[col]) % modulus

    inverse = aug[:, n:]
    return inverse.astype(np.int32)


def is_invertible_mod(matrix: np.ndarray, modulus: int = MODULUS) -> bool:
    """Return ``True`` iff ``matrix`` is invertible modulo ``modulus``."""
    try:
        mod_inverse_matrix(matrix, modulus)
    except MatrixNotInvertibleError:
        return False
    except NonSquareMatrixError:
        return False
    return True


def verify_inverse(
    matrix: np.ndarray,
    inverse: np.ndarray,
    modulus: int = MODULUS,
) -> bool:
    """Check ``(matrix @ inverse) % modulus == identity``."""
    a = _validated_square(matrix)
    b = _validated_square(inverse)
    if a.shape != b.shape:
        return False
    product = (a.astype(np.int64) @ b.astype(np.int64)) % modulus
    return bool(np.array_equal(product, np.eye(a.shape[0], dtype=np.int64)))
