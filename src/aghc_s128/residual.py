"""Shift-128 residual transform (baseline component, unchanged).

The baseline encrypts the trailing ``size % N`` bytes of a file with a fixed
shift: ``(byte + 128) mod 256``.  Decryption is the exact inverse
``(byte - 128) mod 256``.

Scope note (docs/SECURITY_SCOPE.md, docs/KNOWN_ISSUES.md): this transform is
constant, key-independent, and self-inverse.  It is part of the baseline
algorithm and is reproduced faithfully; it is *not* an independent
cryptographic protection.
"""

from __future__ import annotations

import numpy as np

from .constants import MODULUS, SHIFT_VALUE

__all__ = ["shift128_encrypt", "shift128_decrypt"]


def _validated(data: np.ndarray, name: str) -> np.ndarray:
    arr = np.asarray(data)
    if arr.ndim != 1:
        raise ValueError(f"{name} must be a 1-D byte array, got shape {arr.shape}")
    if not np.issubdtype(arr.dtype, np.integer):
        raise TypeError(
            f"{name} must have an integer dtype (uint8 recommended), "
            f"got {arr.dtype}"
        )
    if arr.size and (int(arr.min()) < 0 or int(arr.max()) > MODULUS - 1):
        raise ValueError(
            f"{name} values must be in [0, {MODULUS - 1}], "
            f"got range [{int(arr.min())}, {int(arr.max())}]"
        )
    return arr


def shift128_encrypt(data: np.ndarray) -> np.ndarray:
    """Encrypt residual bytes: ``(byte + 128) mod 256`` -> uint8 array."""
    arr = _validated(data, "data")
    return ((arr.astype(np.int32) + SHIFT_VALUE) % MODULUS).astype(np.uint8)


def shift128_decrypt(data: np.ndarray) -> np.ndarray:
    """Decrypt residual bytes: ``(byte - 128) mod 256`` -> uint8 array."""
    arr = _validated(data, "data")
    return ((arr.astype(np.int32) - SHIFT_VALUE) % MODULUS).astype(np.uint8)
