"""Integrity hashing utilities.

Default algorithm: **SHA3-256** (matches the baseline security-analysis
cells and the paper's integrity verification).  MD5 is retained solely as a
deprecated legacy helper because the original cipher cell used it for its
console report; it must not be used in new workflows.
"""

from __future__ import annotations

import hashlib
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Union

import numpy as np

__all__ = [
    "HashComparison",
    "hash_file",
    "hash_file_sha3_256",
    "hash_bytes_sha3_256",
    "compare_file_hashes",
    "hash_file_md5",
    "hash_bytes_md5",
]

PathLike = Union[str, Path]

_CHUNK_SIZE = 4096  # baseline chunk size


def _hash_file(path: PathLike, algorithm: str) -> str:
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"no such file: {file_path}")
    digest = hashlib.new(algorithm)
    with open(file_path, "rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _hash_bytes(data, algorithm: str) -> str:
    if isinstance(data, np.ndarray):
        data = data.astype(np.uint8).tobytes()
    elif isinstance(data, (bytes, bytearray, memoryview)):
        data = bytes(data)
    else:
        raise TypeError("data must be bytes or a numpy uint8 array")
    return hashlib.new(algorithm, data).hexdigest()


def hash_file(path: PathLike, algorithm: str = "sha3_256") -> str:
    """Hash a file with any ``hashlib`` algorithm name (chunked)."""
    return _hash_file(path, algorithm)


def hash_file_sha3_256(path: PathLike) -> str:
    """SHA3-256 hex digest of a file (default integrity hash)."""
    return _hash_file(path, "sha3_256")


def hash_bytes_sha3_256(data) -> str:
    """SHA3-256 hex digest of a bytes object or uint8 numpy array."""
    return _hash_bytes(data, "sha3_256")


@dataclass
class HashComparison:
    """Result of comparing two files by hash."""

    hash_a: str
    hash_b: str
    algorithm: str

    @property
    def identical(self) -> bool:
        return self.hash_a == self.hash_b


def compare_file_hashes(
    path_a: PathLike, path_b: PathLike, algorithm: str = "sha3_256"
) -> HashComparison:
    """Compare two files by ``algorithm`` hash (default SHA3-256)."""
    return HashComparison(
        hash_a=_hash_file(path_a, algorithm),
        hash_b=_hash_file(path_b, algorithm),
        algorithm=algorithm,
    )


# ---------------------------------------------------------------------------
# Legacy MD5 (deprecated)
# ---------------------------------------------------------------------------


def hash_file_md5(path: PathLike) -> str:
    """MD5 hex digest of a file.  **Deprecated**: legacy compatibility only.

    MD5 is collision-broken and was used by the original notebook only as a
    convenience check.  Use :func:`hash_file_sha3_256` instead.
    """
    warnings.warn(
        "MD5 is deprecated and retained only for legacy compatibility with "
        "the original notebook; use SHA3-256 instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    return _hash_file(path, "md5")


def hash_bytes_md5(data) -> str:
    """MD5 hex digest of bytes/uint8 array.  **Deprecated** (see hash_file_md5)."""
    warnings.warn(
        "MD5 is deprecated and retained only for legacy compatibility with "
        "the original notebook; use SHA3-256 instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    return _hash_bytes(data, "md5")
