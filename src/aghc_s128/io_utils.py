"""Binary file I/O helpers (no interactive layer).

Files are handled exactly like the baseline: read as a 1-D ``uint8`` numpy
array, written back from such an array.  No uploads, downloads, prompts, or
prints happen here.
"""

from __future__ import annotations

from pathlib import Path
from typing import Union

import numpy as np

__all__ = [
    "read_binary_file",
    "write_binary_file",
    "write_bytes",
    "ensure_parent_dir",
    "default_encrypted_path",
    "default_decrypted_path",
]

PathLike = Union[str, Path]


def ensure_parent_dir(path: PathLike) -> Path:
    """Create the parent directory of ``path`` if missing; return the path."""
    resolved = Path(path)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    return resolved


def read_binary_file(path: PathLike) -> np.ndarray:
    """Read a file as a 1-D ``uint8`` array (baseline ``np.fromfile``)."""
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"no such file: {file_path}")
    return np.fromfile(file_path, dtype=np.uint8)


def write_binary_file(path: PathLike, data: np.ndarray) -> Path:
    """Write a uint8 array to ``path`` (creates parent directories)."""
    arr = np.asarray(data)
    if not np.issubdtype(arr.dtype, np.integer):
        raise TypeError(f"data must be an integer array, got {arr.dtype}")
    if arr.size and (int(arr.min()) < 0 or int(arr.max()) > 255):
        raise ValueError("data values must be in [0, 255]")
    target = ensure_parent_dir(path)
    arr.astype(np.uint8).tofile(target)
    return target


def write_bytes(path: PathLike, payload: bytes) -> Path:
    """Write raw ``bytes`` to ``path`` (creates parent directories)."""
    target = ensure_parent_dir(path)
    target.write_bytes(payload)
    return target


def default_encrypted_path(input_path: PathLike) -> Path:
    """Baseline naming convention: ``name.ext`` -> ``name_encrypted.ext``."""
    source = Path(input_path)
    return source.with_name(f"{source.stem}_encrypted{source.suffix}")


def default_decrypted_path(input_path: PathLike) -> Path:
    """Baseline naming convention: ``name.ext`` -> ``name_decrypted.ext``."""
    source = Path(input_path)
    return source.with_name(f"{source.stem}_decrypted{source.suffix}")
