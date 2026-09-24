"""JSON metadata sidecars for AGHC-S128 ciphertexts.

Every encryption produced through :func:`aghc_s128.core.encrypt_file` (with
``write_metadata=True``, the default) stores a sidecar next to the
ciphertext::

    <ciphertext>.aghc-s128.json

The sidecar carries everything decryption needs besides the password
(``n_input``, ``trial_index``) plus provenance for reproducibility.

Privacy rules enforced here:

* **no password** (and no password-derived seed) is ever written;
* only the *basename* of the input filename is stored (no absolute paths,
  no usernames, no machine-identifying paths);
* no tokens or secrets.
"""

from __future__ import annotations

import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Union

from .constants import (
    ALGORITHM_ID,
    ALGORITHM_VERSION,
    METADATA_SCHEMA_VERSION,
    METADATA_SUFFIX,
    MODULUS,
    RESIDUAL_SCHEME,
)

__all__ = [
    "sidecar_path_for",
    "build_encryption_metadata",
    "write_metadata",
    "read_metadata",
    "runtime_environment_summary",
]

PathLike = Union[str, Path]


def sidecar_path_for(ciphertext_path: PathLike) -> Path:
    """Return ``<ciphertext_path>.aghc-s128.json``."""
    return Path(str(ciphertext_path) + METADATA_SUFFIX)


def runtime_environment_summary() -> Dict[str, Any]:
    """Non-identifying runtime description for provenance records."""
    summary: Dict[str, Any] = {
        "python_version": platform.python_version(),
        "implementation": platform.python_implementation(),
        "os": platform.system(),
        "os_release": platform.release(),
        "machine": platform.machine(),
        "platform": sys.platform,
    }
    try:
        import numpy

        summary["numpy_version"] = numpy.__version__
    except ImportError:  # pragma: no cover - numpy is a hard dependency
        summary["numpy_version"] = None
    try:
        import scipy

        summary["scipy_version"] = scipy.__version__
    except ImportError:
        summary["scipy_version"] = None
    try:
        import matplotlib

        summary["matplotlib_version"] = matplotlib.__version__
    except ImportError:
        summary["matplotlib_version"] = None
    summary["aghc_s128_version"] = ALGORITHM_VERSION
    return summary


def build_encryption_metadata(
    *,
    n_input: int,
    effective_matrix_size: int,
    trial_index: int,
    input_filename: str,
    input_size_bytes: int,
    output_size_bytes: int,
    plaintext_sha3_256: str,
    ciphertext_sha3_256: str,
    encryption_time_seconds: Optional[float] = None,
    hill_length: Optional[int] = None,
    residual_length: Optional[int] = None,
    created_utc: Optional[str] = None,
    environment: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a metadata dictionary ready for JSON serialization.

    Only pass the *basename* of the input filename; this function does not
    leak paths by construction.
    """
    return {
        "schema_version": METADATA_SCHEMA_VERSION,
        "algorithm": {
            "id": ALGORITHM_ID,
            "version": ALGORITHM_VERSION,
            "modulus": MODULUS,
            "residual_scheme": RESIDUAL_SCHEME,
            "hill_reshape_orientation": "row-major (C order), (N, len_hill // N)",
        },
        "n_input": int(n_input),
        "effective_matrix_size": int(effective_matrix_size),
        "trial_index": int(trial_index),
        "hill_length_bytes": None if hill_length is None else int(hill_length),
        "residual_length_bytes": None if residual_length is None else int(residual_length),
        "input_filename": Path(input_filename).name,
        "input_size_bytes": int(input_size_bytes),
        "output_size_bytes": int(output_size_bytes),
        "plaintext_sha3_256": plaintext_sha3_256,
        "ciphertext_sha3_256": ciphertext_sha3_256,
        "encryption_time_seconds": encryption_time_seconds,
        "created_utc": created_utc
        or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "runtime_environment": environment or runtime_environment_summary(),
    }


def write_metadata(metadata: Dict[str, Any], ciphertext_path: PathLike) -> Path:
    """Serialize ``metadata`` to the sidecar path of ``ciphertext_path``."""
    target = sidecar_path_for(ciphertext_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
    return target


def read_metadata(path: PathLike) -> Dict[str, Any]:
    """Load and validate a metadata sidecar.

    Raises
    ------
    FileNotFoundError
        If the sidecar does not exist.
    ValueError
        If the payload is not valid JSON or does not describe AGHC-S128.
    """
    sidecar = Path(path)
    if not sidecar.is_file():
        raise FileNotFoundError(f"no such metadata file: {sidecar}")
    try:
        metadata = json.loads(sidecar.read_text())
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid metadata JSON in {sidecar}: {exc}") from exc

    if not isinstance(metadata, dict):
        raise ValueError(f"metadata must be a JSON object: {sidecar}")
    algorithm = metadata.get("algorithm")
    if not isinstance(algorithm, dict) or algorithm.get("id") != ALGORITHM_ID:
        raise ValueError(
            f"{sidecar} is not an {ALGORITHM_ID} metadata sidecar"
        )
    for key in ("n_input", "trial_index", "effective_matrix_size"):
        if key not in metadata:
            raise ValueError(f"metadata is missing required key '{key}': {sidecar}")
    return metadata
