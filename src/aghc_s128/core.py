"""Core AGHC-S128 API (pure functions, no I/O prompts, no Colab).

Pipeline (frozen baseline semantics)::

    size = len(data)
    N    = 2 x n_input
    residual_len = size % N          # trailing bytes
    hill_len     = size - residual_len

    Hill part   : P_hill = data[:hill_len].reshape(N, hill_len // N)
                  C_hill = (K @ P_hill) % 256
    Residual    : (byte + 128) % 256
    Ciphertext  : hill part (flattened) || residual part

Decryption mirrors this with ``K_inv`` and ``(byte - 128) % 256``.

The key ``K`` is derived from the *trial* password
``password + str(trial_index)``.  The baseline re-discovers the trial index
during decryption by retrying from 0 (deterministic, so correct); the
refactored workflow prefers the explicit ``trial_index`` transported in the
metadata sidecar.  ``trial_index=None`` keeps baseline-style rediscovery.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union

import numpy as np

from .constants import (
    ALGORITHM_ID,
    ALGORITHM_VERSION,
    MODULUS,
    effective_matrix_size,
)
from .integrity import hash_bytes_sha3_256
from .io_utils import (
    default_decrypted_path,
    default_encrypted_path,
    read_binary_file,
    write_binary_file,
)
from .key_generation import KeyMaterial, build_key_matrix, generate_valid_key
from .metadata import (
    build_encryption_metadata,
    read_metadata,
    sidecar_path_for,
    write_metadata,
)
from .modular_arithmetic import mod_inverse_matrix
from .residual import shift128_decrypt, shift128_encrypt

__all__ = [
    "EncryptionResult",
    "DecryptionResult",
    "encrypt_bytes",
    "decrypt_bytes",
    "encrypt_file",
    "decrypt_file",
]

PathLike = Union[str, Path]

def _as_uint8(data, name: str) -> np.ndarray:
    if isinstance(data, (bytes, bytearray, memoryview)):
        arr = np.frombuffer(bytes(data), dtype=np.uint8).copy()
        return arr
    arr = np.asarray(data)
    if arr.ndim != 1:
        raise ValueError(f"{name} must be a 1-D byte array, got shape {arr.shape}")
    if np.issubdtype(arr.dtype, np.integer):
        if arr.size and (int(arr.min()) < 0 or int(arr.max()) > 255):
            raise ValueError(f"{name} values must be in [0, 255]")
        arr = arr.astype(np.uint8)
    else:
        raise TypeError(
            f"{name} must be bytes or an integer array, got dtype {arr.dtype}"
        )
    return arr


def _validate_n_input(n_input: int) -> int:
    if not isinstance(n_input, (int, np.integer)) or isinstance(n_input, bool):
        raise ValueError("n_input must be an integer >= 1")
    if int(n_input) < 1:
        raise ValueError("n_input must be an integer >= 1")
    return int(n_input)


def _key_for_trial(n_input: int, password: str, trial_index: int) -> KeyMaterial:
    """Rebuild the exact key material for a known trial index (no search)."""
    effective_n = effective_matrix_size(n_input)
    trial_password = password + str(trial_index)
    matrix = build_key_matrix(effective_n, trial_password)
    inverse = mod_inverse_matrix(matrix, MODULUS)
    from .key_generation import derive_chaos_seed, derive_numeric_seed

    numeric_seed = derive_numeric_seed(trial_password)
    return KeyMaterial(
        matrix=matrix,
        inverse=inverse,
        n_input=n_input,
        effective_n=effective_n,
        trial_index=int(trial_index),
        chaos_seed=derive_chaos_seed(numeric_seed),
        numeric_seed=numeric_seed,
    )


@dataclass
class EncryptionResult:
    """Structured outcome of one encryption.

    ``ciphertext`` holds the encrypted bytes (uint8 array).  All sizes and
    hashes refer to the in-memory payload; path fields are populated by the
    file-level wrapper.
    """

    ciphertext: np.ndarray
    n_input: int
    effective_n: int
    hill_length: int
    residual_length: int
    trial_index: int
    encryption_time_seconds: float
    plaintext_sha3_256: str
    ciphertext_sha3_256: str
    algorithm: str = ALGORITHM_ID
    algorithm_version: str = ALGORITHM_VERSION
    input_path: Optional[Path] = None
    output_path: Optional[Path] = None
    metadata_path: Optional[Path] = field(default=None, repr=False)

    @property
    def input_size(self) -> int:
        return self.hill_length + self.residual_length

    @property
    def output_size(self) -> int:
        return int(self.ciphertext.size)


@dataclass
class DecryptionResult:
    """Structured outcome of one decryption."""

    plaintext: np.ndarray
    n_input: int
    effective_n: int
    hill_length: int
    residual_length: int
    trial_index_used: int
    trial_index_source: str
    decryption_time_seconds: float
    ciphertext_sha3_256: str
    plaintext_sha3_256: str
    algorithm: str = ALGORITHM_ID
    algorithm_version: str = ALGORITHM_VERSION
    input_path: Optional[Path] = None
    output_path: Optional[Path] = None


def encrypt_bytes(
    plaintext,
    n_input: int,
    password: str,
    *,
    max_trials: Optional[int] = None,
) -> EncryptionResult:
    """Encrypt a byte array with AGHC-S128.

    Parameters
    ----------
    plaintext:
        1-D bytes / uint8 array.  Empty input is defined behavior: it yields
        an empty ciphertext (no Hill part, no residual part).
    n_input:
        User parameter ``n``; effective matrix size is ``N = 2 x n``.
    password:
        Base password; the effective trial password appends the trial index.
    max_trials:
        Optional cap for the invertibility retry loop (baseline: unlimited).

    Returns
    -------
    EncryptionResult
    """
    data = _as_uint8(plaintext, "plaintext")
    n = _validate_n_input(n_input)

    start = time.perf_counter()
    key = generate_valid_key(n, password, max_trials=max_trials)
    effective_n = key.effective_n

    residual_length = data.size % effective_n
    hill_length = data.size - residual_length

    # Hill stage — baseline reshape orientation: (N, hill_len // N), C order.
    hill_plain = data[:hill_length].reshape((effective_n, hill_length // effective_n))
    hill_cipher = (
        np.dot(key.matrix.astype(np.int32), hill_plain.astype(np.int32)) % MODULUS
    ).astype(np.uint8)

    # Residual stage — Shift-128.
    shift_cipher = shift128_encrypt(data[hill_length:])

    ciphertext = np.zeros(data.size, dtype=np.uint8)
    ciphertext[:hill_length] = hill_cipher.reshape(hill_length)
    ciphertext[hill_length:] = shift_cipher

    elapsed = time.perf_counter() - start
    return EncryptionResult(
        ciphertext=ciphertext,
        n_input=n,
        effective_n=effective_n,
        hill_length=int(hill_length),
        residual_length=int(residual_length),
        trial_index=key.trial_index,
        encryption_time_seconds=elapsed,
        plaintext_sha3_256=hash_bytes_sha3_256(data),
        ciphertext_sha3_256=hash_bytes_sha3_256(ciphertext),
    )


def decrypt_bytes(
    ciphertext,
    n_input: int,
    password: str,
    trial_index: Optional[int] = None,
) -> DecryptionResult:
    """Decrypt a byte array with AGHC-S128.

    Parameters
    ----------
    ciphertext:
        1-D bytes / uint8 array.
    n_input:
        The same ``n`` used for encryption.
    password:
        The same base password used for encryption.
    trial_index:
        Explicit trial index (preferred: read it from the metadata sidecar).
        ``None`` triggers baseline-style rediscovery: keys are retried from
        trial 0 exactly like the original ``decrypt_file``.  An explicit
        wrong index produces garbage output without raising — verify with
        the SHA3-256 round-trip check.

    Returns
    -------
    DecryptionResult
    """
    data = _as_uint8(ciphertext, "ciphertext")
    n = _validate_n_input(n_input)

    start = time.perf_counter()
    if trial_index is None:
        key = generate_valid_key(n, password)
        trial_source = "rediscovered-from-0 (baseline compatibility)"
    else:
        if not isinstance(trial_index, (int, np.integer)) or int(trial_index) < 0:
            raise ValueError("trial_index must be a non-negative integer or None")
        key = _key_for_trial(n, password, int(trial_index))
        trial_source = "explicit"
    effective_n = key.effective_n

    residual_length = data.size % effective_n
    hill_length = data.size - residual_length

    hill_cipher = data[:hill_length].reshape((effective_n, hill_length // effective_n))
    hill_plain = (
        np.dot(key.inverse.astype(np.int32), hill_cipher.astype(np.int32)) % MODULUS
    ).astype(np.uint8)

    shift_plain = shift128_decrypt(data[hill_length:])

    plaintext = np.zeros(data.size, dtype=np.uint8)
    plaintext[:hill_length] = hill_plain.reshape(hill_length)
    plaintext[hill_length:] = shift_plain

    elapsed = time.perf_counter() - start
    return DecryptionResult(
        plaintext=plaintext,
        n_input=n,
        effective_n=effective_n,
        hill_length=int(hill_length),
        residual_length=int(residual_length),
        trial_index_used=key.trial_index,
        trial_index_source=trial_source,
        decryption_time_seconds=elapsed,
        ciphertext_sha3_256=hash_bytes_sha3_256(data),
        plaintext_sha3_256=hash_bytes_sha3_256(plaintext),
    )


def encrypt_file(
    input_path: PathLike,
    output_path: Optional[PathLike] = None,
    *,
    n_input: int,
    password: str,
    write_metadata_sidecar: bool = True,
    max_trials: Optional[int] = None,
) -> EncryptionResult:
    """Encrypt a file; default output follows the baseline naming convention.

    With ``write_metadata_sidecar=True`` a JSON sidecar
    (``<output>.aghc-s128.json``) is written next to the ciphertext so
    decryption does not need to rediscover the trial index.
    """
    source = Path(input_path)
    target = Path(output_path) if output_path else default_encrypted_path(source)

    data = read_binary_file(source)
    result = encrypt_bytes(data, n_input, password, max_trials=max_trials)
    write_binary_file(target, result.ciphertext)

    result.input_path = source
    result.output_path = target
    if write_metadata_sidecar:
        metadata = build_encryption_metadata(
            n_input=result.n_input,
            effective_matrix_size=result.effective_n,
            trial_index=result.trial_index,
            input_filename=source.name,
            input_size_bytes=result.input_size,
            output_size_bytes=result.output_size,
            plaintext_sha3_256=result.plaintext_sha3_256,
            ciphertext_sha3_256=result.ciphertext_sha3_256,
            encryption_time_seconds=result.encryption_time_seconds,
            hill_length=result.hill_length,
            residual_length=result.residual_length,
        )
        result.metadata_path = write_metadata(metadata, target)
    return result


def decrypt_file(
    input_path: PathLike,
    output_path: Optional[PathLike] = None,
    *,
    n_input: Optional[int] = None,
    password: str,
    trial_index: Optional[int] = None,
    metadata_path: Optional[PathLike] = None,
) -> DecryptionResult:
    """Decrypt a file.

    Resolution order for ``n_input`` / ``trial_index``:

    1. explicit keyword arguments;
    2. the metadata sidecar (explicit ``metadata_path``, else the default
       sidecar path next to ``input_path`` if it exists);
    3. fallback: ``trial_index=None`` triggers baseline rediscovery from 0
       (requires explicit ``n_input``).

    The password is *always* required from the caller.
    """
    source = Path(input_path)
    target = Path(output_path) if output_path else default_decrypted_path(source)

    sidecar = Path(metadata_path) if metadata_path else sidecar_path_for(source)
    metadata: Optional[dict] = None
    if sidecar.is_file():
        metadata = read_metadata(sidecar)

    if n_input is None:
        if metadata is None:
            raise ValueError(
                "n_input is required when no metadata sidecar is available"
            )
        n_input = int(metadata["n_input"])
    if trial_index is None and metadata is not None:
        trial_index = int(metadata["trial_index"])

    data = read_binary_file(source)
    result = decrypt_bytes(data, n_input, password, trial_index=trial_index)
    write_binary_file(target, result.plaintext)

    result.input_path = source
    result.output_path = target
    return result
