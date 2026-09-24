"""AGHC-S128 — Adaptive Graph Hill Cipher with Shift-128 Residual Processing.

Reproducibility implementation of the baseline research algorithm.  This
package is a research artifact: it reproduces the original Colab notebook's
behavior with a clean, testable structure.  It is NOT a production
cryptographic library — see docs/SECURITY_SCOPE.md.

Importing this package has no side effects; nothing executes at import time.
"""

from __future__ import annotations

from .constants import (
    ALGORITHM_ID,
    ALGORITHM_NAME,
    ALGORITHM_VERSION,
    MODULUS,
    effective_matrix_size,
)
from .core import (
    DecryptionResult,
    EncryptionResult,
    decrypt_bytes,
    decrypt_file,
    encrypt_bytes,
    encrypt_file,
)
from .key_generation import (
    KeyMaterial,
    adaptive_graph_perturbation,
    build_key_matrix,
    chaos_matrix,
    complete_graph_matrix,
    derive_chaos_seed,
    derive_numeric_seed,
    generate_valid_key,
    logistic_map,
)
from .modular_arithmetic import (
    MatrixNotInvertibleError,
    is_invertible_mod,
    mod_inverse_matrix,
    verify_inverse,
)
from .residual import shift128_decrypt, shift128_encrypt

__version__ = ALGORITHM_VERSION

__all__ = [
    "__version__",
    # identity / constants
    "ALGORITHM_ID",
    "ALGORITHM_NAME",
    "ALGORITHM_VERSION",
    "MODULUS",
    "effective_matrix_size",
    # core API
    "EncryptionResult",
    "DecryptionResult",
    "encrypt_bytes",
    "decrypt_bytes",
    "encrypt_file",
    "decrypt_file",
    # key generation
    "KeyMaterial",
    "derive_numeric_seed",
    "derive_chaos_seed",
    "logistic_map",
    "complete_graph_matrix",
    "adaptive_graph_perturbation",
    "chaos_matrix",
    "build_key_matrix",
    "generate_valid_key",
    # modular arithmetic
    "MatrixNotInvertibleError",
    "mod_inverse_matrix",
    "is_invertible_mod",
    "verify_inverse",
    # residual
    "shift128_encrypt",
    "shift128_decrypt",
]
