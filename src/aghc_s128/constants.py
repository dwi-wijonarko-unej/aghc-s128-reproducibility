"""Centralized baseline parameters for AGHC-S128.

Every numeric constant of the baseline algorithm lives here so that the
implementation, tests, CLI, and documentation reference a single source of
truth.  Values are frozen from the original Colab notebook (see
``docs/BASELINE_IMPLEMENTATION_AUDIT.md``); changing any of them changes the
ciphertexts and therefore the reproducibility of the paper's results.
"""

from __future__ import annotations

# --- Modular arithmetic -------------------------------------------------
#: Arithmetic modulus of the Hill stage and of the Shift-128 residual stage.
MODULUS: int = 256

# --- Chaos (logistic map) ----------------------------------------------
#: Logistic map control parameter r (baseline value).
LOGISTIC_R: float = 3.99
#: Logistic map warm-up iterations discarded before sampling.
LOGISTIC_WARMUP: int = 1000
#: Scaling used when converting a logistic-map state to a byte:
#: ``int((x * 10**6) % 256)``.
LOGISTIC_SCALE: int = 10**6

# --- Residual Shift-128 -------------------------------------------------
#: Residual transform shift amount: ``(byte + 128) mod 256``.
SHIFT_VALUE: int = 128
#: Identifier of the residual scheme recorded in metadata.
RESIDUAL_SCHEME: str = "shift128"

# --- Password -> seed derivation ---------------------------------------
#: Number of leading hex characters of the SHA-256 password digest used to
#: build the 32-bit numeric seed (baseline behavior; see KNOWN_ISSUES).
SHA256_SEED_HEX_CHARS: int = 8
#: Divisor used to fold the numeric seed into the logistic-map initial state.
CHAOS_SEED_DIVISOR: int = 1_000_000
#: Fallback x0 used when the derived chaos seed is exactly zero.
DEFAULT_FALLBACK_X0: float = 0.54321

# --- Matrix size --------------------------------------------------------
#: Effective matrix dimension is ``N = 2 x n_input`` (2 times n, NOT 2**n).
def effective_matrix_size(n_input: int) -> int:
    """Return the effective key-matrix dimension ``N = 2 x n_input``.

    The baseline defines the Hill-stage matrix size as twice the user
    parameter ``n``.  This helper keeps that definition explicit and
    unambiguous everywhere.
    """
    return 2 * n_input


# --- Algorithm identity --------------------------------------------------
#: Short algorithm identifier (used in metadata and CLI output).
ALGORITHM_ID: str = "AGHC-S128"
#: Version of *this implementation* (not of the baseline algorithm).
ALGORITHM_VERSION: str = "1.0.0"
#: Human-readable algorithm name.
ALGORITHM_NAME: str = "Adaptive Graph Hill Cipher with Shift-128 Residual Processing"

# --- Metadata sidecar ----------------------------------------------------
#: Schema version of the ``*.aghc-s128.json`` sidecar files.
METADATA_SCHEMA_VERSION: int = 1
#: Suffix appended to a ciphertext path to build its metadata sidecar path.
METADATA_SUFFIX: str = ".aghc-s128.json"

# --- Statistical evaluation thresholds (reporting only) ------------------
#: Monobit pass threshold used by the baseline (p > 0.01 -> pass).
MONOBIT_ALPHA: float = 0.01
