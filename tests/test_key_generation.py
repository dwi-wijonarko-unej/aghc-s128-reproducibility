"""Key-generation component tests (baseline invariants)."""

from __future__ import annotations

import numpy as np
import pytest

from aghc_s128 import (
    adaptive_graph_perturbation,
    build_key_matrix,
    chaos_matrix,
    complete_graph_matrix,
    derive_chaos_seed,
    derive_numeric_seed,
    generate_valid_key,
    logistic_map,
)
from aghc_s128 import KeyMaterial
from aghc_s128.key_generation import KeyGenerationError

PASSWORD = "aghc-keygen-unit-test"


# --- complete graph --------------------------------------------------------


@pytest.mark.parametrize("size", [1, 2, 4, 8, 16])
def test_complete_graph_shape_and_values(size):
    matrix = complete_graph_matrix(size)
    assert matrix.shape == (size, size)
    assert np.all(np.diag(matrix) == 0), "diagonal must be 0"
    off = matrix[~np.eye(size, dtype=bool)]
    assert np.all(off == 1), "off-diagonal must be 1"


def test_complete_graph_rejects_invalid():
    with pytest.raises(ValueError):
        complete_graph_matrix(0)


# --- logistic map -----------------------------------------------------------


def test_logistic_map_deterministic_same_seed():
    a = logistic_map(0.54321, 64)
    b = logistic_map(0.54321, 64)
    np.testing.assert_array_equal(a, b)


def test_logistic_map_length():
    for size in (0, 1, 17, 256):
        assert logistic_map(0.31415, size).size == size


def test_logistic_map_value_range():
    stream = logistic_map(0.12345, 10_000)
    assert stream.min() >= 0 and stream.max() <= 255
    assert np.all(stream == stream.astype(np.int32))


def test_logistic_map_seeded_by_hand_matches_sequence():
    """First values must follow r*x*(1-x) with warm-up 1000, int((x*1e6)%256)."""
    x = 0.91
    for _ in range(1000):
        x = 3.99 * x * (1 - x)
    expected = []
    for _ in range(5):
        x = 3.99 * x * (1 - x)
        expected.append(int((x * 10**6) % 256))
    np.testing.assert_array_equal(logistic_map(0.91, 5), expected)


# --- adaptive perturbation ---------------------------------------------------


def test_perturbation_deterministic():
    a = adaptive_graph_perturbation(6, 12345)
    b = adaptive_graph_perturbation(6, 12345)
    np.testing.assert_array_equal(a, b)


def test_perturbation_symmetric_zero_diagonal():
    p = adaptive_graph_perturbation(8, 999)
    np.testing.assert_array_equal(p, p.T)
    assert np.all(np.diag(p) == 0)


def test_perturbation_off_diagonal_odd():
    """Baseline rule: even weights are bumped to odd (then mirrored)."""
    p = adaptive_graph_perturbation(10, 424242)
    mask = ~np.eye(10, dtype=bool)
    assert np.all(p[mask] % 2 == 1), "off-diagonal perturbation must be odd"


def test_perturbation_values_in_range():
    p = adaptive_graph_perturbation(12, 7)
    assert p.min() >= 0 and p.max() <= 255


# --- chaos matrix -------------------------------------------------------------


def test_chaos_matrix_zero_diagonal_and_range():
    c = chaos_matrix(9, 0.777)
    assert c.shape == (9, 9)
    assert np.all(np.diag(c) == 0)
    assert c.min() >= 0 and c.max() <= 255


def test_chaos_matrix_deterministic():
    np.testing.assert_array_equal(chaos_matrix(5, 0.42), chaos_matrix(5, 0.42))


# --- seed derivation ------------------------------------------------------------


def test_derive_numeric_seed_is_32_bit_and_stable():
    seed = derive_numeric_seed(PASSWORD)
    assert 0 <= seed <= 0xFFFFFFFF
    assert seed == derive_numeric_seed(PASSWORD)
    assert seed != derive_numeric_seed(PASSWORD + "x")


def test_derive_numeric_seed_matches_sha256_prefix():
    import hashlib

    expected = int(hashlib.sha256(PASSWORD.encode()).hexdigest()[:8], 16)
    assert derive_numeric_seed(PASSWORD) == expected


def test_derive_chaos_seed_folding_and_fallback():
    assert derive_chaos_seed(500_000) == 0.5
    assert derive_chaos_seed(1_500_000) == 0.5
    assert derive_chaos_seed(1_000_000) == 0.54321  # folds to 0 -> baseline fallback
    assert derive_chaos_seed(0) == 0.54321


# --- key construction ---------------------------------------------------------


def test_build_key_matrix_equals_sum_of_components_with_odd_diagonal():
    from aghc_s128 import (
        complete_graph_matrix as cg,
        adaptive_graph_perturbation as agp,
        chaos_matrix as cm,
        derive_numeric_seed,
        derive_chaos_seed,
    )
    size = 12
    k = build_key_matrix(size, PASSWORD)
    numeric_seed = derive_numeric_seed(PASSWORD)
    expected = (
        cg(size).astype(np.int32)
        + agp(size, numeric_seed).astype(np.int32)
        + cm(size, derive_chaos_seed(numeric_seed)).astype(np.int32)
    ) % 256
    for i in range(size):
        if expected[i, i] % 2 == 0:
            expected[i, i] += 1
    expected %= 256
    np.testing.assert_array_equal(k, expected)
    assert np.all(np.diag(k) % 2 == 1), "final diagonal must be odd"


def test_key_material_rejects_inconsistent_sizes():
    material = generate_valid_key(2, PASSWORD)
    with pytest.raises(ValueError):
        KeyMaterial(
            matrix=material.matrix,
            inverse=material.inverse,
            n_input=2,
            effective_n=7,  # inconsistent with n_input=2 (must be 4)
            trial_index=material.trial_index,
            chaos_seed=material.chaos_seed,
        )



def test_build_key_matrix_deterministic():
    np.testing.assert_array_equal(
        build_key_matrix(8, PASSWORD), build_key_matrix(8, PASSWORD)
    )


def test_generate_valid_key_returns_consistent_material():
    material = generate_valid_key(4, PASSWORD)
    assert material.n_input == 4
    assert material.effective_n == 8  # N = 2 x n, NOT 2**n
    assert material.trial_index >= 0
    assert material.matrix.shape == (8, 8)
    assert material.inverse.shape == (8, 8)
    again = generate_valid_key(4, PASSWORD)
    np.testing.assert_array_equal(material.matrix, again.matrix)
    assert material.trial_index == again.trial_index


def test_generate_valid_key_max_trials_raises():
    """max_trials=0 with a password whose trial-0 key is non-invertible raises.

    We search deterministically for such a password first; if none is found
    within a small budget the assertion degrades gracefully (skip).
    """
    from aghc_s128.modular_arithmetic import MatrixNotInvertibleError

    for i in range(80):
        password = f"aghc-noninvertible-probe-{i}"
        try:
            build_key_matrix(4, password + "0")
            from aghc_s128.modular_arithmetic import mod_inverse_matrix

            mod_inverse_matrix(build_key_matrix(4, password + "0"))
        except MatrixNotInvertibleError:
            # trial 0 fails; find a password where trial 1 also fails so
            # max_trials=0 (allowed attempts: 1) must raise
            with pytest.raises(KeyGenerationError):
                generate_valid_key(4, password, max_trials=0)
            return
    pytest.skip("no non-invertible trial-0 key found in probe budget")




def test_generate_valid_key_rejects_bad_n():
    for bad in (0, -3, 2.5, "8", None):
        with pytest.raises((ValueError, TypeError)):
            generate_valid_key(bad, PASSWORD)  # type: ignore[arg-type]
