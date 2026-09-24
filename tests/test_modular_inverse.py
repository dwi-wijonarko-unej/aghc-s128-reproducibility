"""Modular Gauss–Jordan inversion tests."""

from __future__ import annotations

import numpy as np
import pytest

from aghc_s128 import (
    MatrixNotInvertibleError,
    build_key_matrix,
    generate_valid_key,
    is_invertible_mod,
    mod_inverse_matrix,
    verify_inverse,
)


def test_inverse_verifies_for_valid_key():
    material = generate_valid_key(4, "aghc-inverse-test")
    assert verify_inverse(material.matrix, material.inverse, 256)


def test_known_2x2_inverse():
    # [[1, 0], [0, 1]] is its own inverse
    identity = np.eye(2, dtype=np.int64)
    np.testing.assert_array_equal(mod_inverse_matrix(identity), identity)
    # [[3, 0], [0, 7]] inverse diag: 3^-1 mod 256 = 171, 7^-1 mod 256 = 183
    matrix = np.diag([3, 7]).astype(np.int64)
    inverse = mod_inverse_matrix(matrix)
    assert inverse[0, 0] == pow(3, -1, 256) == 171
    assert inverse[1, 1] == pow(7, -1, 256) == 183
    assert verify_inverse(matrix, inverse)


def test_non_invertible_even_matrix_raises():
    # All entries even -> every pivot candidate shares factor 2 with 256.
    matrix = np.full((3, 3), 2, dtype=np.int64)
    with pytest.raises(MatrixNotInvertibleError):
        mod_inverse_matrix(matrix)


def test_singular_odd_matrix_raises():
    # Odd entries can still be singular mod 256 (duplicate rows).
    matrix = np.array([[3, 3, 3], [3, 3, 3], [1, 5, 9]], dtype=np.int64)
    with pytest.raises(MatrixNotInvertibleError):
        mod_inverse_matrix(matrix)


def test_non_square_raises():
    from aghc_s128.modular_arithmetic import NonSquareMatrixError

    with pytest.raises(NonSquareMatrixError):
        mod_inverse_matrix(np.ones((2, 3), dtype=np.int64))
    with pytest.raises(NonSquareMatrixError):
        mod_inverse_matrix(np.arange(4, dtype=np.int64))


def test_is_invertible_mod_matches_inverse_behavior():
    invertible = build_key_matrix(8, "aghc-isinvertible-ok")
    assert is_invertible_mod(invertible) == (
        is_invertible_mod(invertible)
    )
    singular = np.array([[2, 2], [2, 2]], dtype=np.int64)
    assert not is_invertible_mod(singular)


def test_verify_inverse_detects_wrong_inverse():
    material = generate_valid_key(2, "aghc-verify-wrong")
    wrong = (material.inverse + 1) % 256
    assert not verify_inverse(material.matrix, wrong)


def test_verify_inverse_shape_mismatch():
    matrix = np.eye(2, dtype=np.int64)
    assert not verify_inverse(matrix, np.eye(3, dtype=np.int64))


def test_inverse_entries_in_range():
    material = generate_valid_key(8, "aghc-range-check")
    inverse = material.inverse
    assert inverse.min() >= 0 and inverse.max() <= 255
