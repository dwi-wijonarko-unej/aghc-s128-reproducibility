"""Shift-128 residual transform tests (formula frozen from baseline)."""

from __future__ import annotations

import numpy as np
import pytest

from aghc_s128 import shift128_decrypt, shift128_encrypt


def test_full_byte_range_round_trip():
    data = np.arange(256, dtype=np.uint8)
    encrypted = shift128_encrypt(data)
    decrypted = shift128_decrypt(encrypted)
    np.testing.assert_array_equal(decrypted, data)


def test_encrypt_formula_matches_baseline():
    data = np.arange(256, dtype=np.uint8)
    encrypted = shift128_encrypt(data)
    np.testing.assert_array_equal(encrypted, (data.astype(np.int32) + 128) % 256)
    # spot values: 0->128, 127->255, 128->0, 255->127
    assert encrypted[0] == 128
    assert encrypted[127] == 255
    assert encrypted[128] == 0
    assert encrypted[255] == 127


def test_decrypt_formula_matches_baseline():
    data = np.arange(256, dtype=np.uint8)
    decrypted = shift128_decrypt(data)
    np.testing.assert_array_equal(decrypted, (data.astype(np.int32) - 128) % 256)


def test_output_dtype_uint8():
    data = np.array([0, 5, 200, 255], dtype=np.uint8)
    assert shift128_encrypt(data).dtype == np.uint8
    assert shift128_decrypt(data).dtype == np.uint8


def test_empty_input():
    empty = np.zeros(0, dtype=np.uint8)
    assert shift128_encrypt(empty).size == 0
    assert shift128_decrypt(empty).size == 0


def test_shift128_is_self_inverse_composition():
    data = np.array([1, 2, 3, 254, 255], dtype=np.uint8)
    np.testing.assert_array_equal(shift128_decrypt(shift128_encrypt(data)), data)
    np.testing.assert_array_equal(shift128_encrypt(shift128_decrypt(data)), data)


def test_rejects_float_dtype():
    with pytest.raises(TypeError):
        shift128_encrypt(np.array([1.0, 2.0]))


def test_rejects_out_of_range():
    with pytest.raises(ValueError):
        shift128_encrypt(np.array([0, 256], dtype=np.int64))
    with pytest.raises(ValueError):
        shift128_decrypt(np.array([-1, 0], dtype=np.int64))


def test_rejects_2d_input():
    with pytest.raises(ValueError):
        shift128_encrypt(np.ones((2, 2), dtype=np.uint8))
