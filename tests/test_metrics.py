"""Statistical metric tests: known values, validation, truncation policy."""

from __future__ import annotations

import numpy as np
import pytest

from aghc_s128 import metrics


def uniform_bytes(n: int) -> np.ndarray:
    """Bytes as uniform as possible (each value appears n//256 times)."""
    repeats = n // 256 + 1
    stream = np.tile(np.arange(256, dtype=np.uint8), repeats)
    return stream[:n]


# --- entropy --------------------------------------------------------------------


def test_entropy_uniform_bytes_is_8():
    assert metrics.shannon_entropy(np.arange(256, dtype=np.uint8)) == pytest.approx(8.0)


def test_entropy_constant_bytes_is_zero():
    assert metrics.shannon_entropy(np.zeros(64, dtype=np.uint8)) == pytest.approx(0.0)


def test_entropy_known_small_value():
    # Two symbols with equal counts -> 1 bit/byte.
    data = np.array([0] * 4 + [1] * 4, dtype=np.uint8)
    assert metrics.shannon_entropy(data) == pytest.approx(1.0)


def test_entropy_empty_raises():
    with pytest.raises(ValueError):
        metrics.shannon_entropy(np.zeros(0, dtype=np.uint8))


# --- adjacent byte correlation ------------------------------------------------------


def test_correlation_perfectly_linear_is_one():
    ramp = np.arange(0, 256, dtype=np.uint8)
    assert metrics.adjacent_byte_correlation(ramp) == pytest.approx(1.0)


def test_correlation_short_inputs_defined():
    assert metrics.adjacent_byte_correlation(np.zeros(1, dtype=np.uint8)) == 0.0
    assert metrics.adjacent_byte_correlation(np.zeros(0, dtype=np.uint8)) == 0.0


def test_correlation_rejects_float():
    with pytest.raises(TypeError):
        metrics.adjacent_byte_correlation(np.array([1.0, 2.0]))


# --- NPCR / UACI / bit difference ----------------------------------------------------


def test_npcr_known_values():
    a = np.array([0, 1, 2, 3], dtype=np.uint8)
    b = np.array([0, 9, 2, 9], dtype=np.uint8)
    assert metrics.npcr(a, b) == pytest.approx(50.0)


def test_npcr_identical_is_zero():
    a = np.arange(100, dtype=np.uint8)
    assert metrics.npcr(a, a.copy()) == pytest.approx(0.0)


def test_uaci_known_value():
    a = np.array([0, 0], dtype=np.uint8)
    b = np.array([255, 0], dtype=np.uint8)
    assert metrics.uaci(a, b) == pytest.approx(50.0)  # (255/255 + 0) / 2 * 100
def test_uaci_shift128_pair_is_about_50():
    data = np.arange(256, dtype=np.uint8)
    shifted = ((data.astype(np.int32) + 128) % 256).astype(np.uint8)
    expected = np.mean(
        np.abs(data.astype(np.int32) - shifted.astype(np.int32)) / 255
    ) * 100
    assert metrics.uaci(data, shifted) == pytest.approx(float(expected))

def test_bit_difference_known_values():
    a = np.array([0b0000_0000], dtype=np.uint8)
    b = np.array([0b1111_1111], dtype=np.uint8)
    assert metrics.bit_difference_ratio(a, b) == pytest.approx(100.0)
    assert metrics.bit_difference_ratio(a, a.copy()) == pytest.approx(0.0)
    # 0x00 vs 0x0F -> 4/8 bits
    c = np.array([0x00], dtype=np.uint8)
    d = np.array([0x0F], dtype=np.uint8)
    assert metrics.bit_difference_ratio(c, d) == pytest.approx(50.0)


def test_length_mismatch_raises_by_default():
    a = np.arange(10, dtype=np.uint8)
    b = np.arange(9, dtype=np.uint8)
    for fn in (metrics.npcr, metrics.uaci, metrics.bit_difference_ratio,
               metrics.key_sensitivity):
        with pytest.raises(ValueError, match="length mismatch"):
            fn(a, b)


def test_length_mismatch_allowed_with_truncation():
    a = np.arange(10, dtype=np.uint8)
    b = np.arange(8, dtype=np.uint8) + 1  # differs everywhere in the overlap
    assert metrics.npcr(a, b, allow_truncate=True) == pytest.approx(100.0)


def test_empty_pair_raises():
    empty = np.zeros(0, dtype=np.uint8)
    with pytest.raises(ValueError):
        metrics.npcr(empty, empty)


# --- key sensitivity ------------------------------------------------------------------


def test_key_sensitivity_full_difference():
    a = np.zeros(8, dtype=np.uint8)
    b = np.ones(8, dtype=np.uint8)
    assert metrics.key_sensitivity(a, b) == pytest.approx(100.0)


# --- chi-square ------------------------------------------------------------------------


def test_chi_square_uniform_input_high_p():
    data = uniform_bytes(256 * 40)
    chi_value, p_value = metrics.chi_square_uniformity(data)
    assert p_value > 0.05
    assert chi_value >= 0


def test_chi_square_skewed_input_low_p():
    data = np.zeros(4096, dtype=np.uint8)
    _, p_value = metrics.chi_square_uniformity(data)
    assert p_value < 0.05


def test_chi_square_empty_raises():
    with pytest.raises(ValueError):
        metrics.chi_square_uniformity(np.zeros(0, dtype=np.uint8))


# --- monobit ------------------------------------------------------------------------------


def test_monobit_balanced_stream_p_is_one():
    # 0xAA = 10101010 -> exactly half ones
    data = np.full(32, 0xAA, dtype=np.uint8)
    assert metrics.monobit_frequency_test(data) == pytest.approx(1.0)


def test_monobit_all_zeros_p_is_zero():
    data = np.zeros(16, dtype=np.uint8)
    assert metrics.monobit_frequency_test(data) == pytest.approx(0.0)


def test_monobit_verdict_threshold():
    assert metrics.monobit_verdict(0.5) == "pass"
    assert metrics.monobit_verdict(0.005) == "fail"


def test_monobit_empty_raises():
    with pytest.raises(ValueError):
        metrics.monobit_frequency_test(np.zeros(0, dtype=np.uint8))


def test_monobit_no_unsigned_underflow():
    """Documented baseline divergence: notebook's numpy unsigned subtraction
    underflowed when zeros > ones; the library computes the exact value."""
    # 0x0F has 4 ones / 4 zeros per byte, 0x01 has 1 one / 7 zeros -> zeros win.
    data = np.full(64, 0x01, dtype=np.uint8)
    p = metrics.monobit_frequency_test(data)
    assert 0.0 <= p <= 1.0
    bits = np.unpackbits(data)
    ones, zeros = int(bits.sum()), bits.size - int(bits.sum())
    expected = 2 * (1 - __import__("scipy.stats", fromlist=["norm"]).norm.cdf(
        abs(ones - zeros) / np.sqrt(bits.size)))
    assert p == pytest.approx(float(expected))


# --- differential helpers / integrity -------------------------------------------------------


def test_mean_max_abs_difference():
    a = np.array([0, 10, 200], dtype=np.uint8)
    b = np.array([10, 10, 100], dtype=np.uint8)
    mean_diff, max_diff = metrics.mean_max_abs_difference(a, b)
    assert mean_diff == pytest.approx((10 + 0 + 100) / 3)
    assert max_diff == 100


def test_round_trip_integrity_arrays():
    data = np.arange(64, dtype=np.uint8)
    report = metrics.round_trip_integrity(data, data.copy())
    assert report["identical"]
    assert report["algorithm"] == "sha3_256"


def test_round_trip_integrity_detects_mismatch():
    a = np.arange(64, dtype=np.uint8)
    b = np.arange(64, dtype=np.uint8) + 1
    assert not metrics.round_trip_integrity(a, b)["identical"]


def test_round_trip_integrity_paths(tmp_path):
    a = tmp_path / "a.bin"
    b = tmp_path / "b.bin"
    a.write_bytes(b"same")
    b.write_bytes(b"same")
    report = metrics.round_trip_integrity(None, None, original_path=a, decrypted_path=b)
    assert report["identical"]


def test_metrics_reject_path_inputs():
    with pytest.raises(TypeError):
        metrics.shannon_entropy("some/path.txt")  # type: ignore[arg-type]
