"""Round-trip encryption/decryption tests across input sizes and APIs."""

from __future__ import annotations

import numpy as np
import pytest

from aghc_s128 import decrypt_bytes, decrypt_file, encrypt_bytes, encrypt_file

PASSWORD = "aghc-roundtrip-test"


def pattern(size: int) -> np.ndarray:
    return np.frombuffer(
        bytes((31 * i + 7) % 256 for i in range(size)), dtype=np.uint8
    )


# --- byte-level round trips over size classes --------------------------------


@pytest.mark.parametrize(
    "n_input,size,expect_hill,expect_residual",
    [
        (2, 0, 0, 0),    # empty input (defined behavior)
        (2, 3, 0, 3),    # size < N=4      -> fully residual
        (2, 4, 4, 0),    # size == N       -> fully Hill
        (2, 7, 4, 3),    # mixed
        (2, 12, 12, 0),  # exact multiple of N
        (4, 5, 0, 5),    # size < N=8
        (4, 8, 8, 0),    # size == N
        (4, 20, 16, 4),  # mixed
        (4, 64, 64, 0),  # exact multiple
        (8, 16, 16, 0),  # size == N=16
        (8, 33, 32, 1),  # mixed with 1 residual byte
    ],
)
def test_round_trip_size_classes(n_input, size, expect_hill, expect_residual):
    data = pattern(size)
    result = encrypt_bytes(data, n_input, PASSWORD)
    assert result.effective_n == 2 * n_input
    assert result.hill_length == expect_hill
    assert result.residual_length == expect_residual
    assert result.output_size == size

    decrypted = decrypt_bytes(
        result.ciphertext, n_input, PASSWORD, trial_index=result.trial_index
    )
    np.testing.assert_array_equal(decrypted.plaintext, data)
    assert decrypted.plaintext_sha3_256 == result.plaintext_sha3_256


def test_round_trip_with_trial_rediscovery():
    """trial_index=None keeps baseline behavior: re-search from trial 0."""
    data = pattern(50)
    encrypted = encrypt_bytes(data, 4, PASSWORD)
    decrypted = decrypt_bytes(encrypted.ciphertext, 4, PASSWORD, trial_index=None)
    np.testing.assert_array_equal(decrypted.plaintext, data)
    assert decrypted.trial_index_used == encrypted.trial_index
    assert "rediscovered" in decrypted.trial_index_source


def test_wrong_trial_index_garbage_detected_by_hash():
    """A wrong explicit trial index must not raise; integrity check catches it."""
    data = pattern(40)
    encrypted = encrypt_bytes(data, 4, PASSWORD)
    if encrypted.trial_index == 0:
        wrong = 1
    else:
        wrong = encrypted.trial_index - 1
    decrypted = decrypt_bytes(encrypted.ciphertext, 4, PASSWORD, trial_index=wrong)
    assert decrypted.plaintext_sha3_256 != encrypted.plaintext_sha3_256


def test_wrong_password_fails_round_trip():
    data = pattern(24)
    encrypted = encrypt_bytes(data, 4, PASSWORD)
    decrypted = decrypt_bytes(encrypted.ciphertext, 4, PASSWORD + "-other", trial_index=0)
    assert decrypted.plaintext_sha3_256 != encrypted.plaintext_sha3_256


def test_empty_input_defined_behavior():
    empty = np.zeros(0, dtype=np.uint8)
    result = encrypt_bytes(empty, 2, PASSWORD)
    assert result.ciphertext.size == 0
    assert result.hill_length == 0 and result.residual_length == 0
    decrypted = decrypt_bytes(result.ciphertext, 2, PASSWORD, trial_index=result.trial_index)
    assert decrypted.plaintext.size == 0


def test_ciphertext_same_length_as_plaintext():
    for size in (3, 9, 33, 100):
        result = encrypt_bytes(pattern(size), 4, PASSWORD)
        assert result.ciphertext.size == size


def test_wrong_trial_index_garbage_detected_by_hash():
    """A wrong-but-invertible explicit trial index must not raise; the
    SHA3-256 round-trip check catches the garbage output."""
    from aghc_s128 import build_key_matrix
    from aghc_s128.modular_arithmetic import MatrixNotInvertibleError, mod_inverse_matrix

    data = pattern(40)
    encrypted = encrypt_bytes(data, 4, PASSWORD)
    for wrong in range(0, encrypted.trial_index + 6):
        if wrong == encrypted.trial_index:
            continue
        try:
            mod_inverse_matrix(build_key_matrix(8, PASSWORD + str(wrong)))
        except MatrixNotInvertibleError:
            continue  # this wrong trial cannot even build a key; try next
        decrypted = decrypt_bytes(encrypted.ciphertext, 4, PASSWORD, trial_index=wrong)
        assert decrypted.plaintext_sha3_256 != encrypted.plaintext_sha3_256
        return
    pytest.skip("no invertible wrong trial found near the correct one")


def test_wrong_password_fails_round_trip():
    """Wrong password with baseline-style trial rediscovery yields garbage."""
    data = pattern(24)
    encrypted = encrypt_bytes(data, 4, PASSWORD)
    decrypted = decrypt_bytes(
        encrypted.ciphertext, 4, PASSWORD + "-other", trial_index=None
    )
    assert decrypted.plaintext_sha3_256 != encrypted.plaintext_sha3_256

def test_encrypt_bytes_input_validation():
    with pytest.raises(ValueError):
        encrypt_bytes(pattern(10), 0, PASSWORD)
    with pytest.raises(TypeError):
        encrypt_bytes(np.array([1.5, 2.5]), 2, PASSWORD)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        encrypt_bytes(np.array([[1, 2]], dtype=np.uint8), 2, PASSWORD)


def test_encrypt_bytes_accepts_builtin_bytes():
    payload = bytes(range(20))
    result = encrypt_bytes(payload, 2, PASSWORD)
    assert result.ciphertext.size == 20


# --- file-level round trips ----------------------------------------------------


def test_file_round_trip_default_names(tmp_path):
    source = tmp_path / "payload.bin"
    source.write_bytes(bytes((i * 13) % 256 for i in range(50)))
    original_dir_files = set(tmp_path.iterdir())

    encrypted = encrypt_file(source, n_input=4, password=PASSWORD)
    assert encrypted.output_path.name == "payload_encrypted.bin"
    assert encrypted.metadata_path is not None
    assert encrypted.output_path.is_file()

    decrypted = decrypt_file(encrypted.output_path, password=PASSWORD)
    assert decrypted.output_path.name == "payload_encrypted_decrypted.bin"
    assert decrypted.output_path.read_bytes() == source.read_bytes()
    # only expected artifacts were created next to the source
    assert set(tmp_path.iterdir()) - original_dir_files == {
        encrypted.output_path,
        encrypted.metadata_path,
        decrypted.output_path,
    }


def test_file_round_trip_explicit_output_no_metadata(tmp_path):
    source = tmp_path / "a.txt"
    source.write_bytes(b"AGHC-S128 file round trip sample")
    cipher_path = tmp_path / "a.aghc"
    encrypt_file(source, cipher_path, n_input=2, password=PASSWORD,
                 write_metadata_sidecar=False)
    from aghc_s128.metadata import sidecar_path_for

    assert not sidecar_path_for(cipher_path).exists()

    result = decrypt_file(cipher_path, tmp_path / "a.out", n_input=2, password=PASSWORD)
    assert result.output_path.read_bytes() == source.read_bytes()
    assert result.trial_index_source == "rediscovered-from-0 (baseline compatibility)"


def test_decrypt_file_requires_n_without_metadata(tmp_path):
    cipher = tmp_path / "orphan.bin"
    cipher.write_bytes(bytes(16))
    with pytest.raises(ValueError, match="n_input"):
        decrypt_file(cipher, password=PASSWORD)


def test_file_round_trip_random_content(tmp_path):
    rng = np.random.default_rng(20260924)
    data = rng.integers(0, 256, size=1013, dtype=np.uint8)
    source = tmp_path / "rnd.bin"
    source.write_bytes(data.tobytes())
    encrypted = encrypt_file(source, n_input=8, password=PASSWORD)
    decrypted = decrypt_file(encrypted.output_path, password=PASSWORD)
    assert decrypted.output_path.read_bytes() == data.tobytes()
