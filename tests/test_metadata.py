"""Metadata sidecar tests: contents, privacy rules, decryption workflow."""

from __future__ import annotations

import json

import pytest

from aghc_s128 import decrypt_file, encrypt_file
from aghc_s128.metadata import (
    build_encryption_metadata,
    read_metadata,
    runtime_environment_summary,
    sidecar_path_for,
    write_metadata,
)

PASSWORD = "aghc-metadata-secret-test"


def _encrypt_sample(tmp_path, name="doc.bin", size=40):
    source = tmp_path / name
    source.write_bytes(bytes((7 * i + 3) % 256 for i in range(size)))
    return source, encrypt_file(source, n_input=4, password=PASSWORD)


def test_sidecar_written_next_to_ciphertext(tmp_path):
    source, result = _encrypt_sample(tmp_path)
    expected_sidecar = sidecar_path_for(result.output_path)
    assert result.metadata_path == expected_sidecar
    assert expected_sidecar.name == "doc_encrypted.bin.aghc-s128.json"
    assert expected_sidecar.is_file()


def test_metadata_contains_required_fields(tmp_path):
    _, result = _encrypt_sample(tmp_path)
    metadata = json.loads(result.metadata_path.read_text())
    assert metadata["algorithm"]["id"] == "AGHC-S128"
    assert metadata["algorithm"]["modulus"] == 256
    assert metadata["algorithm"]["residual_scheme"] == "shift128"
    assert metadata["n_input"] == 4
    assert metadata["effective_matrix_size"] == 8
    assert isinstance(metadata["trial_index"], int)
    assert metadata["input_size_bytes"] == 40
    assert metadata["output_size_bytes"] == 40
    assert len(metadata["plaintext_sha3_256"]) == 64
    assert len(metadata["ciphertext_sha3_256"]) == 64
    assert "T" in metadata["created_utc"]  # ISO UTC timestamp
    assert "python_version" in metadata["runtime_environment"]


def test_metadata_never_contains_password_or_secrets(tmp_path):
    source, result = _encrypt_sample(tmp_path)
    raw = result.metadata_path.read_text()
    assert PASSWORD not in raw
    assert "password" not in raw.lower()
    # no password-derived seed material
    assert "numeric_seed" not in raw
    assert "chaos_seed" not in raw
    parsed = json.loads(raw)
    assert "password" not in parsed


def test_metadata_stores_basename_only_no_absolute_paths(tmp_path):
    nested = tmp_path / "deep" / "folder"
    nested.mkdir(parents=True)
    source = nested / "private_name.bin"
    source.write_bytes(b"x" * 24)
    result = encrypt_file(source, n_input=2, password=PASSWORD)
    raw = result.metadata_path.read_text()
    assert "private_name.bin" in raw
    assert str(tmp_path) not in raw  # no absolute path leakage
    assert "/home/" not in raw and "/Users/" not in raw and "C:\\" not in raw


def test_metadata_drives_decryption_workflow(tmp_path):
    """Decrypt without passing n or trial: both come from the sidecar."""
    source, result = _encrypt_sample(tmp_path, size=30)
    decrypted = decrypt_file(result.output_path, password=PASSWORD)
    assert decrypted.output_path.read_bytes() == source.read_bytes()
    assert decrypted.trial_index_used == result.trial_index
    assert decrypted.trial_index_source == "explicit"


def test_explicit_arguments_override_metadata(tmp_path):
    source, result = _encrypt_sample(tmp_path, size=30)
    decrypted = decrypt_file(
        result.output_path, n_input=4, password=PASSWORD,
        trial_index=result.trial_index,
    )
    assert decrypted.output_path.read_bytes() == source.read_bytes()
    assert decrypted.trial_index_used == result.trial_index

def test_read_metadata_rejects_wrong_algorithm(tmp_path):
    payload = {"algorithm": {"id": "NOT-AGHC"}, "n_input": 1, "trial_index": 0}
    sidecar = write_metadata(payload, tmp_path / "x.bin")
    with pytest.raises(ValueError, match="AGHC-S128"):
        read_metadata(sidecar)


def test_read_metadata_rejects_missing_keys(tmp_path):
    payload = {"algorithm": {"id": "AGHC-S128"}}
    sidecar = write_metadata(payload, tmp_path / "y.bin")
    with pytest.raises(ValueError, match="n_input"):
        read_metadata(sidecar)


def test_read_metadata_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        read_metadata(tmp_path / "ghost.json")


def test_read_metadata_rejects_invalid_json(tmp_path):
    target = tmp_path / "broken.aghc-s128.json"
    target.write_text("{not json")
    with pytest.raises(ValueError, match="invalid metadata JSON"):
        read_metadata(target)


def test_build_encryption_metadata_minimal():
    metadata = build_encryption_metadata(
        n_input=2,
        effective_matrix_size=4,
        trial_index=3,
        input_filename="/absolute/path/leak.txt",
        input_size_bytes=10,
        output_size_bytes=10,
        plaintext_sha3_256="a" * 64,
        ciphertext_sha3_256="b" * 64,
    )
    assert metadata["input_filename"] == "leak.txt"  # basename only
    assert metadata["trial_index"] == 3


def test_runtime_environment_summary_has_no_identifying_data():
    summary = runtime_environment_summary()
    assert "python_version" in summary
    assert "aghc_s128_version" in summary
    joined = json.dumps(summary)
    for banned in ("user", "home", "login", "token", "key="):
        assert banned not in joined.lower()
