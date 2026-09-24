"""Integrity hashing tests (SHA3-256 default, MD5 deprecated legacy)."""

from __future__ import annotations

import hashlib

import numpy as np
import pytest

from aghc_s128.integrity import (
    compare_file_hashes,
    hash_bytes_md5,
    hash_bytes_sha3_256,
    hash_file,
    hash_file_md5,
    hash_file_sha3_256,
)


def test_hash_file_sha3_256_matches_hashlib(tmp_path):
    target = tmp_path / "sample.bin"
    payload = bytes(range(256)) * 3
    target.write_bytes(payload)
    assert hash_file_sha3_256(target) == hashlib.sha3_256(payload).hexdigest()


def test_hash_bytes_sha3_256_array_and_bytes_agree():
    arr = np.arange(100, dtype=np.uint8)
    assert hash_bytes_sha3_256(arr) == hash_bytes_sha3_256(arr.tobytes())


def test_hash_bytes_rejects_bad_type():
    with pytest.raises(TypeError):
        hash_bytes_sha3_256("not bytes")  # type: ignore[arg-type]


def test_hash_file_missing_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        hash_file_sha3_256(tmp_path / "missing.bin")


def test_compare_file_hashes_identical(tmp_path):
    a = tmp_path / "a.bin"
    b = tmp_path / "b.bin"
    payload = b"identical bytes"
    a.write_bytes(payload)
    b.write_bytes(payload)
    comparison = compare_file_hashes(a, b)
    assert comparison.identical
    assert comparison.algorithm == "sha3_256"
    assert comparison.hash_a == comparison.hash_b


def test_compare_file_hashes_different(tmp_path):
    a = tmp_path / "a.bin"
    b = tmp_path / "b.bin"
    a.write_bytes(b"one")
    b.write_bytes(b"two")
    assert not compare_file_hashes(a, b).identical


def test_hash_file_generic_algorithm(tmp_path):
    target = tmp_path / "x.bin"
    target.write_bytes(b"abc")
    assert hash_file(target, "sha256") == hashlib.sha256(b"abc").hexdigest()


def test_md5_helpers_are_deprecated(tmp_path):
    target = tmp_path / "legacy.bin"
    payload = b"legacy check"
    target.write_bytes(payload)
    with pytest.warns(DeprecationWarning):
        digest_file = hash_file_md5(target)
    with pytest.warns(DeprecationWarning):
        digest_bytes = hash_bytes_md5(payload)
    assert digest_file == digest_bytes == hashlib.md5(payload).hexdigest()
