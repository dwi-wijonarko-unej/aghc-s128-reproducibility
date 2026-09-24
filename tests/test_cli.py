"""CLI smoke tests (in-process; no shell, no password on argv)."""

from __future__ import annotations

import json

import pytest

from aghc_s128.cli import main

PASSWORD = "aghc-cli-smoke-test"


@pytest.fixture()
def pw_env(monkeypatch):
    monkeypatch.setenv("AGHC_PASSWORD", PASSWORD)


@pytest.fixture()
def sample(tmp_path):
    source = tmp_path / "cli_sample.bin"
    source.write_bytes(bytes((i * 11 + 5) % 256 for i in range(120)))
    return source


def test_encrypt_decrypt_round_trip(tmp_path, sample, pw_env, capsys):
    cipher = tmp_path / "cli_sample.enc"
    assert main(["encrypt", str(sample), "-o", str(cipher), "--n", "4"]) == 0
    assert cipher.is_file()
    sidecar = tmp_path / "cli_sample.enc.aghc-s128.json"
    assert sidecar.is_file()

    out = tmp_path / "cli_sample.out"
    assert main(["decrypt", str(cipher), "-o", str(out)]) == 0
    assert out.read_bytes() == sample.read_bytes()
    # password must never appear in program output
    assert PASSWORD not in capsys.readouterr().out


def test_decrypt_verify_flag_catches_corruption(tmp_path, sample, pw_env):
    cipher = tmp_path / "cli_sample.enc"
    assert main(["encrypt", str(sample), "-o", str(cipher), "--n", "4"]) == 0
    payload = bytearray(cipher.read_bytes())
    payload[0] ^= 0xFF
    cipher.write_bytes(bytes(payload))
    out = tmp_path / "cli_sample.out"
    assert (
        main(["decrypt", str(cipher), "-o", str(out), "--verify"]) == 1
    )


def test_missing_password_env_fails_cleanly(tmp_path, sample, monkeypatch):
    monkeypatch.delenv("AGHC_PASSWORD", raising=False)
    cipher = tmp_path / "x.enc"
    code = main(["encrypt", str(sample), "-o", str(cipher), "--n", "4"])
    assert code == 2
    assert not cipher.exists()


def test_analyze_writes_report_and_figure(tmp_path, sample, pw_env):
    cipher = tmp_path / "cli_sample.enc"
    assert main(["encrypt", str(sample), "-o", str(cipher), "--n", "4"]) == 0
    out_dir = tmp_path / "analysis"
    assert (
        main(["analyze", str(sample), str(cipher), "--output-dir", str(out_dir)]) == 0
    )
    report = json.loads((out_dir / "analysis_cli_sample.json").read_text())
    assert "entropy_encrypted" in report["metrics"]
    assert "monobit_verdict_encrypted" in report["metrics"]
    assert (out_dir / "cli_sample_histogram.png").is_file()


def test_analyze_with_decrypted_integrity(tmp_path, sample, pw_env):
    cipher = tmp_path / "cli_sample.enc"
    main(["encrypt", str(sample), "-o", str(cipher), "--n", "4"])
    plain = tmp_path / "cli_sample.out"
    main(["decrypt", str(cipher), "-o", str(plain)])
    out_dir = tmp_path / "analysis"
    assert (
        main([
            "analyze", str(sample), str(cipher),
            "--decrypted", str(plain),
            "--output-dir", str(out_dir),
        ])
        == 0
    )
    report = json.loads((out_dir / "analysis_cli_sample.json").read_text())
    assert report["integrity"]["identical"] is True


def test_key_sensitivity_command(tmp_path, pw_env, capsys):
    data = bytes((i * 7) % 256 for i in range(200))
    a = tmp_path / "a.enc"
    b = tmp_path / "b.enc"
    from aghc_s128 import encrypt_file

    encrypt_file_write(tmp_path / "src_a.bin", data, a)
    encrypt_file_write(tmp_path / "src_b.bin", data, b, password=PASSWORD + "-alt")
    out_dir = tmp_path / "ks"
    assert main(["key-sensitivity", str(a), str(b), "--output-dir", str(out_dir)]) == 0
    report = json.loads((out_dir / "key_sensitivity.json").read_text())
    assert "key_sensitivity_percent" in report["metrics"]
    assert (out_dir / "key_sensitivity.png").is_file()


def encrypt_file_write(source_path, payload, cipher_path, password=PASSWORD):
    source_path.write_bytes(payload)
    from aghc_s128 import encrypt_file

    encrypt_file(source_path, cipher_path, n_input=4, password=password,
                 write_metadata_sidecar=False)


def test_validate_command(tmp_path, pw_env, capsys):
    assert main(["validate"]) == 0
    out = capsys.readouterr().out
    assert "ALL CHECKS PASSED" in out


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0


def test_reproduce_quick_demo_config(tmp_path, pw_env):
    """End-to-end `reproduce` smoke against the shipped quick-demo config."""
    from pathlib import Path

    repo_root = Path(__file__).resolve().parents[1]
    config = repo_root / "configs" / "quick_demo.yaml"
    if not config.is_file():
        pytest.skip("configs/quick_demo.yaml not present yet")
    assert main(["reproduce", "--config", str(config)]) == 0
    logs = list((repo_root / "results" / "example_outputs" / "logs").glob("*.json"))
    assert logs, "expected a JSON log from the quick demo run"
