import pytest

from compromised_keys import cli, config


def test_doctor_fails_for_unsupported_crtsh_mode(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "compromised_keys.db"))
    monkeypatch.setattr(config, "DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(config, "CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr(config, "CRTSH_MODE", "unsupported")

    with pytest.raises(SystemExit) as error:
        cli.main(["doctor"])

    assert error.value.code == 1


def test_concurrent_writer_is_rejected(monkeypatch, tmp_path):
    from filelock import FileLock

    from compromised_keys import cli, config

    database = tmp_path / "history.db"
    monkeypatch.setattr(config, "DB_PATH", str(database))
    with FileLock(str(database) + ".lock"), pytest.raises(SystemExit) as error:
        cli.main(["export"])
    assert error.value.code == 1
    assert not database.exists()


def test_failed_sync_writes_report_and_exits_nonzero(monkeypatch, tmp_path):
    import json
    from types import SimpleNamespace

    from compromised_keys import cli
    from compromised_keys.main import SyncError

    report = {"release": {"status": "blocked"}, "stages": {}}

    async def fail(**_kwargs):
        raise SyncError("injected", report=report)

    monkeypatch.setattr(
        "compromised_keys.main.CompromisedKeysManager", lambda: SimpleNamespace(run_once=fail)
    )
    output = tmp_path / "report.json"
    args = cli.parse_args(["sync", "--report", str(output)])
    with pytest.raises(SystemExit) as error:
        cli.cmd_sync(args)
    assert error.value.code == 1
    assert json.loads(output.read_text()) == report


def test_check_missing_input_is_not_success(monkeypatch, tmp_path):
    from compromised_keys.exporter import Exporter

    monkeypatch.setattr(config, "DATA_DIR", str(tmp_path))
    Exporter(csv_dir=str(tmp_path), bf_dir=str(tmp_path)).export_all([])
    with pytest.raises(SystemExit) as error:
        cli.main(["check", str(tmp_path / "missing.csr")])
    assert error.value.code == 1


def test_check_processes_all_inputs_after_a_match(monkeypatch, tmp_path, capsys):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    from compromised_keys.crypto_utils import compute_key_hash_from_public_key
    from compromised_keys.exporter import Exporter

    monkeypatch.setattr(config, "DATA_DIR", str(tmp_path))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.test")]))
        .sign(key, hashes.SHA256())
    )
    csr_path = tmp_path / "test.csr"
    csr_path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))
    fingerprint, _algorithm, _size = compute_key_hash_from_public_key(csr.public_key())
    Exporter(csv_dir=str(tmp_path), bf_dir=str(tmp_path)).export_all([{"key_hash": fingerprint}])
    with pytest.raises(SystemExit) as error:
        cli.main(["check", str(csr_path), str(tmp_path / "missing.csr")])
    assert error.value.code == 2
    output = capsys.readouterr()
    assert "POSSIBLE MATCH" in output.out
    assert "missing.csr" in output.err
