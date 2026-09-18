"""Tests for compromised_keys.exporter.Exporter."""

import csv
import hashlib
import json
from datetime import datetime

import pytest
from pybloom_live import BloomFilter

from compromised_keys.exporter import Exporter


@pytest.fixture
def exporter(tmp_path):
    """Create an Exporter that writes into a temporary directory."""
    out_dir = str(tmp_path / "export_output")
    return Exporter(csv_dir=out_dir, bf_dir=out_dir)


@pytest.fixture
def compromised_keys_data():
    """Minimal list of compromised key dicts for export tests."""
    return [
        {
            "serial_number": "0a1b2c",
            "issuer": "CN=Test CA,O=Test,C=US",
            "revocation_date": "2025-01-01T00:00:00",
            "public_key": "deadbeef",
            "key_hash": "abc123",
            "key_algorithm": "RSA",
            "key_size": 2048,
            "is_precert": 0,
            "validated_type": "DV",
            "notbefore": "2024-01-01",
            "notafter": "2025-01-01",
            "cert_sha256": "sha256val",
        },
        {
            "serial_number": "ff00ee",
            "issuer": "CN=Other CA,O=Other,C=DE",
            "revocation_date": "2025-02-01T00:00:00",
            "public_key": "cafebabe",
            "key_hash": "def456",
            "key_algorithm": "EC",
            "key_size": 256,
            "is_precert": 1,
            "validated_type": "OV",
            "notbefore": "2024-06-01",
            "notafter": "2025-06-01",
            "cert_sha256": "sha256val2",
        },
    ]


def test_export_produces_consistent_csv_bloom_and_manifest(exporter, compromised_keys_data):
    version = exporter.export_all(compromised_keys_data)

    with open(exporter.csv_path, newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    assert len(rows) == len(compromised_keys_data)
    for row, expected in zip(rows, compromised_keys_data, strict=True):
        assert all(row[field] == str(value) for field, value in expected.items())
        assert row["crt_sh_url"] == f"https://crt.sh/?serial={expected['serial_number']}"

    with open(exporter.bf_path, "rb") as stream:
        bloom = BloomFilter.fromfile(stream)
    assert all(item["key_hash"] in bloom for item in compromised_keys_data)

    with open(exporter.metadata_path, encoding="utf-8") as stream:
        manifest = json.load(stream)
    assert manifest["version"] == version
    assert manifest["total_keys"] == len(rows)
    assert manifest["schema_version"] == "3.0"
    assert manifest["updated_at"].endswith("Z")
    datetime.fromisoformat(manifest["updated_at"].replace("Z", "+00:00"))
    for kind, path in (("csv", exporter.csv_path), ("bloom_filter", exporter.bf_path)):
        with open(path, "rb") as stream:
            assert manifest["files"][kind]["sha256"] == hashlib.sha256(stream.read()).hexdigest()


def test_custom_directory_contains_all_outputs(tmp_path, monkeypatch):
    from compromised_keys import config

    default = tmp_path / "default"
    monkeypatch.setattr(config, "DATA_DIR", str(default))
    custom = tmp_path / "custom"
    Exporter(str(custom)).export_all([])
    assert {path.name for path in custom.iterdir()} == {
        "compromised_keys.csv",
        "compromised_keys.bf",
        "metadata.json",
    }
    assert not default.exists()


def test_empty_export_replaces_previous_data(exporter, compromised_keys_data):
    exporter.export_all(compromised_keys_data)
    exporter.export_all([])
    with open(exporter.metadata_path, encoding="utf-8") as stream:
        assert json.load(stream)["total_keys"] == 0
    with open(exporter.csv_path, newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        assert "key_hash" in reader.fieldnames
        assert list(reader) == []
    with open(exporter.bf_path, "rb") as stream:
        assert len(BloomFilter.fromfile(stream)) == 0


def test_bloom_filter_ignores_missing_hashes(exporter):
    exporter.generate_bloom_filter([{"serial_number": "aa", "key_hash": None}])
    with open(exporter.bf_path, "rb") as stream:
        assert len(BloomFilter.fromfile(stream)) == 0


def test_write_failure_propagates(exporter, monkeypatch):
    def fail(*_args, **_kwargs):
        raise OSError("injected write failure")

    monkeypatch.setattr("compromised_keys.exporter.atomic_write", fail)
    with pytest.raises(OSError):
        exporter.export_all([])
