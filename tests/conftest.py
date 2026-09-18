"""Shared test fixtures for the compromised_keys test suite."""

from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from compromised_keys.data_manager import DataManager


@pytest.fixture(scope="session")
def crl_der():
    now = datetime.now(timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")]))
        .last_update(now)
        .next_update(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return crl.public_bytes(serialization.Encoding.DER)


@pytest.fixture
def tmp_db(tmp_path):
    """Create a temporary SQLite database path."""
    return str(tmp_path / "test_compromised_keys.db")


@pytest.fixture
def data_manager(tmp_db):
    """Return a DataManager backed by a temporary database."""
    return DataManager(db_path=tmp_db)


@pytest.fixture
def sample_certs():
    """Return a list of sample revoked certificate dicts."""
    return [
        {
            "serial_number": "0a1b2c3d4e",
            "issuer": "CN=Test CA,O=Test Org,C=US",
            "revocation_date": "2025-01-15T00:00:00",
        },
        {
            "serial_number": "ff00ee11dd",
            "issuer": "CN=Test CA,O=Test Org,C=US",
            "revocation_date": "2025-02-20T12:30:00",
        },
        {
            "serial_number": "aabbccddee",
            "issuer": "CN=Another CA,O=Another Org,C=DE",
            "revocation_date": "2025-03-01T08:00:00",
        },
    ]
