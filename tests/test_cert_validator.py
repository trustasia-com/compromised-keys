"""Tests for compromised_keys.cert_validator.CertValidator."""

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from compromised_keys.cert_validator import CertValidator, ValidationResult
from compromised_keys.lookup import LookupOutcome, LookupRecordResult

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _generate_self_signed_cert(key_type="rsa"):
    """Generate a self-signed certificate and return (cert_pem_bytes, serial_hex, issuer_rfc4514)."""
    if key_type == "rsa":
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    else:
        private_key = ec.generate_private_key(ec.SECP256R1())

    subject = issuer_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Test CA"),
        ]
    )

    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    serial_hex = format(cert.serial_number, "x").lower()
    issuer_rfc = cert.issuer.rfc4514_string()

    return cert_pem, serial_hex, issuer_rfc, cert


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestCertValidator:
    @pytest.fixture
    def validator(self, data_manager):
        return CertValidator(data_manager=data_manager)

    # ---- validate_submission ----

    def test_validate_submission_not_in_db(self, validator):
        """A certificate whose serial is not in the revoked DB should fail validation."""
        cert_pem, serial_hex, issuer_rfc, _ = _generate_self_signed_cert("rsa")
        result = validator.validate_submission(cert_pem)
        assert isinstance(result, ValidationResult)
        assert result.is_valid is False
        assert "not found" in result.error.lower()

    def test_validate_submission_serial_mismatch(self, validator):
        """Providing a wrong claimed_serial should fail."""
        cert_pem, serial_hex, _, _ = _generate_self_signed_cert("rsa")
        result = validator.validate_submission(cert_pem, claimed_serial="000000deadwrong")
        assert result.is_valid is False
        assert "mismatch" in result.error.lower()

    def test_validate_submission_already_has_key(self, validator, data_manager):
        """A cert that already has a public_key in the DB should be rejected."""
        cert_pem, serial_hex, issuer_rfc, _ = _generate_self_signed_cert("rsa")

        # Insert the serial into the DB with a public key already present
        data_manager.save_revoked_certs(
            [
                {
                    "serial_number": serial_hex,
                    "issuer": issuer_rfc,
                    "revocation_date": "2025-01-01T00:00:00",
                }
            ]
        )
        data_manager.record_lookup_results(
            "test",
            [
                LookupRecordResult(
                    {"serial_number": serial_hex, "issuer": issuer_rfc},
                    LookupOutcome.FOUND,
                    info={"publickey": "existing_key", "key_hash": "existing_hash"},
                )
            ],
        )

        result = validator.validate_submission(cert_pem)
        assert result.is_valid is False
        assert "already has" in result.error.lower()

    def test_validate_submission_success(self, validator, data_manager):
        """A valid cert whose serial exists without a key should succeed."""
        cert_pem, serial_hex, issuer_rfc, _ = _generate_self_signed_cert("rsa")

        data_manager.save_revoked_certs(
            [
                {
                    "serial_number": serial_hex,
                    "issuer": issuer_rfc,
                    "revocation_date": "2025-01-01T00:00:00",
                }
            ]
        )

        result = validator.validate_submission(cert_pem)
        assert result.is_valid is True
        assert result.serial_number == serial_hex
        assert result.key_algorithm == "RSA"
        assert len(result.key_hash) == 64

    # ---- apply_submission ----

    def test_apply_submission(self, validator, data_manager):
        """apply_submission should write the key info into the database."""
        cert_pem, serial_hex, issuer_rfc, _ = _generate_self_signed_cert("ec")

        data_manager.save_revoked_certs(
            [
                {
                    "serial_number": serial_hex,
                    "issuer": issuer_rfc,
                    "revocation_date": "2025-01-01T00:00:00",
                }
            ]
        )

        result = validator.validate_submission(cert_pem)
        assert result.is_valid is True

        applied = validator.apply_submission(result)
        assert applied is True

        record = data_manager.get_record_by_serial_and_issuer(serial_hex, issuer_rfc)
        assert record is not None
        assert record["public_key"] is not None
        assert record["key_hash"] == result.key_hash

    def test_apply_invalid_submission(self, validator):
        """apply_submission with an invalid result should return False."""
        bad_result = ValidationResult(is_valid=False, error="test error")
        assert validator.apply_submission(bad_result) is False

    @pytest.mark.parametrize("condition", ["aki_mismatch", "inactive", "excluded"])
    def test_submission_respects_identity_and_record_status(
        self, validator, data_manager, condition
    ):
        pem, serial, issuer, _ = _generate_self_signed_cert("ec")
        data_manager.save_revoked_certs(
            [{"serial_number": serial, "issuer": issuer, "revocation_date": "2026-01-01"}]
        )
        if condition == "excluded":
            data_manager.set_record_exclusion(
                serial, issuer, reason_code="test", rationale="review", created_by="tester"
            )
        else:
            with sqlite3.connect(data_manager.db_path) as conn:
                if condition == "inactive":
                    conn.execute("UPDATE revoked_certs SET cleaned_at='2026-01-01'")
                else:
                    conn.execute("UPDATE revoked_certs SET authority_key_identifier='abcd'")
        assert not validator.validate_submission(pem).is_valid
