"""
Certificate validator for community-submitted certificates.

Validates that:
1. The certificate is parseable (PEM or DER)
2. The serial number matches the claimed value
3. The issuer matches (normalized comparison)
4. The serial+issuer exists in the revoked_certs database
5. Extracts and returns SPKI and key_hash for supplementation
"""

import logging
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes

from compromised_keys.crypto_utils import (
    certificate_matches_record,
    classify_validated_type,
    extract_cert_key_info,
    get_cert_validity,
    is_precertificate,
    normalize_issuer,
    parse_certificate,
)
from compromised_keys.data_manager import DataManager
from compromised_keys.lookup import LookupOutcome, LookupRecordResult

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    is_valid: bool
    error: str = ""
    serial_number: str = ""
    issuer: str = ""
    spki_hex: str = ""
    key_hash: str = ""
    key_algorithm: str = ""
    key_size: int = 0
    not_before: str = ""
    not_after: str = ""
    cert_sha256: str = ""
    is_precert: bool = False
    validated_type: str = ""


class CertValidator:
    """Validates community-submitted certificates for key supplementation."""

    def __init__(self, data_manager: DataManager = None):
        self.data_manager = data_manager or DataManager()

    def validate_submission(
        self,
        cert_data: bytes,
        claimed_serial: str = "",
        claimed_issuer: str = "",
    ) -> ValidationResult:
        """
        Validate a community-submitted certificate.

        :param cert_data: Raw certificate bytes (PEM or DER)
        :param claimed_serial: (optional) Claimed serial number to verify
        :param claimed_issuer: (optional) Claimed issuer to verify
        :return: ValidationResult
        """
        cert = parse_certificate(cert_data)
        if cert is None:
            return ValidationResult(
                is_valid=False,
                error="Failed to parse certificate. Ensure it is valid PEM or DER format.",
            )

        # Extract serial number
        cert_serial = format(cert.serial_number, "x").lower()
        cert_issuer = cert.issuer.rfc4514_string()

        # Verify serial number if claimed
        if claimed_serial:
            try:
                claimed_value = int(claimed_serial, 16)
            except ValueError:
                claimed_value = None
            if claimed_value != cert.serial_number:
                return ValidationResult(
                    is_valid=False,
                    error=f"Serial number mismatch. Certificate has {cert_serial}, claimed {claimed_serial}.",
                )

        # Verify issuer if claimed
        if claimed_issuer and normalize_issuer(cert_issuer) != normalize_issuer(claimed_issuer):
            return ValidationResult(
                is_valid=False,
                error="Issuer mismatch. Certificate issuer does not match claimed issuer.",
            )

        # Check if this serial+issuer exists in revoked_certs DB
        # We need to find a matching record using normalized issuer comparison
        import sqlite3

        found_record = None
        with sqlite3.connect(self.data_manager.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            # Try exact match first
            cursor.execute(
                "SELECT * FROM revoked_certs WHERE serial_number = ?",
                (cert_serial,),
            )
            rows = cursor.fetchall()
            for row in rows:
                if normalize_issuer(dict(row)["issuer"]) == normalize_issuer(cert_issuer):
                    found_record = dict(row)
                    break

        if not found_record:
            return ValidationResult(
                is_valid=False,
                error=f"Certificate serial {cert_serial} not found in revoked keys database. "
                f"Only certificates that were revoked due to key compromise can be submitted.",
            )

        if found_record.get("public_key"):
            return ValidationResult(
                is_valid=False,
                error=f"Certificate serial {cert_serial} already has public key information.",
            )

        if found_record.get("cleaned_at"):
            return ValidationResult(is_valid=False, error="Record is inactive.")
        if not certificate_matches_record(cert, found_record):
            return ValidationResult(
                is_valid=False, error="Certificate AKI does not match the revoked record."
            )
        with sqlite3.connect(self.data_manager.db_path) as conn:
            excluded = conn.execute(
                "SELECT 1 FROM record_exclusions WHERE serial_number=? AND issuer=? AND active=1 "
                "AND (expires_at IS NULL OR expires_at > datetime('now'))",
                (found_record["serial_number"], found_record["issuer"]),
            ).fetchone()
        if excluded:
            return ValidationResult(
                is_valid=False, error="Record is excluded from supplementation."
            )

        # Extract key info
        try:
            spki_hex, key_hash, alg, size = extract_cert_key_info(cert)
        except Exception as e:
            return ValidationResult(
                is_valid=False,
                error=f"Failed to extract key info: {e}",
            )

        if not key_hash:
            return ValidationResult(
                is_valid=False,
                error="Could not compute key hash. Unsupported key algorithm.",
            )

        not_before, not_after = get_cert_validity(cert)

        return ValidationResult(
            is_valid=True,
            serial_number=cert_serial,
            issuer=found_record["issuer"],
            spki_hex=spki_hex,
            key_hash=key_hash,
            key_algorithm=alg,
            key_size=size,
            not_before=not_before,
            not_after=not_after,
            cert_sha256=cert.fingerprint(hashes.SHA256()).hex(),
            is_precert=is_precertificate(cert),
            validated_type=classify_validated_type(cert),
        )

    def apply_submission(self, result: ValidationResult) -> bool:
        """Apply a validated submission to the database."""
        if not result.is_valid:
            return False

        self.data_manager.record_lookup_results(
            "community_submission",
            [
                LookupRecordResult(
                    {"serial_number": result.serial_number, "issuer": result.issuer},
                    LookupOutcome.FOUND,
                    info={
                        "publickey": result.spki_hex,
                        "key_hash": result.key_hash,
                        "key_algorithm": result.key_algorithm,
                        "key_size": result.key_size,
                        "notbefore": result.not_before,
                        "notafter": result.not_after,
                        "cert_sha256": result.cert_sha256,
                        "is_precert": result.is_precert,
                        "validated_type": result.validated_type,
                    },
                )
            ],
        )
        logger.info(f"Applied community submission for SN={result.serial_number}")
        return True
