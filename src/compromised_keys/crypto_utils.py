"""
Shared cryptographic utilities for key hash computation.

Key hash format follows dwk_blocklists (github.com/CVE-2008-0166/dwk_blocklists):
  - RSA: SHA-256 of modulus bytes (big-endian, no leading zeros)
  - EC:  SHA-256 of X-coordinate bytes (big-endian, no leading zeros)
  - Output: lowercase hex, 64 characters
"""

import hashlib
import json
import logging
import re
from functools import lru_cache
from typing import Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

logger = logging.getLogger(__name__)

VALIDATED_TYPE_BY_POLICY_OID = {
    "2.23.140.1.2.1": "DV",
    "2.23.140.1.2.2": "OV",
    "2.23.140.1.2.3": "IV",
    "2.23.140.1.1": "EV",
}


@lru_cache(maxsize=4096)
def normalize_issuer(issuer_str: str) -> str:
    """Canonicalize DN attributes without discarding escaped delimiters or word boundaries."""
    if not issuer_str:
        return ""
    value = issuer_str.strip()
    if value.startswith("/"):
        value = re.sub(r"(?<!\\)/(?=[A-Za-z0-9.]+\s*=)", ",", value[1:])
    value = re.sub(r"(?<!\\);(?=\s*[A-Za-z0-9.]+\s*=)", ",", value)
    value = re.sub(r"(?i)(^|(?<!\\)[,+])\s*OID\(([0-9.]+)\)\s*=", r"\1\2=", value)
    value = re.sub(
        r"(^|(?<!\\)[,+])\s*([A-Za-z0-9.]+)\s*=\s*",
        lambda match: match[1] + match[2].upper() + "=",
        value,
    )
    value = re.sub(r"(?<!\\)\s+(?=[,+])", "", value)
    aliases = {
        "EMAILADDRESS": NameOID.EMAIL_ADDRESS,
        "EMAIL": NameOID.EMAIL_ADDRESS,
        "E": NameOID.EMAIL_ADDRESS,
        "SERIALNUMBER": NameOID.SERIAL_NUMBER,
        "GIVENNAME": NameOID.GIVEN_NAME,
        "SURNAME": NameOID.SURNAME,
    }
    try:
        name = x509.Name.from_rfc4514_string(value, aliases)
    except ValueError:
        # Some historical exports omit escaping for commas inside organization names.
        escaped = re.sub(r"(?<!\\),(?!\s*[A-Za-z0-9.]+\s*=)", r"\\,", value)
        try:
            name = x509.Name.from_rfc4514_string(escaped, aliases)
        except ValueError:
            # Unparseable text must never collide with a parsed DN.
            return "unparsed:" + issuer_str.strip()
    rdns = sorted(
        sorted((attr.oid.dotted_string, " ".join(attr.value.split()).casefold()) for attr in rdn)
        for rdn in name.rdns
    )
    return json.dumps(rdns, ensure_ascii=True, separators=(",", ":"))


def _int_to_bytes_unsigned(n: int) -> bytes:
    """Convert a positive integer to big-endian bytes with no leading zeros.

    Matches Go's big.Int.Bytes() behavior used by dwk_blocklists.
    """
    if n == 0:
        return b"\x00"
    byte_len = (n.bit_length() + 7) // 8
    return n.to_bytes(byte_len, byteorder="big").lstrip(b"\x00") or b"\x00"


def certificate_matches_record(cert: x509.Certificate, record: dict) -> bool:
    """Check certificate identity independently of search-service response labels."""
    try:
        if cert.serial_number != int(record["serial_number"], 16):
            return False
        if normalize_issuer(cert.issuer.rfc4514_string()) != normalize_issuer(record["issuer"]):
            return False
        aki = record.get("authority_key_identifier")
        if aki:
            actual = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
            if actual.key_identifier != bytes.fromhex(aki):
                return False
        return True
    except (ValueError, TypeError, KeyError, x509.ExtensionNotFound):
        return False


def compute_key_hash_from_public_key(pub) -> Tuple[str, str, int]:
    """Compute key hash from a public key object.

    Returns (key_hash, algorithm, key_size).
    """
    if isinstance(pub, rsa.RSAPublicKey):
        mod_bytes = _int_to_bytes_unsigned(pub.public_numbers().n)
        key_hash = hashlib.sha256(mod_bytes).hexdigest()
        return key_hash, "RSA", pub.key_size
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        x_bytes = _int_to_bytes_unsigned(pub.public_numbers().x)
        key_hash = hashlib.sha256(x_bytes).hexdigest()
        return key_hash, "EC", pub.key_size
    return "", "", 0


def extract_cert_key_info(cert: x509.Certificate) -> Tuple[str, str, str, int]:
    """Extract SPKI hex, key hash, algorithm, and key size from a certificate.

    Returns (spki_hex, key_hash, algorithm, key_size).
    """
    pub = cert.public_key()
    spki = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    spki_hex = spki.hex()
    key_hash, alg, size = compute_key_hash_from_public_key(pub)
    return spki_hex, key_hash, alg, size


def classify_validated_type(cert: x509.Certificate) -> Optional[str]:
    """Classify a certificate using CA/B Forum validation policy OIDs."""
    try:
        policies = cert.extensions.get_extension_for_class(x509.CertificatePolicies).value
    except x509.ExtensionNotFound:
        return None

    matches = {
        policy.policy_identifier.dotted_string: VALIDATED_TYPE_BY_POLICY_OID[
            policy.policy_identifier.dotted_string
        ]
        for policy in policies
        if policy.policy_identifier.dotted_string in VALIDATED_TYPE_BY_POLICY_OID
    }
    validated_types = set(matches.values())
    if len(validated_types) == 1:
        return next(iter(validated_types))
    if len(validated_types) > 1:
        logger.warning(
            "Certificate serial %x has conflicting CA/B validation policy OIDs: %s",
            cert.serial_number,
            ", ".join(sorted(matches)),
        )
    return None


def is_precertificate(cert: x509.Certificate) -> bool:
    """Return whether a certificate has the critical CT poison extension."""
    try:
        extension = cert.extensions.get_extension_for_oid(ExtensionOID.PRECERT_POISON)
    except x509.ExtensionNotFound:
        return False
    return extension.critical


def parse_certificate(data: bytes) -> Optional[x509.Certificate]:
    """Parse a certificate from PEM or DER format."""
    try:
        if b"-----BEGIN CERTIFICATE-----" in data:
            return x509.load_pem_x509_certificate(data)
        else:
            return x509.load_der_x509_certificate(data)
    except Exception as e:
        logger.error(f"Error parsing certificate: {e}")
        return None


def get_cert_validity(cert: x509.Certificate) -> Tuple[str, str]:
    """Get certificate validity period as ISO strings."""
    return cert.not_valid_before_utc.isoformat(), cert.not_valid_after_utc.isoformat()
