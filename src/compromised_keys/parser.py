import csv
import json
import logging
from dataclasses import dataclass
from typing import Dict, List

from cryptography import x509

logger = logging.getLogger(__name__)


CCADB_REQUIRED_COLUMNS = {
    "Certificate Record Type",
    "TLS Capable",
    "JSON Array of All Full CRL URLs",
    "JSON Array of Partitioned CRLs",
}


@dataclass
class CCADBScope:
    records_total: int
    eligible_intermediates: int
    crl_sources: List[Dict]
    declared_crl_urls: int = 0


def _cell(value) -> str:
    if value is None:
        return ""
    return str(value).strip()


def is_tls_capable_intermediate(row) -> bool:
    return (
        _cell(row.get("Certificate Record Type")) == "Intermediate Certificate"
        and _cell(row.get("TLS Capable")).casefold() == "true"
    )


def _json_array_urls(row, column: str) -> List[str]:
    value = _cell(row.get(column))
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"Invalid CCADB URL array in {column}") from error
    if parsed is None or parsed == "":
        return []
    if not isinstance(parsed, list) or any(not isinstance(item, str) for item in parsed):
        raise ValueError(f"CCADB {column} must be an array of URL strings")

    urls = []
    for item in parsed:
        url = _cell(item)
        if url and url not in urls:
            urls.append(url)
    return urls


def _row_crl_groups(row) -> List[Dict]:
    full_urls = _json_array_urls(row, "JSON Array of All Full CRL URLs")

    groups = []
    if full_urls:
        groups.append({"crl_type": "full", "urls": full_urls})
    groups.extend(
        {"crl_type": "partitioned", "urls": [url]}
        for url in _json_array_urls(row, "JSON Array of Partitioned CRLs")
    )
    return groups


class CCADBParser:
    @staticmethod
    def load_intermediate_scope(csv_path: str) -> CCADBScope:
        """Parse and validate the CCADB intermediate certificate scope once."""
        sources = []
        seen_urls = set()
        seen_groups = set()
        eligible_intermediates = 0
        records_total = 0

        try:
            with open(csv_path, newline="", encoding="utf-8-sig") as stream:
                reader = csv.DictReader(stream)
                missing_columns = sorted(CCADB_REQUIRED_COLUMNS - set(reader.fieldnames or []))
                if missing_columns:
                    raise ValueError(f"CCADB CSV is missing required columns: {missing_columns}")

                for row in reader:
                    records_total += 1
                    if not is_tls_capable_intermediate(row):
                        continue

                    eligible_intermediates += 1
                    meta = {
                        "ccadb_record_id": _cell(row.get("Salesforce Record ID")),
                        "sha256_fp": _cell(row.get("SHA-256 Fingerprint")),
                        "ca_owner": _cell(row.get("CA Owner")),
                        "certificate_name": _cell(row.get("Certificate Name")),
                    }
                    for group in _row_crl_groups(row):
                        urls = group["urls"]
                        seen_urls.update(urls)
                        group_key = (group["crl_type"], frozenset(urls))
                        if group_key in seen_groups:
                            continue
                        seen_groups.add(group_key)
                        sources.append(
                            {
                                "url": urls[0],
                                "urls": urls,
                                "crl_type": group["crl_type"],
                                **meta,
                            }
                        )
        except (OSError, csv.Error, UnicodeError) as error:
            raise ValueError(f"Could not parse CCADB CSV: {error}") from error

        if eligible_intermediates == 0:
            raise ValueError("CCADB contained no eligible intermediate certificates")

        logger.info(
            "CCADB intermediate scope: %d records, %d eligible, %d logical CRLs, %d disclosed URLs",
            records_total,
            eligible_intermediates,
            len(sources),
            len(seen_urls),
        )
        return CCADBScope(
            records_total=records_total,
            eligible_intermediates=eligible_intermediates,
            crl_sources=sources,
            declared_crl_urls=len(seen_urls),
        )


class CRLParser:
    @staticmethod
    def get_revoked_serials(crl_path: str) -> List[Dict]:
        """Parse CRL file and extract key compromise (reasonCode: 1) entries."""
        revoked_info = []
        with open(crl_path, "rb") as f:
            crl_data = f.read()

        crl = x509.load_der_x509_crl(crl_data)
        issuer = crl.issuer.rfc4514_string()
        try:
            aki_value = crl.extensions.get_extension_for_class(
                x509.AuthorityKeyIdentifier
            ).value.key_identifier
        except x509.ExtensionNotFound:
            aki_value = None

        aki_hex = aki_value.hex() if aki_value else None

        for revoked_cert in crl:
            reason = None
            try:
                reason = revoked_cert.extensions.get_extension_for_class(
                    x509.CRLReason
                ).value.reason
            except x509.ExtensionNotFound:
                continue

            if reason == x509.ReasonFlags.key_compromise:
                revoked_info.append(
                    {
                        "serial_number": format(revoked_cert.serial_number, "x").lower(),
                        "issuer": issuer,
                        "revocation_date": revoked_cert.revocation_date_utc.isoformat(),
                        "authority_key_identifier": aki_hex,
                        "aki_source": "crl" if aki_hex else None,
                    }
                )

        logger.info(f"Parsed {len(revoked_info)} key compromised SNs from {crl_path}")
        return revoked_info
