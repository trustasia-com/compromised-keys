import csv
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from compromised_keys.parser import (
    CCADB_REQUIRED_COLUMNS,
    CCADBParser,
    CRLParser,
    is_tls_capable_intermediate,
)


def _row(full=(), partitions=(), **overrides):
    return {
        "Salesforce Record ID": "record-1",
        "CA Owner": "Test",
        "Certificate Name": "Test CA",
        "SHA-256 Fingerprint": "aabb",
        "Certificate Record Type": "Intermediate Certificate",
        "TLS Capable": "True",
        "JSON Array of All Full CRL URLs": json.dumps(full),
        "JSON Array of Partitioned CRLs": json.dumps(partitions),
        **overrides,
    }


def _snapshot(tmp_path, rows):
    path = tmp_path / "ccadb.csv"
    columns = (
        list(dict.fromkeys(key for row in rows for key in row))
        if rows
        else sorted(CCADB_REQUIRED_COLUMNS)
    )
    with path.open("w", newline="", encoding="utf-8-sig") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)
    return str(path)


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({}, True),
        ({"TLS Capable": " true "}, True),
        ({"TLS Capable": False}, False),
        ({"TLS Capable": None}, False),
        ({"Certificate Record Type": " Intermediate Certificate "}, True),
        ({"Certificate Record Type": "Root Certificate"}, False),
        (
            {
                "Chrome Status": "Not Trusted",
                "Apple Status": "Not Trusted",
                "Mozilla Status": "Not Trusted",
                "Microsoft Status": "Not Trusted",
            },
            True,
        ),
    ],
)
def test_tls_scope(overrides, expected):
    assert is_tls_capable_intermediate(_row(**overrides)) is expected


def test_scope_preserves_attribution_and_partitions(tmp_path):
    full = ["https://example.test/a", "https://example.test/b"]
    partition = "https://example.test/p1"
    path = _snapshot(
        tmp_path,
        [
            _row(full, [partition]),
            _row(["https://example.test/excluded"], **{"TLS Capable": "False"}),
        ],
    )
    scope = CCADBParser.load_intermediate_scope(path)
    assert (scope.records_total, scope.eligible_intermediates, scope.declared_crl_urls) == (2, 1, 3)
    assert [(s["crl_type"], s["urls"]) for s in scope.crl_sources] == [
        ("full", full),
        ("partitioned", [partition]),
    ]
    source = scope.crl_sources[0]
    assert source["url"] == full[0]
    assert source["ccadb_record_id"] == "record-1"
    assert source["certificate_name"] == "Test CA"
    assert source["ca_owner"] == "Test"
    assert source["sha256_fp"] == "aabb"


def test_overlapping_groups_keep_all_mirrors(tmp_path):
    a, b, c = [f"https://example.test/{name}" for name in "abc"]
    path = _snapshot(tmp_path, [_row([a, b], [b]), _row([b, c], [b]), _row([b, a])])
    scope = CCADBParser.load_intermediate_scope(path)
    assert scope.declared_crl_urls == 3
    assert [(s["crl_type"], s["urls"]) for s in scope.crl_sources] == [
        ("full", [a, b]),
        ("partitioned", [b]),
        ("full", [b, c]),
    ]


def test_url_arrays_trim_and_deduplicate(tmp_path):
    path = _snapshot(tmp_path, [_row([" https://example.test/a ", "", "https://example.test/a"])])
    assert CCADBParser.load_intermediate_scope(path).crl_sources[0]["urls"] == [
        "https://example.test/a"
    ]


@pytest.mark.parametrize("value", ["", '""', "null", "[]"])
def test_empty_url_arrays(tmp_path, value):
    path = _snapshot(tmp_path, [_row(**{"JSON Array of All Full CRL URLs": value})])
    assert CCADBParser.load_intermediate_scope(path).crl_sources == []


@pytest.mark.parametrize("value", ['{"url":"https://example.test"}', "[{}]", "broken"])
def test_invalid_url_arrays_fail_closed(tmp_path, value):
    path = _snapshot(tmp_path, [_row(**{"JSON Array of All Full CRL URLs": value})])
    with pytest.raises(ValueError):
        CCADBParser.load_intermediate_scope(path)


@pytest.mark.parametrize("rows", [[], [_row(**{"TLS Capable": "False"})]])
def test_empty_scope_fails_closed(tmp_path, rows):
    with pytest.raises(ValueError, match="no eligible"):
        CCADBParser.load_intermediate_scope(_snapshot(tmp_path, rows))


def test_missing_columns_fail_closed(tmp_path):
    row = _row()
    del row["TLS Capable"]
    with pytest.raises(ValueError, match="missing required columns"):
        CCADBParser.load_intermediate_scope(_snapshot(tmp_path, [row]))


def test_missing_snapshot_fails_closed(tmp_path):
    with pytest.raises(ValueError):
        CCADBParser.load_intermediate_scope(str(tmp_path / "missing.csv"))


def test_crl_retains_only_key_compromise_and_hex_aki(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")]))
        .last_update(now)
        .next_update(now + timedelta(days=1))
        .add_extension(x509.AuthorityKeyIdentifier(bytes.fromhex("00aabb"), None, None), False)
    )
    for serial, reason in [
        (1, x509.ReasonFlags.key_compromise),
        (2, x509.ReasonFlags.superseded),
        (3, None),
    ]:
        revoked = x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(now)
        if reason is not None:
            revoked = revoked.add_extension(x509.CRLReason(reason), False)
        builder = builder.add_revoked_certificate(revoked.build())
    path = tmp_path / "revoked.crl"
    path.write_bytes(builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER))
    records = CRLParser.get_revoked_serials(str(path))
    assert len(records) == 1
    assert records[0]["serial_number"] == "1"
    assert records[0]["issuer"] == "CN=Test CA"
    assert records[0]["authority_key_identifier"] == "00aabb"
    assert records[0]["aki_source"] == "crl"


def test_empty_crl_is_valid(tmp_path, crl_der):
    path = tmp_path / "empty.crl"
    path.write_bytes(crl_der)
    assert CRLParser.get_revoked_serials(str(path)) == []


def test_invalid_crl_raises(tmp_path):
    path = tmp_path / "bad.crl"
    path.write_bytes(b"not a CRL")
    with pytest.raises(ValueError):
        CRLParser.get_revoked_serials(str(path))
    with pytest.raises(OSError):
        CRLParser.get_revoked_serials(str(tmp_path / "missing.crl"))
