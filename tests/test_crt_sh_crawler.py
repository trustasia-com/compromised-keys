"""Tests for crt.sh crawler and shared crypto utilities."""

from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID, ObjectIdentifier

import compromised_keys.crypto_utils as crypto_utils
from compromised_keys.crt_sh_crawler import (
    CrtShHttpProvider,
    CrtShPostgresProvider,
    CrtShSupplementer,
    _build_cert_info,
)
from compromised_keys.crypto_utils import (
    _int_to_bytes_unsigned,
    extract_cert_key_info,
    normalize_issuer,
    parse_certificate,
)
from compromised_keys.lookup import LookupOutcome, LookupProviderResult, LookupRecordResult

# ---------------------------------------------------------------------------
# normalize_issuer
# ---------------------------------------------------------------------------


class TestNormalizeIssuer:
    def test_basic(self):
        result = normalize_issuer("CN=Test CA,O=Test Org,C=US")
        assert "test ca" in result
        assert "test org" in result
        assert "2.5.4.6" in result

    def test_empty(self):
        assert normalize_issuer("") == ""

    def test_slash_vs_comma(self):
        slash = normalize_issuer("/C=US/O=Org/CN=CA")
        comma = normalize_issuer("C=US,O=Org,CN=CA")
        assert slash == comma

    def test_semicolon(self):
        semi = normalize_issuer("C=US;O=Org;CN=CA")
        comma = normalize_issuer("C=US,O=Org,CN=CA")
        assert semi == comma

    def test_case_insensitive(self):
        assert normalize_issuer("CN=FOO") == normalize_issuer("cn=foo")

    def test_sorts(self):
        a = normalize_issuer("O=Org,CN=CA,C=US")
        b = normalize_issuer("C=US,CN=CA,O=Org")
        assert a == b

    def test_strips_whitespace(self):
        result = normalize_issuer("CN = CA , O = Org")
        assert result == normalize_issuer("CN=CA,O=Org")

    @pytest.mark.parametrize(
        ("left", "right"),
        [
            ("CN=Test CA", "CN=TestCA"),
            (r"CN=CA\,O=Other", "CN=CA,O=Other"),
            ("CN=CA+O=Org", "CN=CA,O=Org"),
            ("CN=CA/Division", "CN=CA,Division"),
        ],
    )
    def test_distinct_names_do_not_collide(self, left, right):
        assert normalize_issuer(left) != normalize_issuer(right)

    @pytest.mark.parametrize(
        ("legacy", "rfc4514"),
        [
            ("C=US, O=DigiCert, Inc., CN=CA", r"CN=CA,O=DigiCert\, Inc.,C=US"),
            ("CN=CA, OID(2.5.4.97)=VATHU-123", "2.5.4.97=VATHU-123,CN=CA"),
            ("CN=CA, Email=info@example.com", "1.2.840.113549.1.9.1=info@example.com,CN=CA"),
        ],
    )
    def test_legacy_dn_formats(self, legacy, rfc4514):
        assert normalize_issuer(legacy) == normalize_issuer(rfc4514)


# ---------------------------------------------------------------------------
# extract_cert_key_info
# ---------------------------------------------------------------------------


def _make_cert_der(key_type="rsa"):
    """Generate a self-signed certificate and return raw DER bytes."""
    if key_type == "rsa":
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    else:
        private_key = ec.generate_private_key(ec.SECP256R1())

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Test"),
        ]
    )
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
        .sign(private_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER), private_key


def _make_certificate(policy_oids=(), precert_poison_critical=None):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Metadata Test")])
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(0x1234)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
    )
    if policy_oids:
        builder = builder.add_extension(
            x509.CertificatePolicies(
                [x509.PolicyInformation(ObjectIdentifier(oid), None) for oid in policy_oids]
            ),
            critical=False,
        )
    if precert_poison_critical is not None:
        builder = builder.add_extension(
            x509.PrecertPoison(),
            critical=precert_poison_critical,
        )
    return builder.sign(private_key, hashes.SHA256())


@pytest.mark.parametrize(
    ("policy_oid", "expected"),
    [
        ("2.23.140.1.2.1", "DV"),
        ("2.23.140.1.2.2", "OV"),
        ("2.23.140.1.2.3", "IV"),
        ("2.23.140.1.1", "EV"),
    ],
)
def test_classify_validated_type_from_cabf_policy(policy_oid, expected):
    cert = _make_certificate(policy_oids=[policy_oid])

    assert crypto_utils.classify_validated_type(cert) == expected


@pytest.mark.parametrize(
    "policy_oids",
    [(), ("1.2.3.4.5",)],
)
def test_classify_validated_type_returns_none_without_matching_policy(policy_oids):
    cert = _make_certificate(policy_oids=policy_oids)

    assert crypto_utils.classify_validated_type(cert) is None


def test_classify_validated_type_rejects_conflicting_cabf_policies(caplog):
    cert = _make_certificate(policy_oids=["2.23.140.1.2.1", "2.23.140.1.1"])

    with caplog.at_level("WARNING"):
        result = crypto_utils.classify_validated_type(cert)

    assert result is None
    assert "1234" in caplog.text
    assert "2.23.140.1.2.1" in caplog.text
    assert "2.23.140.1.1" in caplog.text


@pytest.mark.parametrize(
    ("precert_poison_critical", "expected"),
    [(True, True), (False, False), (None, False)],
)
def test_is_precertificate_requires_critical_poison(precert_poison_critical, expected):
    cert = _make_certificate(precert_poison_critical=precert_poison_critical)

    assert crypto_utils.is_precertificate(cert) is expected


def test_build_cert_info_includes_der_metadata():
    cert = _make_certificate(
        policy_oids=["2.23.140.1.2.1"],
        precert_poison_critical=True,
    )

    info = _build_cert_info(cert)

    assert info["validated_type"] == "DV"
    assert info["is_precert"] is True


@pytest.mark.parametrize("wrong_field", ["serial_number", "authority_key_identifier"])
def test_postgres_rejects_certificate_identity_mismatch(wrong_field):
    cert = _make_certificate()
    record = {
        "serial_number": format(cert.serial_number, "x"),
        "issuer": cert.issuer.rfc4514_string(),
    }
    record[wrong_field] = "abcd"
    result = CrtShPostgresProvider._match_records(
        [record], {record["serial_number"]: [(1, cert.public_bytes(serialization.Encoding.DER))]}
    )
    assert result[0].outcome == LookupOutcome.IDENTITY_MISMATCH


class TestExtractCertKeyInfo:
    def test_rsa_der(self):
        der, _ = _make_cert_der("rsa")
        cert = parse_certificate(der)
        spki_hex, key_hash, alg, size = extract_cert_key_info(cert)
        assert spki_hex is not None
        assert key_hash is not None
        assert len(key_hash) == 64
        assert alg == "RSA"
        assert size == 2048

    def test_ec_der(self):
        der, _ = _make_cert_der("ec")
        cert = parse_certificate(der)
        spki_hex, key_hash, alg, size = extract_cert_key_info(cert)
        assert spki_hex is not None
        assert key_hash is not None
        assert len(key_hash) == 64
        assert alg == "EC"

    def test_pem_input(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PEM Test")])
        now = datetime.now(timezone.utc)
        cert_obj = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=1))
            .sign(private_key, hashes.SHA256())
        )
        pem = cert_obj.public_bytes(serialization.Encoding.PEM)
        cert = parse_certificate(pem)
        assert cert is not None
        spki_hex, key_hash, alg, size = extract_cert_key_info(cert)
        assert spki_hex is not None
        assert key_hash is not None

    def test_garbage_returns_none(self):
        cert = parse_certificate(b"not a cert")
        assert cert is None

    def test_empty_bytes_returns_none(self):
        cert = parse_certificate(b"")
        assert cert is None


class TestKeyHashConsistency:
    """Verify certificate key hashes against independent reference calculations."""

    def test_rsa_matches_dwk_approach(self):
        """Verify our hash matches the dwk_blocklists approach:
        SHA256 of modulus bytes with no leading zeros."""
        import hashlib

        der, key = _make_cert_der("rsa")
        cert = parse_certificate(der)
        _, key_hash, _, _ = extract_cert_key_info(cert)

        # Manually compute using the dwk approach
        pub = cert.public_key()
        modulus = pub.public_numbers().n
        mod_bytes = _int_to_bytes_unsigned(modulus)
        expected = hashlib.sha256(mod_bytes).hexdigest()
        assert key_hash == expected

    def test_ec_matches_dwk_approach(self):
        """Verify our hash matches the dwk_blocklists approach:
        SHA256 of X-coordinate bytes with no leading zeros."""
        import hashlib

        der, key = _make_cert_der("ec")
        cert = parse_certificate(der)
        _, key_hash, _, _ = extract_cert_key_info(cert)

        pub = cert.public_key()
        x_coord = pub.public_numbers().x
        x_bytes = _int_to_bytes_unsigned(x_coord)
        expected = hashlib.sha256(x_bytes).hexdigest()
        assert key_hash == expected


async def test_supplementer_returns_provider_update_stats():
    class FakeProvider:
        source = "crtsh_postgres"

        async def supplement_records(self, records, data_manager):
            assert len(records) == 2
            return LookupProviderResult(
                records=[
                    LookupRecordResult(
                        records[0],
                        LookupOutcome.FOUND,
                        info={"publickey": "aa", "key_hash": "hash"},
                    ),
                    LookupRecordResult(records[1], LookupOutcome.NOT_FOUND),
                ],
                requests_total=1,
            )

    class FakeDataManager:
        def record_lookup_results(self, source, records):
            assert source == "crtsh_postgres"
            return {"found": 1, "not_found": 1}

    supplementer = CrtShSupplementer.__new__(CrtShSupplementer)
    supplementer.mode = "postgres"
    supplementer.data_manager = FakeDataManager()
    supplementer.provider = FakeProvider()
    supplementer.get_pending_records = lambda limit: [
        {"serial_number": "01", "issuer": "CN=One"},
        {"serial_number": "02", "issuer": "CN=Two"},
    ]

    result = await supplementer.run(limit=2, export_results=False)

    assert result["status"] == "ok"
    assert result["submitted"] == 2
    assert result["updated"] == 1
    assert result["outcomes"] == {"found": 1, "not_found": 1}


async def test_postgres_provider_classifies_connection_failure(monkeypatch):
    provider = CrtShPostgresProvider()

    def fail_connect():
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(provider, "_connect", fail_connect)

    result = await provider.supplement_records(
        [{"serial_number": "01", "issuer": "CN=One"}], object()
    )

    assert result.records[0].outcome == LookupOutcome.PROVIDER_UNAVAILABLE
    assert result.records[0].outcome != LookupOutcome.NOT_FOUND


async def test_postgres_commits_each_batch_before_next_query(monkeypatch, data_manager):
    from types import SimpleNamespace

    records = [
        {"serial_number": "01", "issuer": "CN=One", "revocation_date": "2026-09-01"},
        {"serial_number": "02", "issuer": "CN=Two", "revocation_date": "2026-09-01"},
    ]
    data_manager.save_revoked_certs(records)
    provider = CrtShPostgresProvider()
    provider.pg_batch_size = 1
    monkeypatch.setattr(
        provider, "_connect", lambda: SimpleNamespace(cursor=lambda: None, close=lambda: None)
    )

    def query(_cursor, serials):
        if serials == ["02"]:
            state = data_manager.get_lookup_state("01", "CN=One", provider.source)
            assert state["consecutive_misses"] == 1
        return []

    monkeypatch.setattr(provider, "_batch_query_serials", query)
    monkeypatch.setattr(
        provider,
        "_match_records",
        lambda batch, _results: [
            LookupRecordResult(record, LookupOutcome.NOT_FOUND) for record in batch
        ],
    )
    result = await provider.supplement_records(records, data_manager)
    assert result.persisted_counts == {"not_found": 2}
    assert data_manager.get_lookup_state("01", "CN=One", provider.source)["consecutive_misses"] == 1


@pytest.mark.parametrize("body", [[{}], [None], [{"id": "invalid", "issuer_name": "CN=One"}]])
async def test_http_malformed_candidates_are_not_misses(monkeypatch, body):
    import asyncio

    from compromised_keys.lookup import SourceCircuitBreaker

    provider = CrtShHttpProvider()

    async def get(*_args, **_kwargs):
        return body, None, 200, 1, 0, ""

    monkeypatch.setattr(provider, "_get", get)
    result, _total, failed = await provider._process_one(
        None,
        {"serial_number": "01", "issuer": "CN=One"},
        asyncio.Semaphore(1),
        SourceCircuitBreaker(),
    )
    assert result.outcome == LookupOutcome.MALFORMED_RESPONSE
    assert failed == 1


async def test_postgres_budget_preserves_completed_batches(monkeypatch, data_manager):
    from types import SimpleNamespace

    from psycopg2 import extensions

    import compromised_keys.crt_sh_crawler as crawler

    records = [
        {"serial_number": sn, "issuer": "CN=CA", "revocation_date": None}
        for sn in ("01", "02", "03")
    ]
    data_manager.save_revoked_certs(records)
    clock = [0.0]
    monkeypatch.setattr(crawler.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(crawler, "_query_budget", lambda: 10)
    closed = []
    connection = SimpleNamespace(
        cursor=lambda: None, close=lambda: closed.append(True), poll=lambda: extensions.POLL_READ
    )
    provider = CrtShPostgresProvider(pg_batch_size=1)
    monkeypatch.setattr(provider, "_connect", lambda: connection)

    def wait_for_socket(_read, _write, _errors, timeout):
        clock[0] += timeout
        return [], [], []

    monkeypatch.setattr(crawler.select, "select", wait_for_socket)

    def query(_cursor, serials):
        if serials == ["01"]:
            clock[0] = 7
            return {}
        assert serials == ["02"]
        provider._wait(connection)
        pytest.fail("Budget expiry must interrupt the pending query")

    monkeypatch.setattr(provider, "_batch_query_serials", query)
    result = await provider.supplement_records(records, data_manager)
    assert result.budget_exhausted
    assert result.persisted_counts == {"not_found": 1}
    assert clock[0] == 10
    assert closed
    assert data_manager.get_lookup_state("02", "CN=CA", provider.source) is None
    assert data_manager.get_lookup_state("03", "CN=CA", provider.source) is None


async def test_http_budget_keeps_completed_results(monkeypatch, data_manager):
    import asyncio

    import compromised_keys.crt_sh_crawler as crawler

    records = [
        {"serial_number": sn, "issuer": "CN=CA", "revocation_date": None} for sn in ("01", "02")
    ]
    data_manager.save_revoked_certs(records)
    provider = CrtShHttpProvider(concurrency=1)
    monkeypatch.setattr(crawler, "_query_budget", lambda: 0.05)
    cancelled = []

    async def process(_session, record, _semaphore, _circuit):
        if record["serial_number"] == "02":
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.append(True)
        return LookupRecordResult(record, LookupOutcome.NOT_FOUND), 1, 0

    monkeypatch.setattr(provider, "_process_one", process)
    result = await provider.supplement_records(records, data_manager)
    assert result.budget_exhausted
    assert result.persisted_counts == {"not_found": 1}
    assert cancelled
    assert data_manager.get_lookup_state("02", "CN=CA", provider.source) is None


def test_crtsh_selects_newest_remaining_keys(data_manager):
    import sqlite3

    records = [
        {"serial_number": "01", "issuer": "CN=CA", "revocation_date": "2026-09-01"},
        {"serial_number": "02", "issuer": "CN=CA", "revocation_date": "2026-09-02"},
        {"serial_number": "03", "issuer": "CN=CA", "revocation_date": "2026-09-03"},
        {"serial_number": "04", "issuer": "CN=CA", "revocation_date": None},
    ]
    data_manager.save_revoked_certs(records)
    data_manager.record_lookup_results(
        "operator_ct",
        [
            LookupRecordResult(
                records[2], LookupOutcome.FOUND, info={"publickey": "aa", "key_hash": "key"}
            )
        ],
    )
    data_manager.record_lookup_results(
        "crtsh_postgres", [LookupRecordResult(records[1], LookupOutcome.NOT_FOUND)]
    )
    with sqlite3.connect(data_manager.db_path) as conn:
        conn.execute("UPDATE lookup_state SET next_retry_after=NULL WHERE source='crtsh_postgres'")
    supplementer = CrtShSupplementer(mode="postgres", db_path=data_manager.db_path)
    assert [r["serial_number"] for r in supplementer.get_pending_records(4)] == ["02", "01", "04"]


async def test_http_record_exception_preserves_progress(monkeypatch, data_manager):
    records = [
        {"serial_number": sn, "issuer": "CN=CA", "revocation_date": None}
        for sn in ("01", "02", "03")
    ]
    data_manager.save_revoked_certs(records)
    provider = CrtShHttpProvider(concurrency=1)

    async def process(_session, record, _semaphore, _circuit):
        if record["serial_number"] == "02":
            raise ValueError("Unparseable certificate extension")
        return LookupRecordResult(record, LookupOutcome.NOT_FOUND), 1, 0

    monkeypatch.setattr(provider, "_process_one", process)
    result = await provider.supplement_records(records, data_manager)
    assert result.persisted_counts == {"not_found": 2, "provider_unavailable": 1}
    assert result.requests_failed == 1
    state = data_manager.get_lookup_state("02", "CN=CA", provider.source)
    assert state["consecutive_misses"] == 0
    assert state["next_retry_after"] is None
