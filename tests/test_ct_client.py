import base64
from datetime import date, datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ObjectIdentifier

from compromised_keys import config, ct_client
from compromised_keys.lookup import LookupOutcome

TEST_AKI = "6175054e1af50fc1602020c228d98bb3e2c17db4"
TEST_SERIAL = "33b27161f0b25ca77720fbd03d583e24ab0694bd"


def _record(serial=TEST_SERIAL, aki=TEST_AKI, issuer="CN=Test CA", revoked=None):
    return {
        "serial_number": serial,
        "issuer": issuer,
        "authority_key_identifier": aki,
        "revocation_date": revoked,
    }


@pytest.fixture(scope="module")
def certificate_der():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Leaf")]))
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(int(TEST_SERIAL, 16))
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.AuthorityKeyIdentifier(bytes.fromhex(TEST_AKI), None, None), critical=False
        )
        .add_extension(
            x509.CertificatePolicies(
                [x509.PolicyInformation(ObjectIdentifier("2.23.140.1.2.1"), None)]
            ),
            critical=False,
        )
        .add_extension(x509.PrecertPoison(), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert, cert.public_bytes(serialization.Encoding.DER)


def _item(der, *, serial=TEST_SERIAL, aki=TEST_AKI, include_der=True):
    item = {
        "aki": ct_client.encode_hex_base64(aki),
        "serial_number": ct_client.encode_hex_base64(serial),
    }
    if include_der:
        item["der"] = base64.b64encode(der).decode("ascii")
    return item


class Response:
    request_info = None
    history = ()

    def __init__(self, status=200, body=None):
        self.status = status
        self.body = body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    async def json(self):
        return self.body


class Session:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class SessionContext(Session):
    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False


def test_hex_to_binary_base64_and_validation():
    assert ct_client.encode_hex_base64("abc") == base64.b64encode(bytes.fromhex("0abc")).decode()
    assert ct_client.normalize_serial_hex("000A") == "a"
    with pytest.raises(ValueError):
        ct_client.encode_hex_base64("not-hex")


def test_prepare_batches_groups_caps_and_marks_invalid():
    provider = ct_client.SearchAPICTProvider("https://ct.example", batch_size=2000)
    records = [_record(format(index + 1, "x"), "aabb") for index in range(1001)]
    records.append(_record("zz", "aabb"))

    batches, invalid = provider._prepare_batches(records)

    assert [len(batch.records) for batch in batches] == [1000, 1]
    assert len(invalid) == 1
    assert invalid[0].outcome == LookupOutcome.INVALID_LOCAL_IDENTITY
    assert config.CT_CONCURRENCY == 5


def test_full_history_date_range(monkeypatch):
    class FixedDate(date):
        @classmethod
        def today(cls):
            return cls(2028, 2, 29)

    monkeypatch.setattr(ct_client, "date", FixedDate)
    provider = ct_client.SearchAPICTProvider("https://ct.example", full_history=True)
    payload = provider._prepare_batches([_record("01", "aabb")])[0][0].payload

    assert payload["not_before_from"] == "2010-01-01"
    assert payload["not_after_from"] == "2010-01-01"
    assert payload["not_before_to"] == "2028-02-29"
    assert payload["not_after_to"] == "2029-02-28"


@pytest.fixture
def future_today(monkeypatch):
    class FixedDate(date):
        @classmethod
        def today(cls):
            return cls(2035, 1, 1)

    monkeypatch.setattr(ct_client, "date", FixedDate)


def test_batches_sort_dates_and_separate_aki_and_unknown_dates(future_today):
    records = [
        _record("01", revoked="2026-01-31T23:30:00-02:00"),
        _record("02", revoked="2026-01-15"),
        _record("03", revoked="2026-02-20"),
        _record("04", aki="aabb", revoked="2026-02-20"),
        _record("05", revoked="invalid"),
    ]
    batches, invalid = ct_client.SearchAPICTProvider(
        "https://ct.example", batch_size=2
    )._prepare_batches(records)
    assert not invalid
    assert [[record["serial_number"] for record in batch.records] for batch in batches] == [
        ["03", "01"],
        ["02"],
        ["04"],
        ["05"],
    ]
    assert batches[0].payload["not_before_to"] == "2026-02-21"
    assert batches[0].payload["not_after_from"] == "2026-01-31"
    assert "not_before_from" not in batches[-1].payload


@pytest.mark.parametrize("full_history", [False, True])
def test_window_uses_both_batch_extremes_and_398_days(future_today, full_history):
    records = [_record("01", revoked="2025-06-01"), _record("02", revoked="2025-06-20")]
    provider = ct_client.SearchAPICTProvider("https://ct.example", full_history=full_history)
    payload = provider._prepare_batches(records)[0][0].payload
    assert payload["not_before_from"] == (date(2025, 5, 31) - timedelta(days=398)).isoformat()
    assert payload["not_before_to"] == "2025-06-21"
    assert payload["not_after_from"] == "2025-05-31"
    assert payload["not_after_to"] == (date(2025, 6, 21) + timedelta(days=398)).isoformat()


@pytest.mark.parametrize(
    ("issued", "expires", "revoked"),
    [
        ("2016-06-30", "2021-06-30", "2021-06-01"),
        ("2018-02-28", "2021-05-28", "2021-05-01"),
        ("2020-08-31", "2022-12-04", "2022-11-20"),
        ("2026-03-14", "2027-04-16", "2026-09-09"),
        ("2027-03-14", "2027-09-30", "2027-09-01"),
        ("2029-03-14", "2029-06-22", "2029-06-01"),
    ],
)
def test_transition_preserves_still_valid_older_certificates(
    future_today, issued, expires, revoked
):
    window = ct_client._validity_window([_record(revoked=revoked)])
    assert window["not_before_from"] <= issued <= window["not_before_to"]
    assert window["not_after_from"] <= expires <= window["not_after_to"]


@pytest.mark.parametrize(
    ("revoked", "days"),
    [("2025-01-01", 398), ("2028-01-01", 100), ("2030-01-01", 47)],
)
def test_settled_validity_periods(future_today, revoked, days):
    window = ct_client._validity_window([_record(revoked=revoked)])
    day = date.fromisoformat(revoked)
    assert window["not_before_from"] == (day - timedelta(days=days + 1)).isoformat()
    assert window["not_after_to"] == (day + timedelta(days=days + 1)).isoformat()


@pytest.mark.parametrize("revoked", [None, "", "invalid", "2025-02-30", "2011-01-18", "9999-12-31"])
def test_unusable_dates_keep_existing_scope(future_today, revoked):
    record = _record(revoked=revoked)
    regular = ct_client.SearchAPICTProvider("https://ct.example")._prepare_batches([record])[0][0]
    historical = ct_client.SearchAPICTProvider(
        "https://ct.example", full_history=True
    )._prepare_batches([record])[0][0]
    assert "not_before_from" not in regular.payload
    assert historical.payload["not_before_from"] == "2010-01-01"


def test_calendar_validity_handles_leap_days():
    assert ct_client._shift_validity(date(2020, 2, 29), -60, 0) == date(2015, 2, 28)
    assert ct_client._shift_validity(date(2016, 1, 31), 39, 0) == date(2019, 4, 30)


@pytest.mark.asyncio
async def test_full_history_falls_back_only_for_valid_misses(future_today, certificate_der):
    _cert, der = certificate_der
    records = [_record(revoked="2025-01-01"), _record("02", revoked="2025-01-01")]
    provider = ct_client.SearchAPICTProvider("https://ct.example", full_history=True, max_retries=1)
    batch = provider._prepare_batches(records)[0][0]
    session = Session(
        [
            Response(body={"results": [_item(der, serial="02", include_der=False)]}),
            Response(body={"results": [_item(der)]}),
        ]
    )
    result = await provider._query_with_fallback(
        session, batch, ct_client.asyncio.Semaphore(1), ct_client.SourceCircuitBreaker()
    )
    assert [item.outcome for item in result.records] == [
        LookupOutcome.FOUND,
        LookupOutcome.MISSING_DER,
    ]
    assert result.requests_total == 2
    assert len(session.calls[1][1]["json"]["serial_number"]) == 1
    assert session.calls[1][1]["json"]["not_before_from"] == "2010-01-01"


@pytest.mark.asyncio
async def test_wide_fallback_errors_replace_narrow_misses(future_today):
    provider = ct_client.SearchAPICTProvider("https://ct.example", full_history=True, max_retries=1)
    batch = provider._prepare_batches([_record(revoked="2025-01-01")])[0][0]
    session = Session([Response(body={"results": None}), Response(status=503)])
    result = await provider._query_with_fallback(
        session, batch, ct_client.asyncio.Semaphore(1), ct_client.SourceCircuitBreaker()
    )
    assert result.records[0].outcome == LookupOutcome.HTTP_SERVER_ERROR
    assert result.requests_failed == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("full_history", [False, True])
async def test_windowed_http_error_never_triggers_wide_query(future_today, full_history):
    provider = ct_client.SearchAPICTProvider(
        "https://ct.example", full_history=full_history, max_retries=1
    )
    batch = provider._prepare_batches([_record(revoked="2025-01-01")])[0][0]
    session = Session([Response(status=400)])
    result = await provider._query_with_fallback(
        session, batch, ct_client.asyncio.Semaphore(1), ct_client.SourceCircuitBreaker()
    )
    assert result.records[0].outcome == LookupOutcome.HTTP_CLIENT_ERROR
    assert len(session.calls) == 1


@pytest.mark.asyncio
async def test_regular_window_miss_does_not_repeat_wide_query(future_today):
    provider = ct_client.SearchAPICTProvider("https://ct.example", max_retries=1)
    batch = provider._prepare_batches([_record(revoked="2025-01-01")])[0][0]
    session = Session([Response(body={"results": None})])
    result = await provider._query_with_fallback(
        session, batch, ct_client.asyncio.Semaphore(1), ct_client.SourceCircuitBreaker()
    )
    assert result.records[0].outcome == LookupOutcome.NOT_FOUND
    assert len(session.calls) == 1


@pytest.mark.asyncio
async def test_ambiguous_wide_fallback_keeps_wide_scope_when_split(future_today):
    provider = ct_client.SearchAPICTProvider("https://ct.example", full_history=True, max_retries=1)
    records = [_record("01", revoked="2025-01-01"), _record("02", revoked="2025-01-01")]
    batch = provider._prepare_batches(records)[0][0]
    session = Session(
        [
            Response(body={"results": None}),
            Response(body={"results": [{}]}),
            Response(body={"results": None}),
            Response(body={"results": None}),
        ]
    )
    result = await provider._query_with_fallback(
        session, batch, ct_client.asyncio.Semaphore(1), ct_client.SourceCircuitBreaker()
    )
    assert len(result.records) == 2
    assert all(item.outcome == LookupOutcome.NOT_FOUND for item in result.records)
    assert result.requests_total == 4
    assert all(call[1]["json"]["not_before_from"] == "2010-01-01" for call in session.calls[1:])


def test_parse_item_extracts_metadata(certificate_der):
    cert, der = certificate_der
    provider = ct_client.SearchAPICTProvider("https://ct.example")
    record = _record()
    batch = provider._prepare_batches([record])[0][0]

    identity, outcome, info = provider._parse_item(_item(der), provider._expected(batch))

    assert identity == (TEST_AKI, TEST_SERIAL)
    assert outcome == LookupOutcome.FOUND
    assert info["key_algorithm"] == "RSA"
    assert info["key_size"] == 2048
    assert info["is_precert"] is True
    assert info["validated_type"] == "DV"
    assert info["cert_sha256"] == cert.fingerprint(hashes.SHA256()).hex()


@pytest.mark.asyncio
async def test_valid_empty_response_is_not_found():
    provider = ct_client.SearchAPICTProvider("https://ct.example", max_retries=1)
    record = _record("01", "aabb")
    batch = provider._prepare_batches([record])[0][0]
    session = Session([Response(body={"results": None})])

    outcome = await provider._query_batch(
        session,
        batch,
        ct_client.asyncio.Semaphore(1),
        ct_client.SourceCircuitBreaker(),
    )

    assert outcome.records[0].outcome == LookupOutcome.NOT_FOUND
    assert outcome.requests_failed == 0


async def test_ct_checks_issuer_for_each_record_with_same_aki_and_serial(certificate_der):
    _, der = certificate_der
    provider = ct_client.SearchAPICTProvider("https://ct.example", max_retries=1)
    batch = provider._prepare_batches([_record(), _record(issuer="CN=Other CA")])[0][0]
    result = await provider._query_batch(
        Session([Response(body={"results": [_item(der)]})]),
        batch,
        ct_client.asyncio.Semaphore(1),
        ct_client.SourceCircuitBreaker(),
    )
    assert [item.outcome for item in result.records] == [
        LookupOutcome.FOUND,
        LookupOutcome.IDENTITY_MISMATCH,
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (400, LookupOutcome.HTTP_CLIENT_ERROR),
        (429, LookupOutcome.RATE_LIMITED),
        (503, LookupOutcome.HTTP_SERVER_ERROR),
    ],
)
async def test_http_errors_never_become_not_found(status, expected, monkeypatch):
    provider = ct_client.SearchAPICTProvider("https://ct.example", max_retries=1)
    batch = provider._prepare_batches([_record("01", "aabb")])[0][0]
    monkeypatch.setattr(ct_client.asyncio, "sleep", lambda *_args: None)

    outcome = await provider._query_batch(
        Session([Response(status=status)]),
        batch,
        ct_client.asyncio.Semaphore(1),
        ct_client.SourceCircuitBreaker(),
    )

    assert outcome.records[0].outcome == expected
    assert outcome.records[0].outcome != LookupOutcome.NOT_FOUND
    assert outcome.requests_failed == 1


@pytest.mark.asyncio
async def test_queued_batch_observes_circuit_opened_by_first_request():
    provider = ct_client.SearchAPICTProvider("https://ct.example", batch_size=1, max_retries=1)
    batches, _invalid = provider._prepare_batches([_record("01", "aabb"), _record("02", "aabb")])
    session = Session([Response(status=404)])
    semaphore = ct_client.asyncio.Semaphore(1)
    circuit = ct_client.SourceCircuitBreaker()

    first, second = await ct_client.asyncio.gather(
        provider._query_batch(session, batches[0], semaphore, circuit),
        provider._query_batch(session, batches[1], semaphore, circuit),
    )

    assert first.records[0].outcome == LookupOutcome.HTTP_CLIENT_ERROR
    assert second.records[0].outcome == LookupOutcome.PROVIDER_UNAVAILABLE
    assert second.circuit_open is True
    assert len(session.calls) == 1


@pytest.mark.asyncio
async def test_network_failure_never_becomes_not_found():
    provider = ct_client.SearchAPICTProvider("https://ct.example", max_retries=1)
    batch = provider._prepare_batches([_record("01", "aabb")])[0][0]
    outcome = await provider._query_batch(
        Session([ct_client.aiohttp.ClientConnectionError("down")]),
        batch,
        ct_client.asyncio.Semaphore(1),
        ct_client.SourceCircuitBreaker(),
    )
    assert outcome.records[0].outcome == LookupOutcome.NETWORK_ERROR


@pytest.mark.asyncio
async def test_missing_der_is_counted_separately(certificate_der):
    _cert, der = certificate_der
    provider = ct_client.SearchAPICTProvider("https://ct.example", max_retries=1)
    batch = provider._prepare_batches([_record()])[0][0]
    outcome = await provider._query_batch(
        Session([Response(body={"results": [_item(der, include_der=False)]})]),
        batch,
        ct_client.asyncio.Semaphore(1),
        ct_client.SourceCircuitBreaker(),
    )
    assert outcome.records[0].outcome == LookupOutcome.MISSING_DER


@pytest.mark.asyncio
async def test_out_of_batch_identity_is_not_treated_as_not_found(certificate_der):
    _cert, der = certificate_der
    provider = ct_client.SearchAPICTProvider("https://ct.example", max_retries=1)
    batch = provider._prepare_batches([_record()])[0][0]
    outcome = await provider._query_batch(
        Session([Response(body={"results": [_item(der, serial="01")]})]),
        batch,
        ct_client.asyncio.Semaphore(1),
        ct_client.SourceCircuitBreaker(),
    )
    assert outcome.records[0].outcome == LookupOutcome.IDENTITY_MISMATCH
    assert outcome.records[0].outcome != LookupOutcome.NOT_FOUND


@pytest.mark.asyncio
async def test_identityless_malformed_item_splits_batch():
    provider = ct_client.SearchAPICTProvider("https://ct.example", max_retries=1)
    records = [_record("01", "aabb"), _record("02", "aabb")]
    batch = provider._prepare_batches(records)[0][0]
    session = Session(
        [
            Response(body={"results": [{}]}),
            Response(body={"results": None}),
            Response(body={"results": None}),
        ]
    )

    outcome = await provider._query_batch(
        session,
        batch,
        ct_client.asyncio.Semaphore(1),
        ct_client.SourceCircuitBreaker(),
    )

    assert [result.outcome for result in outcome.records] == [
        LookupOutcome.NOT_FOUND,
        LookupOutcome.NOT_FOUND,
    ]
    assert outcome.requests_total == 3


@pytest.mark.asyncio
async def test_session_setup_failure_marks_provider_unavailable(monkeypatch):
    provider = ct_client.SearchAPICTProvider("https://ct.example")

    def fail(**_kwargs):
        raise RuntimeError("session unavailable")

    monkeypatch.setattr(ct_client.aiohttp, "ClientSession", fail)
    monkeypatch.setattr(ct_client.aiohttp, "TCPConnector", lambda **_kwargs: object())
    result = await provider.query_records([_record("01", "aabb")])
    assert result.records[0].outcome == LookupOutcome.PROVIDER_UNAVAILABLE


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [{}, {"error": "unavailable"}, {"results": "invalid"}])
async def test_invalid_envelope_never_counts_as_miss(body):
    provider = ct_client.SearchAPICTProvider("https://ct.example", max_retries=1)
    batch = provider._prepare_batches([_record()])[0][0]
    result = await provider._query_batch(
        Session([Response(body=body)]),
        batch,
        ct_client.asyncio.Semaphore(1),
        ct_client.SourceCircuitBreaker(),
    )
    assert result.records[0].outcome == LookupOutcome.MALFORMED_RESPONSE


def test_der_aki_must_match_request(certificate_der):
    _cert, der = certificate_der
    provider = ct_client.SearchAPICTProvider("https://ct.example")
    batch = provider._prepare_batches([_record(aki="aabb")])[0][0]
    _identity, outcome, _info = provider._parse_item(
        _item(der, aki="aabb"), provider._expected(batch)
    )
    assert outcome == LookupOutcome.IDENTITY_MISMATCH


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("issuer", "expected"),
    [("cn=test ca", LookupOutcome.FOUND), ("CN=Alias", LookupOutcome.IDENTITY_MISMATCH)],
)
async def test_duplicate_identities_and_missing_der_do_not_lose_hits(
    certificate_der, issuer, expected
):
    _cert, der = certificate_der
    provider = ct_client.SearchAPICTProvider("https://ct.example", max_retries=1)
    records = [_record(), _record(issuer=issuer)]
    batch = provider._prepare_batches(records)[0][0]
    result = await provider._query_batch(
        Session([Response(body={"results": [_item(der, include_der=False), _item(der)]})]),
        batch,
        ct_client.asyncio.Semaphore(1),
        ct_client.SourceCircuitBreaker(),
    )
    assert [item.record for item in result.records] == records
    assert [item.outcome for item in result.records] == [LookupOutcome.FOUND, expected]
