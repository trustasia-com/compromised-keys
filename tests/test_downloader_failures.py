"""Tests covering downloader's interaction with crl_status failure tracking."""

import asyncio
import csv
import os
from contextlib import asynccontextmanager

import pytest

from compromised_keys.downloader import Downloader


class _FakeCCADBResponse:
    def __init__(self, body):
        self._body = body

    def raise_for_status(self):
        return None

    def json(self):
        return self._body


class _FakeCCADBSession:
    def __init__(self, pages):
        self.pages = pages
        self.requests = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def post(self, url, json, timeout):
        self.requests.append((url, json, timeout))
        page = json["filters"]["PageNumber"]
        return _FakeCCADBResponse(self.pages[page])


class _FakeResponse:
    def __init__(self, status: int, body: bytes = b"", raises: Exception = None):
        self.status = status
        self._body = body
        self._raises = raises
        self.content = self

    async def iter_chunked(self, size):
        payload = await self.read()
        for offset in range(0, len(payload), size):
            yield payload[offset : offset + size]

    async def read(self):
        if self._raises is not None:
            raise self._raises
        return self._body


class _FakeSession:
    """Minimal async session whose `get(...)` returns a configured response."""

    def __init__(self, response):
        self._response = response

    def get(self, *_args, **_kwargs):
        response = self._response

        @asynccontextmanager
        async def cm():
            yield response

        return cm()


class _FakeRoutingSession:
    def __init__(self, responses):
        self.responses = responses
        self.requests = []

    def get(self, url, **_kwargs):
        self.requests.append(url)
        response = self.responses[url]

        @asynccontextmanager
        async def cm():
            yield response

        return cm()


def _semaphore() -> asyncio.Semaphore:
    return asyncio.Semaphore(1)


@pytest.mark.parametrize("value", [None, "", "   ", '""', "null", []])
def test_ccadb_empty_url_representations(value):
    assert Downloader._ccadb_json_array(value) == "[]"


@pytest.fixture
def downloader(tmp_path, data_manager):
    return Downloader(
        cache_dir=str(tmp_path / "cache"),
        max_retries=1,
        concurrency=1,
        data_manager=data_manager,
    )


def test_download_ccadb_records_paginates_and_normalizes(monkeypatch, downloader):
    def page(number, next_number, data):
        return {
            "Status": "Success",
            "Meta": {
                "Pagination": {
                    "TotalRecords": 2,
                    "CurrentPageNumber": number,
                    "NextPageNumber": next_number,
                }
            },
            "Data": data,
        }

    records = [
        {
            "CertificateInformation": {
                "CCADBUniqueID": "record-1",
                "CAOwner": "Acme",
                "CertificateName": "Acme TLS CA",
                "CertificateRecordType": "Intermediate Certificate",
            },
            "RootStoreStatus": {"ChromeStatus": "Trusted"},
            "CertificateData": {
                "SHA256Fingerprint": "AABB",
                "SubjectKeyIdentifier": "qrs=",
            },
            "PertainingToCertificatesIssued": {
                "JSONArrayOfAllFullCRLURLs": ["https://example.test/full.crl"],
                "JSONArrayOfPartitionedCRLs": [],
            },
            "Capabilities": {"TLSCapable": True},
        },
        {
            "CertificateInformation": {
                "CCADBUniqueID": "record-2",
                "CertificateRecordType": "Root Certificate",
            },
            "RootStoreStatus": {"ChromeStatus": "Not Trusted"},
            "CertificateData": {},
            "PertainingToCertificatesIssued": {},
            "Capabilities": {},
        },
    ]
    session = _FakeCCADBSession({1: page(1, 2, records[:1]), 2: page(2, 0, records[1:])})
    monkeypatch.setattr("compromised_keys.downloader.requests.Session", lambda: session)
    monkeypatch.setattr("compromised_keys.downloader.config.CCADB_API_START_DECADE", 2020)
    monkeypatch.setattr("compromised_keys.downloader.config.CCADB_API_END_DECADE", 2020)
    monkeypatch.setattr("compromised_keys.downloader.config.CCADB_CACHE_TTL_HOURS", 0)

    path = downloader.download_ccadb_records("https://ccadb.example.test/api")

    with open(path, newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 2
    assert rows[0]["Salesforce Record ID"] == "record-1"
    assert rows[0]["TLS Capable"] == "True"
    assert rows[0]["JSON Array of All Full CRL URLs"] == ('["https://example.test/full.crl"]')
    assert [request[1]["filters"]["PageNumber"] for request in session.requests] == [1, 2]
    assert session.requests[0][1]["fieldSets"] == [
        "PertainingToCertificatesIssued",
        "Capabilities",
    ]


def test_download_success_records_in_db(downloader, data_manager, crl_der):
    payload = crl_der
    session = _FakeSession(_FakeResponse(200, body=payload))

    async def go():
        return await downloader._download_crl_with_retry(
            session, "http://crl.example.com/a.crl", _semaphore()
        )

    result = asyncio.run(go())
    assert result is not None
    path, updated = result
    assert updated is True
    assert os.path.isfile(path)

    failures = data_manager.get_crl_failures()
    assert failures == []


def test_download_404_records_failure(downloader, data_manager):
    session = _FakeSession(_FakeResponse(404))

    async def go():
        return await downloader._download_crl_with_retry(
            session, "http://crl.example.com/missing.crl", _semaphore()
        )

    result = asyncio.run(go())
    assert result is None

    failures = data_manager.get_crl_failures()
    assert len(failures) == 1
    f = failures[0]
    assert f["consecutive_failures"] == 1
    assert f["download_status"] == 404
    assert f["last_error"] == "HTTP 404"
    assert f["first_failure_at"] is not None


def test_download_recovery_clears_failures(downloader, data_manager, crl_der):
    async def go():
        session_fail = _FakeSession(_FakeResponse(404))
        await downloader._download_crl_with_retry(
            session_fail, "http://crl.example.com/a.crl", _semaphore()
        )
        assert len(data_manager.get_crl_failures()) == 1

        session_ok = _FakeSession(_FakeResponse(200, body=crl_der))
        await downloader._download_crl_with_retry(
            session_ok, "http://crl.example.com/a.crl", _semaphore()
        )
        assert data_manager.get_crl_failures() == []

    asyncio.run(go())


def test_full_crl_group_stops_after_first_success(downloader, crl_der):
    session = _FakeRoutingSession(
        {
            "https://example.test/primary.crl": _FakeResponse(200, body=crl_der),
            "https://example.test/mirror.crl": _FakeResponse(200, body=crl_der),
        }
    )

    async def go():
        return await downloader._download_crl_group(
            session,
            [
                "https://example.test/primary.crl",
                "https://example.test/mirror.crl",
            ],
            _semaphore(),
        )

    result = asyncio.run(go())

    assert result is not None
    assert session.requests == ["https://example.test/primary.crl"]


def test_full_crl_group_falls_back_after_failure(downloader, crl_der):
    session = _FakeRoutingSession(
        {
            "https://example.test/unavailable.crl": _FakeResponse(404),
            "https://example.test/mirror.crl": _FakeResponse(200, body=crl_der),
        }
    )

    async def go():
        return await downloader._download_crl_group(
            session,
            [
                "https://example.test/unavailable.crl",
                "https://example.test/mirror.crl",
            ],
            _semaphore(),
        )

    result = asyncio.run(go())

    assert result is not None
    assert session.requests == [
        "https://example.test/unavailable.crl",
        "https://example.test/mirror.crl",
    ]


def test_register_crl_sources_attaches_ccadb_attribution(data_manager):
    data_manager.register_crl_sources(
        [
            {
                "url": "http://crl.example.com/a.crl",
                "ccadb_record_id": "rec-123",
                "ca_owner": "Acme",
                "certificate_name": "Acme Root",
                "sha256_fp": "DEADBEEF",
            }
        ]
    )
    data_manager.record_crl_failure("http://crl.example.com/a.crl", 404, "Not Found")
    failures = data_manager.get_crl_failures()
    assert len(failures) == 1
    assert failures[0]["ccadb_record_id"] == "rec-123"
    assert failures[0]["ca_owner"] == "Acme"
    assert failures[0]["sha256_fp"] == "DEADBEEF"


@pytest.mark.asyncio
async def test_invalid_200_falls_back_and_is_not_cached(downloader, data_manager, crl_der):
    session = _FakeRoutingSession(
        {
            "https://example.test/error": _FakeResponse(200, b"<html>Unavailable</html>"),
            "https://example.test/crl": _FakeResponse(200, crl_der),
        }
    )
    result = await downloader._download_crl_group(session, list(session.responses), _semaphore())
    assert result is not None
    assert len(session.requests) == 2
    assert len(data_manager.get_crl_failures()) == 1
    assert len(os.listdir(downloader.cache_dir)) == 1


@pytest.mark.asyncio
async def test_overlapping_groups_share_one_download(downloader, crl_der):
    session = _FakeRoutingSession({"https://example.test/crl": _FakeResponse(200, crl_der)})
    downloads = {}
    results = await asyncio.gather(
        *(
            downloader._download_crl_group(
                session, list(session.responses), _semaphore(), downloads
            )
            for _ in range(2)
        )
    )
    assert results[0] == results[1]
    assert len(session.requests) == 1


@pytest.mark.asyncio
async def test_oversized_crl_is_rejected(downloader, monkeypatch):
    monkeypatch.setattr("compromised_keys.config.CRL_MAX_BYTES", 2)
    result = await downloader._download_crl_with_retry(
        _FakeSession(_FakeResponse(200, b"123")), "https://example.test/crl", _semaphore()
    )
    assert result is None
    assert not os.listdir(downloader.cache_dir)


@pytest.mark.asyncio
async def test_unchanged_download_retries_until_database_checkpoint(
    downloader, data_manager, crl_der
):
    import hashlib

    url = "https://example.test/crl"
    session = _FakeSession(_FakeResponse(200, crl_der))
    first = await downloader._download_crl_with_retry(session, url, _semaphore())
    second = await downloader._download_crl_with_retry(session, url, _semaphore())
    assert first[1] is True
    assert second[1] is True
    data_manager.save_revoked_certs([], crl_hash=hashlib.sha256(crl_der).hexdigest())
    third = await downloader._download_crl_with_retry(session, url, _semaphore())
    assert third[1] is False
