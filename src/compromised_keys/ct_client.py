import asyncio
import base64
import binascii
import calendar
import logging
import re
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

import aiohttp
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from compromised_keys import config
from compromised_keys.crypto_utils import (
    classify_validated_type,
    extract_cert_key_info,
    get_cert_validity,
    is_precertificate,
    normalize_issuer,
)
from compromised_keys.lookup import (
    LookupOutcome,
    LookupProviderResult,
    LookupRecordResult,
    SourceCircuitBreaker,
)

logger = logging.getLogger(__name__)

MAX_SERIALS_PER_REQUEST = 1000

# TLS BR 6.3.2: (issuance period start, calendar months, days).
# The 60-month exception remained available through June 2016.
TLS_VALIDITY_PERIODS = (
    (date(2012, 7, 1), 60, 0),
    (date(2016, 7, 1), 39, 0),
    (date(2018, 3, 1), 0, 825),
    (date(2020, 9, 1), 0, 398),
    (date(2026, 3, 15), 0, 200),
    (date(2027, 3, 15), 0, 100),
    (date(2029, 3, 15), 0, 47),
)


def _shift_validity(value: date, months: int, days: int) -> date:
    year, month = divmod(value.year * 12 + value.month - 1 + months, 12)
    shifted = value.replace(
        year=year, month=month + 1, day=min(value.day, calendar.monthrange(year, month + 1)[1])
    )
    return shifted + timedelta(days=days)


def _revocation_date(record: Dict) -> Optional[date]:
    value = record.get("revocation_date")
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(timezone.utc)
        result = parsed.date()
    except (ValueError, OverflowError):
        return None
    return result if TLS_VALIDITY_PERIODS[0][0] <= result <= date.today() else None


def _validity_window(records: List[Dict]) -> Dict[str, str]:
    """Bound TLS certificates presumed valid when revoked; historical runs retry misses widely."""
    dates = [_revocation_date(record) for record in records]
    if not dates or any(value is None for value in dates):
        return {}
    earliest = min(dates) - timedelta(days=1)
    latest = max(dates) + timedelta(days=1)
    starts, ends = [], []
    for index, (start, months, days) in enumerate(TLS_VALIDITY_PERIODS):
        end = (
            TLS_VALIDITY_PERIODS[index + 1][0] - timedelta(days=1)
            if index + 1 < len(TLS_VALIDITY_PERIODS)
            else date.max
        )
        first_issue = max(start, _shift_validity(earliest, -months, -days))
        last_issue = min(end, latest)
        # Older issuance rules remain relevant until their certificates expire.
        if first_issue <= last_issue:
            starts.append(first_issue)
            ends.append(_shift_validity(last_issue, months, days))
    return {
        "not_before_from": min(starts).isoformat(),
        "not_before_to": latest.isoformat(),
        "not_after_from": earliest.isoformat(),
        "not_after_to": max(ends).isoformat(),
    }


@dataclass
class CTQueryBatch:
    records: List[Dict]
    payload: Dict
    wide: bool = False


def normalize_serial_hex(value: str) -> str:
    normalized = value.strip().lower()
    if not re.fullmatch(r"[0-9a-f]+", normalized):
        raise ValueError("serial number must be hexadecimal")
    return normalized.lstrip("0") or "0"


def encode_hex_base64(value: str) -> str:
    normalized = value.strip()
    if not re.fullmatch(r"[0-9a-fA-F]+", normalized):
        raise ValueError("value must be hexadecimal")
    if len(normalized) % 2:
        normalized = "0" + normalized
    return base64.b64encode(bytes.fromhex(normalized)).decode("ascii")


class BaseCTProvider(ABC):
    @abstractmethod
    async def query_records(
        self, records: List[Dict], concurrency: int = 5
    ) -> LookupProviderResult:
        raise NotImplementedError


class SearchAPICTProvider(BaseCTProvider):
    """Query an operator-configured AKI and serial-number CT search API."""

    def __init__(
        self,
        server_host: str = "",
        batch_size: int = 0,
        max_retries: int = 0,
        timeout_seconds: int = 0,
        full_history: bool = False,
    ):
        self.server_host = server_host or config.CT_SERVER_HOST
        if not self.server_host:
            raise ValueError("CT_SERVER_HOST must be set to use SearchAPICTProvider")
        host = self.server_host.rstrip("/")
        self.search_url = host if host.endswith("/search") else f"{host}/search"
        self.batch_size = min(batch_size or config.CT_BATCH_SIZE, MAX_SERIALS_PER_REQUEST)
        self.max_retries = max_retries or config.CT_MAX_RETRIES
        self.timeout_seconds = timeout_seconds or config.CT_TIMEOUT_SECONDS
        if min(self.batch_size, self.max_retries, self.timeout_seconds) < 1:
            raise ValueError("CT batch size, retries, and timeout must be positive")
        self.full_history = full_history

    def _payload(
        self, aki_hex: str, records: List[Tuple[Dict, str]], *, wide: bool = False
    ) -> Dict:
        payload = {
            "aki": encode_hex_base64(aki_hex),
            "serial_number": [encode_hex_base64(serial) for _record, serial in records],
            "include_der": True,
        }
        window = {} if wide else _validity_window([record for record, _serial in records])
        if window:
            payload.update(window)
        elif self.full_history:
            today = date.today()
            payload.update(
                {
                    "not_before_from": "2010-01-01",
                    "not_before_to": today.isoformat(),
                    "not_after_from": "2010-01-01",
                    "not_after_to": _shift_validity(today, 12, 0).isoformat(),
                }
            )
        return payload

    def _prepare_batches(
        self, records: List[Dict]
    ) -> Tuple[List[CTQueryBatch], List[LookupRecordResult]]:
        groups = defaultdict(list)
        invalid = []
        for record in records:
            aki_hex = str(record.get("authority_key_identifier") or "").strip().lower()
            try:
                if len(aki_hex) % 2:
                    raise ValueError("AKI must contain complete bytes")
                encode_hex_base64(aki_hex)
                serial_hex = normalize_serial_hex(str(record.get("serial_number") or ""))
                encode_hex_base64(serial_hex)
            except ValueError as error:
                invalid.append(
                    LookupRecordResult(
                        record,
                        LookupOutcome.INVALID_LOCAL_IDENTITY,
                        error_class=type(error).__name__,
                    )
                )
                continue
            revoked = _revocation_date(record)
            groups[(aki_hex, revoked is not None)].append((record, serial_hex))

        batches = []
        for (aki_hex, _dated), group in groups.items():
            group.sort(key=lambda item: _revocation_date(item[0]) or date.min, reverse=True)
            for offset in range(0, len(group), self.batch_size):
                chunk = group[offset : offset + self.batch_size]
                batches.append(
                    CTQueryBatch(
                        records=[record for record, _serial in chunk],
                        payload=self._payload(aki_hex, chunk),
                    )
                )
        return batches, invalid

    @staticmethod
    def _expected(batch: CTQueryBatch) -> Dict[Tuple[str, str], Dict]:
        return {
            (
                str(record["authority_key_identifier"]).strip().lower(),
                normalize_serial_hex(str(record["serial_number"])),
            ): record
            for record in batch.records
        }

    def _parse_item(
        self, item: Dict, expected: Dict[Tuple[str, str], Dict]
    ) -> Tuple[Optional[Tuple[str, str]], LookupOutcome, Optional[Dict]]:
        try:
            aki_hex = base64.b64decode(item["aki"], validate=True).hex()
            serial_hex = normalize_serial_hex(
                base64.b64decode(item["serial_number"], validate=True).hex()
            )
        except (KeyError, TypeError, ValueError, binascii.Error):
            return None, LookupOutcome.MALFORMED_RESPONSE, None

        identity = (aki_hex, serial_hex)
        if identity not in expected:
            return identity, LookupOutcome.IDENTITY_MISMATCH, None
        if not item.get("der"):
            return identity, LookupOutcome.MISSING_DER, None

        try:
            der = base64.b64decode(item["der"], validate=True)
            cert = x509.load_der_x509_certificate(der)
        except (TypeError, ValueError, binascii.Error):
            return identity, LookupOutcome.MALFORMED_RESPONSE, None

        if normalize_serial_hex(format(cert.serial_number, "x")) != serial_hex:
            return identity, LookupOutcome.IDENTITY_MISMATCH, None
        try:
            cert_aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
            if cert_aki.key_identifier is None or cert_aki.key_identifier.hex() != aki_hex:
                return identity, LookupOutcome.IDENTITY_MISMATCH, None
        except x509.ExtensionNotFound:
            return identity, LookupOutcome.IDENTITY_MISMATCH, None

        spki_hex, key_hash, algorithm, key_size = extract_cert_key_info(cert)
        if not key_hash:
            return identity, LookupOutcome.UNSUPPORTED_KEY, None
        not_before, not_after = get_cert_validity(cert)
        return (
            identity,
            LookupOutcome.FOUND,
            {
                "authority_key_identifier": aki_hex,
                "serialnumber": serial_hex,
                "issuername": cert.issuer.rfc4514_string(),
                "publickey": spki_hex,
                "key_hash": key_hash,
                "key_algorithm": algorithm,
                "key_size": key_size,
                "notbefore": not_before,
                "notafter": not_after,
                "cert_sha256": cert.fingerprint(hashes.SHA256()).hex(),
                "is_precert": is_precertificate(cert),
                "validated_type": classify_validated_type(cert),
            },
        )

    @staticmethod
    def _request_error(
        records: List[Dict],
        outcome: LookupOutcome,
        status_code: Optional[int] = None,
        error_class: str = "",
    ) -> List[LookupRecordResult]:
        return [
            LookupRecordResult(
                record,
                outcome,
                status_code=status_code,
                error_class=error_class,
            )
            for record in records
        ]

    async def _query_batch(
        self,
        session: aiohttp.ClientSession,
        batch: CTQueryBatch,
        semaphore: asyncio.Semaphore,
        circuit: SourceCircuitBreaker,
    ) -> LookupProviderResult:
        last_outcome = LookupOutcome.PROVIDER_UNAVAILABLE
        last_status = None
        last_error_class = ""
        requests_total = 0
        requests_failed = 0
        async with semaphore:
            # Check after entering the concurrency slot so queued work observes
            # failures from requests that ran before it.
            if not await circuit.allow_request():
                return LookupProviderResult(
                    records=self._request_error(
                        batch.records,
                        LookupOutcome.PROVIDER_UNAVAILABLE,
                        error_class="CircuitOpen",
                    ),
                    circuit_open=True,
                    circuit_reason=circuit.reason,
                )
            for attempt in range(self.max_retries):
                requests_total += 1
                try:
                    timeout = aiohttp.ClientTimeout(total=self.timeout_seconds)
                    async with session.post(
                        self.search_url,
                        json=batch.payload,
                        headers={"Content-Type": "application/json"},
                        timeout=timeout,
                    ) as response:
                        last_status = response.status
                        if response.status != 200:
                            if response.status == 429:
                                last_outcome = LookupOutcome.RATE_LIMITED
                            elif 400 <= response.status < 500:
                                last_outcome = LookupOutcome.HTTP_CLIENT_ERROR
                            else:
                                last_outcome = LookupOutcome.HTTP_SERVER_ERROR
                            last_error_class = "HTTPStatusError"
                            requests_failed += 1
                            await circuit.record_failure(last_outcome, response.status)
                            if 400 <= response.status < 500 and response.status != 429:
                                break
                            if attempt < self.max_retries - 1 and not circuit.is_open:
                                await asyncio.sleep(2**attempt)
                                continue
                            break

                        body = await response.json()
                        if not isinstance(body, dict) or "results" not in body:
                            raise ValueError("CT response must contain results")
                        if body["results"] is None:
                            items = []
                        else:
                            items = body.get("results") if isinstance(body, dict) else None
                        if not isinstance(items, list):
                            raise ValueError("CT response results must be a list or null")

                        expected = self._expected(batch)
                        parsed = [self._parse_item(item, expected) for item in items]
                        ambiguous = [
                            (identity, outcome)
                            for identity, outcome, _info in parsed
                            if identity is None
                            or (
                                outcome == LookupOutcome.IDENTITY_MISMATCH
                                and identity not in expected
                            )
                        ]
                        if ambiguous:
                            requests_failed += 1
                            await circuit.record_failure(LookupOutcome.MALFORMED_RESPONSE)
                            if len(batch.records) > 1 and not circuit.is_open:
                                midpoint = len(batch.records) // 2
                                children = []
                                for records in (
                                    batch.records[:midpoint],
                                    batch.records[midpoint:],
                                ):
                                    aki_hex = str(records[0]["authority_key_identifier"]).lower()
                                    serials = [
                                        (record, normalize_serial_hex(record["serial_number"]))
                                        for record in records
                                    ]
                                    children.append(
                                        CTQueryBatch(
                                            records,
                                            self._payload(aki_hex, serials, wide=batch.wide),
                                            wide=batch.wide,
                                        )
                                    )
                                split_semaphore = asyncio.Semaphore(1)
                                child_results = await asyncio.gather(
                                    *[
                                        self._query_batch(session, child, split_semaphore, circuit)
                                        for child in children
                                    ]
                                )
                                return LookupProviderResult(
                                    records=[
                                        item for child in child_results for item in child.records
                                    ],
                                    requests_total=requests_total
                                    + sum(child.requests_total for child in child_results),
                                    requests_failed=requests_failed
                                    + sum(child.requests_failed for child in child_results),
                                    circuit_open=circuit.is_open,
                                    circuit_reason=circuit.reason,
                                )
                            singleton_outcome = (
                                LookupOutcome.MALFORMED_RESPONSE
                                if any(identity is None for identity, _outcome in ambiguous)
                                else LookupOutcome.IDENTITY_MISMATCH
                            )
                            return LookupProviderResult(
                                records=self._request_error(
                                    batch.records,
                                    singleton_outcome,
                                    error_class="AmbiguousResponseItem",
                                ),
                                requests_total=requests_total,
                                requests_failed=requests_failed,
                                circuit_open=circuit.is_open,
                                circuit_reason=circuit.reason,
                            )

                        await circuit.record_success()
                        by_identity = {}
                        for identity, outcome, info in parsed:
                            if identity in expected and (
                                identity not in by_identity or outcome == LookupOutcome.FOUND
                            ):
                                by_identity[identity] = (outcome, info)
                        record_results = []
                        for record in batch.records:
                            identity = (
                                str(record["authority_key_identifier"]).strip().lower(),
                                normalize_serial_hex(str(record["serial_number"])),
                            )
                            outcome, info = by_identity.get(
                                identity, (LookupOutcome.NOT_FOUND, None)
                            )
                            if outcome == LookupOutcome.FOUND and normalize_issuer(
                                info["issuername"]
                            ) != normalize_issuer(record["issuer"]):
                                outcome, info = LookupOutcome.IDENTITY_MISMATCH, None
                            record_results.append(LookupRecordResult(record, outcome, info=info))
                        return LookupProviderResult(
                            records=record_results,
                            requests_total=requests_total,
                            requests_failed=requests_failed,
                        )
                except asyncio.TimeoutError as error:
                    last_outcome = LookupOutcome.TIMEOUT
                    last_error_class = type(error).__name__
                except aiohttp.ClientError as error:
                    last_outcome = LookupOutcome.NETWORK_ERROR
                    last_error_class = type(error).__name__
                except (ValueError, TypeError) as error:
                    last_outcome = LookupOutcome.MALFORMED_RESPONSE
                    last_error_class = type(error).__name__

                requests_failed += 1
                await circuit.record_failure(last_outcome, last_status)
                if circuit.is_open:
                    break
                if attempt < self.max_retries - 1 and not circuit.is_open:
                    await asyncio.sleep(2**attempt)

        return LookupProviderResult(
            records=self._request_error(
                batch.records,
                last_outcome,
                status_code=last_status,
                error_class=last_error_class,
            ),
            requests_total=requests_total,
            requests_failed=requests_failed,
            circuit_open=circuit.is_open,
            circuit_reason=circuit.reason,
        )

    async def _query_with_fallback(
        self,
        session: aiohttp.ClientSession,
        batch: CTQueryBatch,
        semaphore: asyncio.Semaphore,
        circuit: SourceCircuitBreaker,
    ) -> LookupProviderResult:
        logger.debug(
            "CT batch: %d records, validity bounds %s",
            len(batch.records),
            {key: value for key, value in batch.payload.items() if key.startswith("not_")},
        )
        result = await self._query_batch(session, batch, semaphore, circuit)
        if not self.full_history or not _validity_window(batch.records):
            return result
        missing = [
            item.record for item in result.records if item.outcome == LookupOutcome.NOT_FOUND
        ]
        if not missing:
            return result
        logger.info("CT historical fallback for %d unmatched records", len(missing))
        aki_hex = str(missing[0]["authority_key_identifier"]).strip().lower()
        serials = [(record, normalize_serial_hex(record["serial_number"])) for record in missing]
        fallback = await self._query_batch(
            session,
            CTQueryBatch(missing, self._payload(aki_hex, serials, wide=True), wide=True),
            semaphore,
            circuit,
        )
        replacements = {id(item.record): item for item in fallback.records}
        return LookupProviderResult(
            records=[replacements.get(id(item.record), item) for item in result.records],
            requests_total=result.requests_total + fallback.requests_total,
            requests_failed=result.requests_failed + fallback.requests_failed,
            circuit_open=circuit.is_open,
            circuit_reason=circuit.reason,
        )

    async def query_records(
        self, records: List[Dict], concurrency: int = 0
    ) -> LookupProviderResult:
        batches, invalid = self._prepare_batches(records)
        if not batches:
            return LookupProviderResult(records=invalid)
        concurrency = concurrency or config.CT_CONCURRENCY
        if concurrency < 1:
            raise ValueError("CT concurrency must be positive")
        semaphore = asyncio.Semaphore(concurrency)
        circuit = SourceCircuitBreaker()
        try:
            connector = aiohttp.TCPConnector(limit=concurrency, limit_per_host=concurrency)
            async with aiohttp.ClientSession(connector=connector) as session:
                outcomes = await asyncio.gather(
                    *[
                        self._query_with_fallback(session, batch, semaphore, circuit)
                        for batch in batches
                    ]
                )
        except Exception as error:
            logger.warning("Unable to initialize CT HTTP session: %s", error)
            return LookupProviderResult(
                records=invalid
                + self._request_error(
                    [record for batch in batches for record in batch.records],
                    LookupOutcome.PROVIDER_UNAVAILABLE,
                    error_class=type(error).__name__,
                ),
                requests_failed=1,
            )

        return LookupProviderResult(
            records=invalid + [item for outcome in outcomes for item in outcome.records],
            requests_total=sum(outcome.requests_total for outcome in outcomes),
            requests_failed=sum(outcome.requests_failed for outcome in outcomes),
            circuit_open=circuit.is_open,
            circuit_reason=circuit.reason,
        )


class DisabledCTProvider(BaseCTProvider):
    """Return a retryable outcome when no operator CT provider is configured."""

    async def query_records(
        self, records: List[Dict], concurrency: int = 5
    ) -> LookupProviderResult:
        return LookupProviderResult(
            records=[
                LookupRecordResult(record, LookupOutcome.PROVIDER_UNAVAILABLE) for record in records
            ]
        )


class CTClient:
    def __init__(self, provider: BaseCTProvider = None, full_history: bool = False):
        if provider:
            self.provider = provider
        elif config.CT_SERVER_HOST:
            self.provider = SearchAPICTProvider(full_history=full_history)
        else:
            self.provider = DisabledCTProvider()

    async def query_records_async(
        self, records: List[Dict], concurrency: int = 5
    ) -> LookupProviderResult:
        return await self.provider.query_records(records, concurrency)
