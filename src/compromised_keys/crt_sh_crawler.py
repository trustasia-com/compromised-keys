import asyncio
import contextlib
import logging
import math
import select
import time
from typing import Dict, List, Optional, Tuple

import aiohttp
from cryptography.hazmat.primitives import hashes

from compromised_keys import config
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
from compromised_keys.exporter import Exporter
from compromised_keys.lookup import (
    LookupOutcome,
    LookupProviderResult,
    LookupRecordResult,
    SourceCircuitBreaker,
)

logger = logging.getLogger(__name__)


class QueryBudgetExceededError(TimeoutError):
    """The optional lookup stage must yield to export and publication."""


def _query_budget() -> int:
    if not 0 < config.CRTSH_MAX_SECONDS <= 3600:
        raise ValueError("CRTSH_MAX_SECONDS must be between 1 and 3600")
    return config.CRTSH_MAX_SECONDS


def _build_cert_info(cert_obj) -> Dict:
    spki_hex, key_hash, algorithm, key_size = extract_cert_key_info(cert_obj)
    not_before, not_after = get_cert_validity(cert_obj)
    return {
        "publickey": spki_hex,
        "key_hash": key_hash,
        "key_algorithm": algorithm,
        "key_size": key_size,
        "is_precert": is_precertificate(cert_obj),
        "validated_type": classify_validated_type(cert_obj),
        "notbefore": not_before,
        "notafter": not_after,
        "cert_sha256": cert_obj.fingerprint(hashes.SHA256()).hex(),
    }


def _error_results(
    records: List[Dict],
    outcome: LookupOutcome,
    *,
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


class CrtShPostgresProvider:
    """Direct read-only PostgreSQL lookup against crt.sh certwatch."""

    source = "crtsh_postgres"

    def __init__(self, dsn: str = "", pg_batch_size: int = 0):
        self.dsn = dsn or config.CRTSH_PG_DSN
        self.pg_batch_size = pg_batch_size or config.CRTSH_PG_BATCH_SIZE
        self._deadline = float("inf")

    def _remaining(self) -> float:
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise QueryBudgetExceededError()
        return remaining

    def _wait(self, connection, timeout: float = 60) -> None:
        from psycopg2 import OperationalError, extensions

        operation_deadline = time.monotonic() + timeout
        while True:
            remaining = min(self._remaining(), operation_deadline - time.monotonic())
            if remaining <= 0:
                raise OperationalError("crt.sh operation timed out")
            state = connection.poll()
            if state == extensions.POLL_OK:
                return
            if state not in (extensions.POLL_READ, extensions.POLL_WRITE):
                raise OperationalError("Unexpected PostgreSQL poll state")
            select.select(
                [connection] if state == extensions.POLL_READ else [],
                [connection] if state == extensions.POLL_WRITE else [],
                [],
                remaining,
            )

    def _connect(self):
        import psycopg2

        last_error = None
        for attempt in range(3):
            self._remaining()
            conn = None
            try:
                conn = psycopg2.connect(
                    self.dsn,
                    async_=True,
                    connect_timeout=30,
                    keepalives=1,
                    keepalives_idle=30,
                    keepalives_interval=5,
                    keepalives_count=3,
                )
                self._wait(conn, 30)
                with conn.cursor() as cursor:
                    cursor.execute("SET default_transaction_read_only = on")
                    self._wait(conn)
                    cursor.execute("SET statement_timeout = 60000")
                    self._wait(conn)
                return conn
            except QueryBudgetExceededError:
                if conn is not None:
                    conn.close()
                raise
            except psycopg2.Error as error:
                if conn is not None:
                    conn.close()
                last_error = error
                logger.warning("[PG] Connection attempt %d/3 failed: %s", attempt + 1, error)
                if attempt < 2:
                    time.sleep(min(10, self._remaining()))
        raise RuntimeError("Failed to connect to crt.sh PostgreSQL") from last_error

    def _batch_query_serials(self, cursor, serial_hex_list: List[str]) -> Dict:
        self._remaining()
        padded = []
        serial_map = {}
        for serial in serial_hex_list:
            normalized = serial.lower().lstrip("0") or "0"
            query_value = normalized if len(normalized) % 2 == 0 else "0" + normalized
            padded.append(query_value)
            serial_map[query_value.lower()] = normalized
        cursor.execute(
            """
            SELECT encode(x509_serialNumber(c.certificate), 'hex') AS sn_hex,
                   c.id, c.certificate
            FROM certificate c
            WHERE x509_serialNumber(c.certificate) = ANY(
                ARRAY(SELECT decode(unnest, 'hex') FROM unnest(%s::text[]))
            )
            """,
            (padded,),
        )
        self._wait(cursor.connection)
        results = {}
        for serial_hex, cert_id, cert_der in cursor:
            if serial_hex and cert_der:
                normalized = serial_map.get(
                    serial_hex.lower(), serial_hex.lower().lstrip("0") or "0"
                )
                results.setdefault(normalized, []).append((cert_id, bytes(cert_der)))
        return results

    @staticmethod
    def _match_records(records: List[Dict], pg_results: Dict) -> List[LookupRecordResult]:
        results = []
        for record in records:
            serial = record["serial_number"].lower().lstrip("0") or "0"
            target_issuer = normalize_issuer(record["issuer"])
            candidates = pg_results.get(serial, [])
            malformed_seen = False
            unsupported_seen = False
            identity_mismatch_seen = False
            found = None
            for cert_id, cert_der in candidates:
                cert = parse_certificate(cert_der)
                if cert is None:
                    malformed_seen = True
                    continue
                if normalize_issuer(cert.issuer.rfc4514_string()) != target_issuer:
                    continue
                if not certificate_matches_record(cert, record):
                    identity_mismatch_seen = True
                    continue
                info = _build_cert_info(cert)
                if not info["key_hash"]:
                    unsupported_seen = True
                    continue
                logger.info(
                    "[PG] Supplemented SN=%s from crt.sh (cert_id=%s)",
                    record["serial_number"],
                    cert_id,
                )
                found = LookupRecordResult(record, LookupOutcome.FOUND, info=info)
                break
            if found:
                results.append(found)
            elif unsupported_seen:
                results.append(LookupRecordResult(record, LookupOutcome.UNSUPPORTED_KEY))
            elif candidates and malformed_seen:
                results.append(LookupRecordResult(record, LookupOutcome.MALFORMED_RESPONSE))
            elif identity_mismatch_seen:
                results.append(LookupRecordResult(record, LookupOutcome.IDENTITY_MISMATCH))
            else:
                results.append(LookupRecordResult(record, LookupOutcome.NOT_FOUND))
        return results

    async def supplement_records(
        self,
        records: List[Dict],
        data_manager: Optional[DataManager] = None,
        batch_size: int = 50,
    ) -> LookupProviderResult:
        self._deadline = time.monotonic() + _query_budget()
        try:
            import psycopg2
        except ImportError as error:
            return LookupProviderResult(
                records=_error_results(
                    records, LookupOutcome.PROVIDER_UNAVAILABLE, error_class=type(error).__name__
                ),
                requests_failed=1,
            )

        try:
            connection = self._connect()
            cursor = connection.cursor()
        except QueryBudgetExceededError:
            return LookupProviderResult(budget_exhausted=True)
        except Exception as error:
            return LookupProviderResult(
                records=_error_results(
                    records, LookupOutcome.PROVIDER_UNAVAILABLE, error_class=type(error).__name__
                ),
                requests_failed=1,
            )

        results = []
        requests_total = 0
        requests_failed = 0
        budget_exhausted = False
        circuit = SourceCircuitBreaker()
        pg_batch_size = max(1, min(self.pg_batch_size, batch_size))
        persisted_counts = {} if data_manager is not None else None
        total_batches = math.ceil(len(records) / pg_batch_size)
        try:
            for batch_number, offset in enumerate(range(0, len(records), pg_batch_size), start=1):
                self._remaining()
                current = records[offset : offset + pg_batch_size]
                if batch_number == 1 or batch_number % 10 == 0:
                    logger.info(
                        "[PG] Processing batch %d/%d (%d records processed)",
                        batch_number,
                        total_batches,
                        offset,
                    )
                if not await circuit.allow_request():
                    break

                pg_results = None
                last_error = None
                for attempt in range(3):
                    self._remaining()
                    requests_total += 1
                    try:
                        pg_results = self._batch_query_serials(
                            cursor, [record["serial_number"] for record in current]
                        )
                        await circuit.record_success()
                        break
                    except psycopg2.Error as error:
                        last_error = error
                        requests_failed += 1
                        await circuit.record_failure(LookupOutcome.NETWORK_ERROR)
                        if circuit.is_open or attempt == 2:
                            break
                        with contextlib.suppress(Exception):
                            connection.close()
                        try:
                            connection = self._connect()
                            cursor = connection.cursor()
                        except QueryBudgetExceededError:
                            raise
                        except Exception as connect_error:
                            last_error = connect_error
                            break

                if pg_results is None:
                    batch_results = _error_results(
                        current,
                        LookupOutcome.NETWORK_ERROR,
                        error_class=type(last_error).__name__ if last_error else "PostgresError",
                    )
                else:
                    batch_results = self._match_records(current, pg_results)
                if data_manager is not None:
                    counts = data_manager.record_lookup_results(self.source, batch_results)
                    for name, count in counts.items():
                        persisted_counts[name] = persisted_counts.get(name, 0) + count
                results.extend(batch_results)
        except QueryBudgetExceededError:
            budget_exhausted = True
            logger.info("[PG] Query time budget exhausted; completed %d records", len(results))
        finally:
            with contextlib.suppress(Exception):
                connection.close()

        return LookupProviderResult(
            records=results,
            requests_total=requests_total,
            requests_failed=requests_failed,
            circuit_open=circuit.is_open,
            circuit_reason=circuit.reason,
            persisted_counts=persisted_counts,
            budget_exhausted=budget_exhausted,
        )


class CrtShHttpProvider:
    """HTTP fallback for environments that cannot reach crt.sh PostgreSQL."""

    source = "crtsh_http"

    def __init__(self, concurrency: int = 0):
        self.concurrency = concurrency or config.CRTSH_HTTP_CONCURRENCY

    async def _get(
        self,
        session: aiohttp.ClientSession,
        url: str,
        circuit: SourceCircuitBreaker,
        *,
        json_response: bool,
    ) -> Tuple[object, Optional[LookupOutcome], Optional[int], int, int, str]:
        last_outcome = LookupOutcome.PROVIDER_UNAVAILABLE
        last_status = None
        last_error = ""
        total = 0
        failed = 0
        for attempt in range(3):
            if not await circuit.allow_request():
                return None, LookupOutcome.PROVIDER_UNAVAILABLE, None, total, failed, "CircuitOpen"
            total += 1
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                    last_status = response.status
                    if response.status == 200:
                        value = await response.json() if json_response else await response.read()
                        await circuit.record_success()
                        return value, None, response.status, total, failed, ""
                    if response.status == 429:
                        last_outcome = LookupOutcome.RATE_LIMITED
                    elif 400 <= response.status < 500:
                        last_outcome = LookupOutcome.HTTP_CLIENT_ERROR
                    else:
                        last_outcome = LookupOutcome.HTTP_SERVER_ERROR
                    last_error = "HTTPStatusError"
                    failed += 1
                    await circuit.record_failure(last_outcome, response.status)
                    if 400 <= response.status < 500 and response.status != 429:
                        break
            except asyncio.TimeoutError as error:
                last_outcome = LookupOutcome.TIMEOUT
                last_error = type(error).__name__
                failed += 1
                await circuit.record_failure(last_outcome)
            except (aiohttp.ClientError, ValueError, TypeError) as error:
                last_outcome = (
                    LookupOutcome.MALFORMED_RESPONSE
                    if isinstance(error, (ValueError, TypeError))
                    else LookupOutcome.NETWORK_ERROR
                )
                last_error = type(error).__name__
                failed += 1
                await circuit.record_failure(last_outcome)
            if attempt < 2 and not circuit.is_open:
                await asyncio.sleep(2**attempt)
        return None, last_outcome, last_status, total, failed, last_error

    async def _process_one(
        self,
        session: aiohttp.ClientSession,
        record: Dict,
        semaphore: asyncio.Semaphore,
        circuit: SourceCircuitBreaker,
    ) -> Tuple[LookupRecordResult, int, int]:
        async with semaphore:
            serial = record["serial_number"]
            query_serial = serial if len(serial) % 2 == 0 else "0" + serial
            data, error, status, total, failed, error_class = await self._get(
                session,
                f"https://crt.sh/?serial={query_serial}&output=json",
                circuit,
                json_response=True,
            )
            if error:
                return (
                    LookupRecordResult(record, error, status_code=status, error_class=error_class),
                    total,
                    failed,
                )
            if not isinstance(data, list):
                return (
                    LookupRecordResult(record, LookupOutcome.MALFORMED_RESPONSE),
                    total,
                    failed + 1,
                )

            if any(
                not isinstance(item, dict)
                or not isinstance(item.get("issuer_name"), str)
                or not item["issuer_name"].strip()
                or type(item.get("id")) is not int
                or item["id"] <= 0
                for item in data
            ):
                return (
                    LookupRecordResult(record, LookupOutcome.MALFORMED_RESPONSE),
                    total,
                    failed + 1,
                )

            target_issuer = normalize_issuer(record["issuer"])
            candidate_ids = [
                item.get("id")
                for item in data
                if isinstance(item, dict)
                and normalize_issuer(item.get("issuer_name", "")) == target_issuer
                and item.get("id") is not None
            ]
            if not candidate_ids:
                return LookupRecordResult(record, LookupOutcome.NOT_FOUND), total, failed

            last_error_result = None
            for cert_id in candidate_ids:
                (
                    der,
                    der_error,
                    der_status,
                    req_total,
                    req_failed,
                    der_error_class,
                ) = await self._get(
                    session,
                    f"https://crt.sh/?d={cert_id}",
                    circuit,
                    json_response=False,
                )
                total += req_total
                failed += req_failed
                if der_error:
                    last_error_result = LookupRecordResult(
                        record,
                        der_error,
                        status_code=der_status,
                        error_class=der_error_class,
                    )
                    continue
                cert = parse_certificate(der)
                if cert is None:
                    last_error_result = LookupRecordResult(record, LookupOutcome.MALFORMED_RESPONSE)
                    continue
                if not certificate_matches_record(cert, record):
                    last_error_result = LookupRecordResult(record, LookupOutcome.IDENTITY_MISMATCH)
                    continue
                info = _build_cert_info(cert)
                if not info["key_hash"]:
                    last_error_result = LookupRecordResult(record, LookupOutcome.UNSUPPORTED_KEY)
                    continue
                return LookupRecordResult(record, LookupOutcome.FOUND, info=info), total, failed
            return last_error_result, total, failed

    async def supplement_records(
        self, records: List[Dict], data_manager: Optional[DataManager] = None
    ) -> LookupProviderResult:
        if not records:
            return LookupProviderResult()
        semaphore = asyncio.Semaphore(self.concurrency)
        circuit = SourceCircuitBreaker()
        outcomes = []
        persisted_counts = {} if data_manager is not None else None
        pending = iter(records)
        budget_exhausted = False

        async def worker(session):
            for record in pending:
                if not await circuit.allow_request():
                    break
                outcome = await self._process_one(session, record, semaphore, circuit)
                if data_manager is not None:
                    counts = data_manager.record_lookup_results(self.source, [outcome[0]])
                    for name, count in counts.items():
                        persisted_counts[name] = persisted_counts.get(name, 0) + count
                outcomes.append(outcome)

        async with aiohttp.ClientSession() as session:
            workers = [asyncio.create_task(worker(session)) for _ in range(self.concurrency)]
            try:
                await asyncio.wait_for(asyncio.gather(*workers), timeout=_query_budget())
            except asyncio.TimeoutError:
                budget_exhausted = True
            finally:
                for task in workers:
                    task.cancel()
                await asyncio.gather(*workers, return_exceptions=True)
        return LookupProviderResult(
            records=[item[0] for item in outcomes],
            requests_total=sum(item[1] for item in outcomes),
            requests_failed=sum(item[2] for item in outcomes),
            circuit_open=circuit.is_open,
            circuit_reason=circuit.reason,
            persisted_counts=persisted_counts,
            budget_exhausted=budget_exhausted,
        )


class CrtShSupplementer:
    def __init__(self, mode: str = "", db_path: str = ""):
        self.mode = mode or config.CRTSH_MODE
        self.data_manager = DataManager(db_path=db_path)
        self.exporter = Exporter()
        self.provider = CrtShPostgresProvider() if self.mode == "postgres" else CrtShHttpProvider()

    @property
    def source(self) -> str:
        return self.provider.source

    def get_pending_records(self, limit: int = 500) -> List[Dict]:
        return self.data_manager.get_pending_lookup_records(
            self.source, limit=limit, newest_first=True
        )

    async def run(self, limit: int = 500, export_results: bool = True) -> Dict:
        records = self.get_pending_records(limit)
        if not records:
            return {"status": "ok", "mode": self.mode, "submitted": 0, "updated": 0}

        outcome = await self.provider.supplement_records(records, self.data_manager)
        counts = outcome.persisted_counts
        if counts is None:
            counts = self.data_manager.record_lookup_results(self.source, outcome.records)
        updated = counts.get(LookupOutcome.FOUND.value, 0)
        if updated and export_results:
            keys = self.data_manager.get_all_compromised_keys()
            self.exporter.export_all(keys)

        status = (
            "degraded"
            if (outcome.requests_failed or outcome.circuit_open or outcome.budget_exhausted)
            else "ok"
        )
        return {
            "status": status,
            "mode": self.mode,
            "source": self.source,
            "submitted": len(outcome.records),
            "selected": len(records),
            "deferred": len(records) - len(outcome.records),
            "budget_exhausted": outcome.budget_exhausted,
            "time_budget_seconds": _query_budget(),
            "updated": updated,
            "requests_total": outcome.requests_total,
            "requests_failed": outcome.requests_failed,
            "circuit_open": outcome.circuit_open,
            "circuit_reason": outcome.circuit_reason,
            "outcomes": counts,
        }
