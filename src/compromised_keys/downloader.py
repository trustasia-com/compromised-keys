import asyncio
import csv
import hashlib
import json
import logging
import os
import time
from typing import Dict, List, Optional, Tuple

import aiohttp
import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from compromised_keys import config
from compromised_keys.atomic_io import atomic_write
from compromised_keys.public_http import PublicResolver, public_url_middleware, validate_public_url

logger = logging.getLogger(__name__)

CCADB_FIELD_SETS = ("PertainingToCertificatesIssued", "Capabilities")
CCADB_CACHE_FIELDS = (
    "Salesforce Record ID",
    "CA Owner",
    "Certificate Name",
    "SHA-256 Fingerprint",
    "TLS Capable",
    "Certificate Record Type",
    "JSON Array of All Full CRL URLs",
    "JSON Array of Partitioned CRLs",
)


class Downloader:
    def __init__(
        self,
        cache_dir: str = "",
        max_retries: int = 0,
        concurrency: int = 0,
        data_manager=None,
    ):
        self.cache_dir = cache_dir or config.CACHE_DIR
        self.max_retries = max_retries or config.CRL_MAX_RETRIES
        self.concurrency = concurrency or config.CRL_DOWNLOAD_CONCURRENCY
        self.data_manager = data_manager
        if (
            min(self.concurrency, self.max_retries, config.CRL_MAX_BYTES, config.CRL_PARSE_WORKERS)
            < 1
        ):
            raise ValueError(
                "CRL concurrency, retries, parser workers, and size limit must be positive"
            )
        os.makedirs(self.cache_dir, exist_ok=True)

    @staticmethod
    def _ccadb_section(record: Dict, name: str) -> Dict:
        section = record.get(name, {})
        return section if isinstance(section, dict) else {}

    @staticmethod
    def _ccadb_json_array(value) -> str:
        if value is None or value == "":
            return "[]"
        if isinstance(value, str):
            if not value.strip():
                return "[]"
            value = json.loads(value)
        if value is None or value == "":
            return "[]"
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            raise ValueError("CCADB CRL URLs must be an array of strings")
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))

    @classmethod
    def _flatten_ccadb_record(cls, record: Dict) -> Dict[str, str]:
        certificate = cls._ccadb_section(record, "CertificateInformation")
        data = cls._ccadb_section(record, "CertificateData")
        endpoints = cls._ccadb_section(record, "PertainingToCertificatesIssued")
        capabilities = cls._ccadb_section(record, "Capabilities")
        return {
            "Salesforce Record ID": certificate.get("CCADBUniqueID", ""),
            "CA Owner": certificate.get("CAOwner", ""),
            "Certificate Name": certificate.get("CertificateName", ""),
            "SHA-256 Fingerprint": data.get("SHA256Fingerprint", ""),
            "TLS Capable": capabilities.get("TLSCapable", ""),
            "Certificate Record Type": certificate.get("CertificateRecordType", ""),
            "JSON Array of All Full CRL URLs": cls._ccadb_json_array(
                endpoints.get("JSONArrayOfAllFullCRLURLs")
            ),
            "JSON Array of Partitioned CRLs": cls._ccadb_json_array(
                endpoints.get("JSONArrayOfPartitionedCRLs")
            ),
        }

    def _request_ccadb_page(
        self,
        session: requests.Session,
        url: str,
        decade: int,
        page_number: int,
    ) -> Dict:
        payload = {
            "filters": {
                "notBeforeDecade": decade,
                "PageNumber": page_number,
            },
            "fieldSets": list(CCADB_FIELD_SETS),
        }
        last_error = None
        for attempt in range(self.max_retries):
            try:
                response = session.post(url, json=payload, timeout=60)
                response.raise_for_status()
                body = response.json()
                if not isinstance(body, dict):
                    raise ValueError("response body is not a JSON object")
                if str(body.get("Status", "")).casefold() == "error":
                    raise ValueError(body.get("Message") or "CCADB API returned an error")
                if not isinstance(body.get("Data"), list):
                    raise ValueError("response Data is not a list")
                pagination = body.get("Meta", {}).get("Pagination")
                if not isinstance(pagination, dict):
                    raise ValueError("response is missing Meta.Pagination")
                return body
            except (requests.RequestException, TypeError, ValueError) as error:
                last_error = error
                logger.warning(
                    "CCADB API decade %d page %d attempt %d/%d failed: %s",
                    decade,
                    page_number,
                    attempt + 1,
                    self.max_retries,
                    error,
                )
                if attempt < self.max_retries - 1:
                    time.sleep(2**attempt)
        raise RuntimeError(f"CCADB API decade {decade} page {page_number} failed: {last_error}")

    def _download_ccadb_partition(
        self,
        session: requests.Session,
        url: str,
        decade: int,
    ) -> List[Dict]:
        records = []
        page_number = 1
        expected_total = None

        while page_number:
            body = self._request_ccadb_page(session, url, decade, page_number)
            pagination = body["Meta"]["Pagination"]
            current_page = int(pagination.get("CurrentPageNumber", 0))
            next_page = int(pagination.get("NextPageNumber", 0))
            total_records = int(pagination.get("TotalRecords", 0))

            if current_page != page_number:
                raise ValueError(f"CCADB API returned page {current_page}, expected {page_number}")
            if next_page and next_page <= page_number:
                raise ValueError(
                    f"CCADB API returned invalid next page {next_page} after {page_number}"
                )
            if expected_total is None:
                expected_total = total_records
            elif expected_total != total_records:
                raise ValueError(
                    f"CCADB API total changed from {expected_total} to {total_records}"
                )

            records.extend(body["Data"])
            page_number = next_page

        if len(records) != expected_total:
            raise ValueError(
                f"CCADB API decade {decade} returned {len(records)} of {expected_total} records"
            )
        return records

    def download_ccadb_records(self, url: str = "") -> Optional[str]:
        """Fetch the paginated CCADB API and return a normalized local snapshot."""
        url = url or config.CCADB_API_URL
        filename = "ccadb_api_all_certificate_records.csv"
        filepath = os.path.join(self.cache_dir, filename)
        cache_ttl = max(config.CCADB_CACHE_TTL_HOURS, 0) * 3600

        if (
            cache_ttl
            and os.path.isfile(filepath)
            and os.path.getsize(filepath) > 0
            and time.time() - os.path.getmtime(filepath) < cache_ttl
        ):
            logger.info("Using cached CCADB API snapshot at %s", filepath)
            return filepath

        start_decade = config.CCADB_API_START_DECADE
        end_decade = config.CCADB_API_END_DECADE
        if (
            start_decade < 1990
            or end_decade > 2100
            or start_decade % 10
            or end_decade % 10
            or start_decade > end_decade
        ):
            logger.error("Invalid CCADB API decade range: %d-%d", start_decade, end_decade)
            return None

        temp_path = f"{filepath}.tmp"
        try:
            all_records = []
            with requests.Session() as session:
                for decade in range(start_decade, end_decade + 1, 10):
                    partition = self._download_ccadb_partition(session, url, decade)
                    all_records.extend(partition)
                    logger.info("CCADB API decade %d: %d records", decade, len(partition))

            with open(temp_path, "w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=CCADB_CACHE_FIELDS)
                writer.writeheader()
                writer.writerows(self._flatten_ccadb_record(record) for record in all_records)
            os.replace(temp_path, filepath)
            logger.info("CCADB API snapshot saved to %s (%d records)", filepath, len(all_records))
            return filepath
        except Exception as error:
            logger.error("Failed to synchronize CCADB API: %s", error)
            if os.path.exists(temp_path):
                os.remove(temp_path)
            return None

    def _record_success(self, url: str, content: bytes):
        if not self.data_manager:
            return
        try:
            self.data_manager.record_crl_success(url, hashlib.sha256(content).hexdigest())
        except Exception as e:
            logger.debug(f"Failed to record CRL success for {url}: {e}")

    def _record_failure(self, url: str, status: int, error: str):
        if not self.data_manager:
            return
        try:
            self.data_manager.record_crl_failure(url, status, error)
        except Exception as e:
            logger.debug(f"Failed to record CRL failure for {url}: {e}")

    async def _download_crl_with_retry(
        self,
        session: aiohttp.ClientSession,
        url: str,
        semaphore: asyncio.Semaphore,
    ) -> Optional[Tuple[str, bool]]:
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        filepath = os.path.join(self.cache_dir, f"crl_{url_hash}.crl")

        last_status: int = -1
        last_error: str = ""

        async with semaphore:
            for attempt in range(self.max_retries):
                try:
                    validate_public_url(url)
                    timeout = aiohttp.ClientTimeout(total=30, connect=10)
                    async with session.get(url, timeout=timeout, allow_redirects=True) as response:
                        last_status = response.status
                        if response.status == 200:
                            chunks = bytearray()
                            async for chunk in response.content.iter_chunked(64 * 1024):
                                if len(chunks) + len(chunk) > config.CRL_MAX_BYTES:
                                    raise ValueError("CRL response exceeds CRL_MAX_BYTES")
                                chunks.extend(chunk)
                            content = bytes(chunks)
                            try:
                                crl = x509.load_der_x509_crl(content)
                            except ValueError:
                                crl = x509.load_pem_x509_crl(content)
                            # Normalize PEM mirrors and reject HTTP-200 error documents.
                            _ = crl.extensions
                            content = crl.public_bytes(serialization.Encoding.DER)

                            if os.path.exists(filepath):
                                with open(filepath, "rb") as f:
                                    if (
                                        hashlib.sha256(content).hexdigest()
                                        == hashlib.sha256(f.read()).hexdigest()
                                    ):
                                        self._record_success(url, content)
                                        needs_parsing = (
                                            self.data_manager is not None
                                            and self.data_manager.crl_needs_parsing(
                                                url, hashlib.sha256(content).hexdigest()
                                            )
                                        )
                                        return filepath, needs_parsing

                            with atomic_write(filepath, "wb") as f:
                                f.write(content)
                            self._record_success(url, content)
                            logger.debug(f"Downloaded updated CRL from {url}")
                            return filepath, True
                        elif response.status in (403, 404, 410):
                            logger.debug(f"CRL {url} returned {response.status}, skipping.")
                            self._record_failure(url, response.status, f"HTTP {response.status}")
                            return None
                        else:
                            last_error = f"HTTP {response.status}"
                            log = (
                                logger.warning if attempt == self.max_retries - 1 else logger.debug
                            )
                            log(f"CRL {url} returned {response.status} (attempt {attempt + 1})")
                except asyncio.TimeoutError:
                    last_status = -1
                    last_error = "timeout"
                    log = logger.warning if attempt == self.max_retries - 1 else logger.debug
                    log(f"CRL {url} timeout (attempt {attempt + 1})")
                except aiohttp.ClientError as e:
                    last_status = -1
                    last_error = f"client error: {e}"
                    log = logger.warning if attempt == self.max_retries - 1 else logger.debug
                    log(f"CRL {url} client error: {e} (attempt {attempt + 1})")
                except Exception as e:
                    last_status = -2
                    last_error = f"unexpected: {e}"
                    logger.error(f"CRL {url} unexpected error: {e}")
                    self._record_failure(url, last_status, last_error)
                    return None

                if attempt < self.max_retries - 1:
                    await asyncio.sleep(1 * (attempt + 1))

            self._record_failure(url, last_status, last_error or "unknown")
            return None

    async def _download_crl_group(
        self,
        session: aiohttp.ClientSession,
        urls: List[str],
        semaphore: asyncio.Semaphore,
        downloads: Optional[Dict] = None,
    ) -> Optional[Tuple[str, bool]]:
        """Try equivalent CRL URLs in order and stop after the first success."""
        for url in urls:
            if downloads is None:
                result = await self._download_crl_with_retry(session, url, semaphore)
            else:
                if url not in downloads:
                    downloads[url] = asyncio.create_task(
                        self._download_crl_with_retry(session, url, semaphore)
                    )
                result = await downloads[url]
            if result is not None:
                return result
        return None

    async def download_crl_groups(self, url_groups: List[List[str]]) -> List[Tuple[str, bool]]:
        """Download logical CRLs, using each inner URL list as ordered mirrors."""
        results = []
        semaphore = asyncio.Semaphore(self.concurrency)
        candidate_count = sum(len(urls) for urls in url_groups)
        logger.info(
            "Downloading %d logical CRLs from %d candidate URLs with concurrency %d...",
            len(url_groups),
            candidate_count,
            self.concurrency,
        )

        resolver = PublicResolver()
        connector = aiohttp.TCPConnector(
            limit=self.concurrency, limit_per_host=10, resolver=resolver
        )
        try:
            async with aiohttp.ClientSession(
                connector=connector,
                middlewares=(public_url_middleware,),
                cookie_jar=aiohttp.DummyCookieJar(),
            ) as session:
                groups = iter(url_groups)
                downloads = {}
                completed = 0

                async def worker():
                    nonlocal completed
                    for urls in groups:
                        result = await self._download_crl_group(session, urls, semaphore, downloads)
                        if result is not None:
                            results.append(result)
                        completed += 1
                        if completed % 1000 == 0 or completed == len(url_groups):
                            logger.info(
                                "Logical CRL download progress: %d/%d", completed, len(url_groups)
                            )

                await asyncio.gather(
                    *(worker() for _ in range(min(self.concurrency, len(url_groups))))
                )
        finally:
            await resolver.close()

        success_count = len(results)
        fail_count = len(url_groups) - success_count
        logger.info(
            f"CRL Download Summary: {success_count} logical CRLs successful, "
            f"{fail_count} failed out of {len(url_groups)} total"
        )
        return results
