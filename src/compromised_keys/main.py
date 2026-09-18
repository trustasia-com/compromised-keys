import asyncio
import hashlib
import json
import logging
import os
import time
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from datetime import datetime, timezone
from typing import Dict, List, Optional
from uuid import uuid4

from compromised_keys import config
from compromised_keys.ct_client import CTClient
from compromised_keys.data_manager import DataManager
from compromised_keys.downloader import Downloader
from compromised_keys.exporter import Exporter
from compromised_keys.lookup import LookupOutcome
from compromised_keys.parser import CCADBParser, CRLParser

logger = logging.getLogger(__name__)


class SyncError(RuntimeError):
    """Raised when a required synchronization stage cannot complete."""

    def __init__(self, message: str, report: Optional[Dict] = None):
        super().__init__(message)
        self.report = report


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class CompromisedKeysManager:
    def __init__(self, ct_provider=None):
        self.data_manager = DataManager()
        self.downloader = Downloader(data_manager=self.data_manager)
        self.ct_client = ct_provider if ct_provider else CTClient()
        self.ct_enabled = ct_provider is not None or bool(config.CT_SERVER_HOST)
        self.exporter = Exporter()

    # ------------------------------------------------------------------
    # CRL phase
    # ------------------------------------------------------------------

    def _register_crl_sources(self, sources: List[Dict]):
        """Register the current CCADB attribution in one transaction."""
        self.data_manager.register_crl_sources(
            [
                {**source, "url": url}
                for source in sources
                for url in source.get("urls", [source["url"]])
            ]
        )

    async def crl_sync_only(self) -> Dict:
        """Download CRLs for TLS-capable CCADB intermediates and parse keyCompromise revocations."""
        stats = {
            "crl_urls_found": 0,
            "crl_files_downloaded": 0,
            "crl_download_errors": 0,
            "total_revoked_found": 0,
        }

        ccadb_path = self.downloader.download_ccadb_records()
        if not ccadb_path:
            raise SyncError("CCADB download failed; CRL sync cannot continue")

        try:
            scope = CCADBParser.load_intermediate_scope(ccadb_path)
        except ValueError as error:
            raise SyncError(f"CCADB scope validation failed: {error}") from error

        sources = scope.crl_sources
        stats.update(
            {
                "ccadb_records_total": scope.records_total,
                "ccadb_eligible_intermediates": scope.eligible_intermediates,
            }
        )
        url_groups = [source.get("urls", [source["url"]]) for source in sources]
        declared_urls = scope.declared_crl_urls or len(
            {url for group in url_groups for url in group}
        )
        stats["crl_urls_found"] = declared_urls
        stats["crl_download_targets"] = len(url_groups)

        self._register_crl_sources(sources)

        crl_results = await self.downloader.download_crl_groups(url_groups)

        all_downloaded = list(dict.fromkeys(path for path, _updated in crl_results if path))
        updated_crls = list(
            dict.fromkeys(path for path, updated in crl_results if path and updated)
        )
        stats["crl_parse_targets"] = len(updated_crls)
        stats["crl_parse_errors"] = 0
        stats["crl_unchanged_skipped"] = len(all_downloaded) - len(updated_crls)

        if updated_crls:
            logger.info(f"Starting parallel parsing for {len(updated_crls)} updated CRLs...")
            with ProcessPoolExecutor(max_workers=config.CRL_PARSE_WORKERS) as executor:
                paths = iter(updated_crls)
                pending = {}

                def submit_next():
                    path = next(paths, None)
                    if path is not None:
                        pending[executor.submit(CRLParser.get_revoked_serials, path)] = path

                for _ in range(config.CRL_PARSE_WORKERS * 2):
                    submit_next()
                while pending:
                    completed, _ = wait(pending, return_when=FIRST_COMPLETED)
                    for future in completed:
                        path = pending.pop(future)
                        try:
                            revoked_certs = future.result()
                            digest = hashlib.sha256()
                            with open(path, "rb") as stream:
                                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                                    digest.update(chunk)
                            self.data_manager.save_revoked_certs(
                                revoked_certs, crl_hash=digest.hexdigest()
                            )
                            stats["total_revoked_found"] += len(revoked_certs)
                        except Exception as error:
                            stats["crl_parse_errors"] += 1
                            logger.error("Error parsing or saving %s: %s", path, error)
                        submit_next()

        issuer_aki_stats = self.data_manager.propagate_unique_crl_aki_by_issuer()
        stats["crl_issuer_aki_updated"] = issuer_aki_stats["updated"]
        stats["crl_issuer_aki_conflicts"] = issuer_aki_stats["conflicting_issuers"]
        logger.info(
            "CRL issuer AKI propagation: %d updated, %d conflicting issuers",
            issuer_aki_stats["updated"],
            issuer_aki_stats["conflicting_issuers"],
        )

        stats["crl_files_downloaded"] = sum(1 for p, _u in crl_results if p)
        stats["crl_download_errors"] = len(url_groups) - stats["crl_files_downloaded"]
        stats["success_rate"] = (
            round(stats["crl_files_downloaded"] / len(url_groups), 6) if url_groups else 0.0
        )
        return stats

    # ------------------------------------------------------------------
    # CT phase
    # ------------------------------------------------------------------

    async def ct_sync_only(self, *, ignore_retry: bool = False) -> Dict:
        """Run the optional operator CT source over source-eligible records."""
        source = "operator_ct"
        stats = {
            "status": "ok",
            "source": source,
            "submitted": 0,
            "updated": 0,
            "requests_total": 0,
            "requests_failed": 0,
            "outcomes": {},
        }
        pending_records = self.data_manager.get_pending_lookup_records(
            source, require_aki=True, ignore_retry=ignore_retry
        )
        manager_batch_size = 5000
        stats["selected"] = len(pending_records)

        for offset in range(0, len(pending_records), manager_batch_size):
            current_batch = pending_records[offset : offset + manager_batch_size]
            logger.info(
                "CT batch: %d records (Total pending: %d)...",
                len(current_batch),
                len(pending_records),
            )
            outcome = await self.ct_client.query_records_async(
                current_batch, concurrency=config.CT_CONCURRENCY
            )
            counts = self.data_manager.record_lookup_results(source, outcome.records)
            stats["submitted"] += len(outcome.records)
            stats["updated"] += counts.get(LookupOutcome.FOUND.value, 0)
            stats["requests_total"] += outcome.requests_total
            stats["requests_failed"] += outcome.requests_failed
            for name, count in counts.items():
                stats["outcomes"][name] = stats["outcomes"].get(name, 0) + count
            missing_der = counts.get(LookupOutcome.MISSING_DER.value, 0)
            if missing_der:
                logger.warning("CT response omitted DER for %d requested records", missing_der)
            if outcome.circuit_open:
                stats["circuit_open"] = True
                stats["circuit_reason"] = outcome.circuit_reason
                break

        if stats["requests_failed"] or stats.get("circuit_open"):
            stats["status"] = "degraded"
        stats["deferred"] = stats["selected"] - stats["submitted"]
        return stats

    # ------------------------------------------------------------------
    # Combined run
    # ------------------------------------------------------------------

    def _export_all(self):
        all_compromised = self.data_manager.get_all_compromised_keys()
        version = self.exporter.export_all(all_compromised)
        return version, self.data_manager.get_db_stats()

    def _verify_exports(self) -> bool:
        try:
            with open(self.exporter.metadata_path, encoding="utf-8") as stream:
                metadata = json.load(stream)
            for item in metadata["files"].values():
                path = os.path.join(self.exporter.csv_dir, item["filename"])
                if self.exporter._calculate_sha256(path) != item["sha256"]:
                    return False
            return True
        except (OSError, KeyError, TypeError, json.JSONDecodeError):
            return False

    def _release_gate(
        self, report: Dict, baseline: Dict, db_stats: Dict, previous_crl: Optional[Dict]
    ) -> Dict:
        blockers = []
        warnings = []
        crl = report["stages"]["crl"]
        if crl.get("crl_parse_errors", 0):
            blockers.append("crl_parse_failed")
        if (
            crl.get("ccadb_records_total", 0) <= 0
            or crl.get("ccadb_eligible_intermediates", 0) <= 0
        ):
            blockers.append("ccadb_scope_empty")
        targets = crl.get("crl_download_targets", crl.get("crl_urls_found", 0))
        success_rate = crl.get("crl_files_downloaded", 0) / targets if targets else 0.0
        crl["success_rate"] = round(success_rate, 6)
        if success_rate < 0.95:
            blockers.append("crl_success_rate_below_95_percent")
        if (
            previous_crl
            and previous_crl.get("success_rate") is not None
            and success_rate < float(previous_crl["success_rate"]) - 0.02
        ):
            blockers.append("crl_success_rate_drop_over_2_points")
        if self.data_manager.integrity_check() != "ok":
            blockers.append("sqlite_integrity_check_failed")
        if db_stats["total_revoked"] < baseline["total_revoked"]:
            blockers.append("active_record_count_decreased")
        if db_stats["total_with_public_key"] < baseline["total_with_public_key"]:
            blockers.append("public_key_count_decreased")
        if not self._verify_exports():
            blockers.append("export_hash_mismatch")
        for source in ("ct", "crtsh"):
            if report["stages"].get(source, {}).get("status") in {"failed", "degraded"}:
                warnings.append(f"optional_source_{source}_degraded")
        status = "blocked" if blockers else ("degraded" if warnings else "ready")
        return {"status": status, "blockers": blockers, "warnings": warnings}

    async def run_once(
        self,
        crtsh_mode: str = "",
        crtsh_limit: int = 5000,
        include_crtsh: bool = True,
    ) -> Dict:
        logger.info("Starting a new update cycle...")
        run_id = str(uuid4())
        baseline = self.data_manager.get_db_stats()
        previous_crl = self.data_manager.get_previous_source_stats("crl", run_id)
        report: Dict = {"run_id": run_id, "started_at": _utcnow_iso(), "stages": {}}
        self.data_manager.start_sync_run(run_id)
        stage_started = time.monotonic()

        # 1) CCADB + CRL
        try:
            crl_stats = await self.crl_sync_only()
        except Exception as error:
            report["stages"]["crl"] = {"status": "failed", "error": str(error)}
            report["release"] = {
                "status": "blocked",
                "blockers": ["required_crl_stage_failed"],
                "warnings": [],
            }
            report["finished_at"] = _utcnow_iso()
            self.data_manager.record_source_run(run_id, "crl", "failed", report["stages"]["crl"])
            self.data_manager.finish_sync_run(run_id, "blocked", report)
            raise SyncError(str(error), report=report) from error
        report["stages"]["crl"] = {"status": "ok", **crl_stats}
        report["stages"]["crl"]["duration_seconds"] = round(time.monotonic() - stage_started, 3)
        self.data_manager.record_source_run(run_id, "crl", "ok", report["stages"]["crl"])

        # 2) Optional CT supplementation
        stage_started = time.monotonic()
        if self.ct_enabled:
            try:
                ct_stats = await self.ct_sync_only()
                report["stages"]["ct"] = {"status": "ok", **ct_stats}
            except Exception as error:
                logger.exception("Optional CT supplementation failed")
                report["stages"]["ct"] = {
                    "status": "failed",
                    "error_class": type(error).__name__,
                }
        else:
            report["stages"]["ct"] = {
                "status": "skipped",
                "reason": "not_configured",
            }
        report["stages"]["ct"]["duration_seconds"] = round(time.monotonic() - stage_started, 3)
        self.data_manager.record_source_run(
            run_id,
            "operator_ct",
            report["stages"]["ct"]["status"],
            report["stages"]["ct"],
            report["stages"]["ct"].get("circuit_reason", ""),
        )

        # 3) Public crt.sh supplementation
        stage_started = time.monotonic()
        if include_crtsh:
            from compromised_keys.crt_sh_crawler import CrtShSupplementer

            try:
                supplementer = CrtShSupplementer(mode=crtsh_mode, db_path=self.data_manager.db_path)
                report["stages"]["crtsh"] = await supplementer.run(
                    limit=crtsh_limit, export_results=False
                )
            except Exception as error:
                logger.exception("crt.sh supplementation failed")
                report["stages"]["crtsh"] = {
                    "status": "failed",
                    "mode": crtsh_mode or config.CRTSH_MODE,
                    "error_class": type(error).__name__,
                }
        else:
            report["stages"]["crtsh"] = {
                "status": "skipped",
                "reason": "disabled",
            }
        report["stages"]["crtsh"]["duration_seconds"] = round(time.monotonic() - stage_started, 3)
        self.data_manager.record_source_run(
            run_id,
            f"crtsh_{crtsh_mode or config.CRTSH_MODE}",
            report["stages"]["crtsh"]["status"],
            report["stages"]["crtsh"],
            report["stages"]["crtsh"].get("circuit_reason", ""),
        )

        # 4) Export and evaluate release gates after all database writes.
        stage_started = time.monotonic()
        try:
            version, db_stats = self._export_all()
        except Exception as error:
            report["stages"]["export"] = {"status": "failed", "error": str(error)}
            report["release"] = {"status": "blocked", "blockers": ["export_failed"], "warnings": []}
            report["finished_at"] = _utcnow_iso()
            self.data_manager.finish_sync_run(run_id, "blocked", report)
            raise SyncError("Export failed", report=report) from error
        report["stages"]["export"] = {
            "status": "ok",
            "version": version,
            "total_keys": db_stats["total_with_public_key"],
            "duration_seconds": round(time.monotonic() - stage_started, 3),
        }
        report["database"] = db_stats
        report["release"] = self._release_gate(report, baseline, db_stats, previous_crl)
        report["finished_at"] = _utcnow_iso()
        self.data_manager.finish_sync_run(run_id, report["release"]["status"], report)
        logger.info("=" * 50)
        logger.info(f"Cycle Summary (Version: {version}):")
        logger.info(
            f"  DL Success: {crl_stats.get('crl_files_downloaded', 0)}, "
            f"Revocations observed: {crl_stats.get('total_revoked_found', 0)}"
        )
        ct_report = report["stages"]["ct"]
        if ct_report["status"] == "ok":
            logger.info(
                f"  CT Requests: {ct_report.get('requests_total', 0)}, "
                f"New Keys: {ct_report.get('updated', 0)}"
            )
        else:
            logger.info(f"  CT Status: {ct_report['status']}")
        logger.info(
            f"  DB Total Records: {db_stats['total_revoked']}, "
            f"DB Total Keys: {db_stats['total_with_public_key']}, "
            f"Exclusions: {db_stats['active_exclusions']}, "
            f"Cleaned: {db_stats['cleaned']}"
        )
        logger.info("=" * 50)
        return report

    async def run_forever(
        self,
        interval_hours: int = 0,
        crtsh_mode: str = "",
        crtsh_limit: int = 5000,
        include_crtsh: bool = True,
    ):
        interval_hours = interval_hours or config.SYNC_INTERVAL_HOURS
        while True:
            try:
                await self.run_once(
                    crtsh_mode=crtsh_mode,
                    crtsh_limit=crtsh_limit,
                    include_crtsh=include_crtsh,
                )
            except Exception as e:
                logger.error(f"Error in run_forever: {e}")
            logger.info(f"Sleeping for {interval_hours} hours...")
            await asyncio.sleep(interval_hours * 3600)
