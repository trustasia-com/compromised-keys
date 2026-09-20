import json
import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from compromised_keys import config
from compromised_keys.crypto_utils import normalize_issuer
from compromised_keys.lookup import LookupOutcome, LookupRecordResult

logger = logging.getLogger(__name__)


SCHEMA_VERSION = 3


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _retry_delay_hours(attempts: int) -> int:
    """Backoff for completed source-specific misses."""
    return 24 * 7 if attempts < 10 else 24 * 30


class DataManager:
    def __init__(self, db_path: str = ""):
        self.db_path = db_path or config.DB_PATH
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            existing = cursor.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'revoked_certs'"
            ).fetchone()
            version = cursor.execute("PRAGMA user_version").fetchone()[0]
            if existing and version != SCHEMA_VERSION:
                raise RuntimeError(
                    f"Unsupported database schema version: {version}; expected {SCHEMA_VERSION}"
                )

            cursor.execute("BEGIN IMMEDIATE")
            try:
                self._create_operational_tables(cursor)
                if not existing:
                    self._create_revoked_table(cursor)
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS crl_status (
                    url TEXT NOT NULL PRIMARY KEY,
                    last_hash TEXT,
                    last_update TEXT,
                    parsed_hash TEXT,
                    download_status INTEGER,
                    consecutive_failures INTEGER DEFAULT 0,
                    last_error TEXT,
                    last_failure_at TEXT,
                    first_failure_at TEXT,
                    ccadb_record_id TEXT,
                    ca_owner TEXT,
                    certificate_name TEXT,
                    sha256_fp TEXT
                )
                """)
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_crl_last_hash ON crl_status(last_hash)"
                )
                # Index only pending records; public keys can be several KiB each.
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_revoked_pending "
                    "ON revoked_certs(revocation_date DESC) "
                    "WHERE cleaned_at IS NULL AND (public_key IS NULL OR key_hash IS NULL)"
                )
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_revoked_cleaned ON revoked_certs(cleaned_at)"
                )
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_lookup_due "
                    "ON lookup_state(source, next_retry_after, last_outcome)"
                )
                cursor.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                conn.commit()
            except Exception:
                conn.rollback()
                raise

    @staticmethod
    def _create_revoked_table(cursor):
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS revoked_certs (
                serial_number TEXT NOT NULL CHECK (serial_number != ''),
                issuer TEXT NOT NULL CHECK (issuer != ''),
                revocation_date TEXT,
                authority_key_identifier TEXT,
                aki_source TEXT,
                public_key TEXT,
                key_hash TEXT,
                is_precert INTEGER CHECK (is_precert IN (0, 1)),
                key_algorithm TEXT,
                key_size INTEGER,
                validated_type TEXT CHECK (validated_type IN ('DV', 'OV', 'IV', 'EV')),
                notbefore TEXT,
                notafter TEXT,
                cert_sha256 TEXT,
                public_key_source TEXT,
                public_key_obtained_at TEXT,
                cleaned_at TEXT,
                cleanup_reason TEXT,
                PRIMARY KEY (serial_number, issuer)
            )
        """)

    @staticmethod
    def _create_operational_tables(cursor):
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS lookup_state (
                serial_number TEXT NOT NULL,
                issuer TEXT NOT NULL,
                source TEXT NOT NULL,
                last_outcome TEXT,
                consecutive_misses INTEGER NOT NULL DEFAULT 0,
                consecutive_errors INTEGER NOT NULL DEFAULT 0,
                last_attempt_at TEXT,
                last_completed_at TEXT,
                next_retry_after TEXT,
                last_status_code INTEGER,
                last_error_class TEXT,
                PRIMARY KEY (serial_number, issuer, source)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS record_exclusions (
                serial_number TEXT NOT NULL,
                issuer TEXT NOT NULL,
                reason_code TEXT NOT NULL,
                rationale TEXT NOT NULL,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT,
                active INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (serial_number, issuer)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sync_runs (
                run_id TEXT NOT NULL PRIMARY KEY,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                release_status TEXT,
                report_json TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS source_runs (
                run_id TEXT NOT NULL,
                source TEXT NOT NULL,
                status TEXT NOT NULL,
                stats_json TEXT NOT NULL,
                circuit_reason TEXT,
                PRIMARY KEY (run_id, source)
            )
        """)

    # ----- revoked_certs ---------------------------------------------------

    def save_revoked_certs(self, certs: List[Dict], *, crl_hash: Optional[str] = None):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            for cert in certs:
                cursor.execute(
                    """
                    INSERT INTO revoked_certs (
                        serial_number, issuer, revocation_date,
                        authority_key_identifier, aki_source
                    ) VALUES (?, ?, ?, lower(?), ?)
                    ON CONFLICT(serial_number, issuer) DO UPDATE SET
                        revocation_date = excluded.revocation_date,
                        authority_key_identifier = CASE
                            WHEN excluded.authority_key_identifier IS NOT NULL
                            THEN lower(excluded.authority_key_identifier)
                            ELSE revoked_certs.authority_key_identifier
                        END,
                        aki_source = CASE
                            WHEN excluded.authority_key_identifier IS NOT NULL
                            THEN 'crl'
                            ELSE revoked_certs.aki_source
                        END
                    """,
                    (
                        cert["serial_number"],
                        cert["issuer"],
                        cert["revocation_date"],
                        cert.get("authority_key_identifier"),
                        "crl" if cert.get("authority_key_identifier") else None,
                    ),
                )
            if crl_hash is not None:
                cursor.execute(
                    "UPDATE crl_status SET parsed_hash = ? WHERE last_hash = ?",
                    (crl_hash, crl_hash),
                )
            conn.commit()

    def crl_needs_parsing(self, url: str, content_hash: str) -> bool:
        """A downloaded file is not a checkpoint until its revocations commit."""
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT parsed_hash FROM crl_status WHERE url = ?", (url,)
            ).fetchone()
        return row is None or row[0] != content_hash

    def propagate_unique_crl_aki_by_issuer(self) -> Dict[str, int]:
        from collections import defaultdict

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("BEGIN IMMEDIATE")
            direct_rows = conn.execute(
                """
                SELECT issuer, authority_key_identifier
                FROM revoked_certs
                WHERE aki_source = 'crl'
                  AND authority_key_identifier IS NOT NULL
                  AND authority_key_identifier != ''
                """
            ).fetchall()

            candidates = defaultdict(set)
            for row in direct_rows:
                issuer_norm = normalize_issuer(row["issuer"])
                if issuer_norm:
                    candidates[issuer_norm].add(row["authority_key_identifier"].lower())

            unique = {
                issuer_norm: next(iter(akis))
                for issuer_norm, akis in candidates.items()
                if len(akis) == 1
            }
            conflicts = {issuer_norm for issuer_norm, akis in candidates.items() if len(akis) > 1}

            target_rows = conn.execute(
                """
                SELECT rowid, issuer, authority_key_identifier, aki_source
                FROM revoked_certs
                WHERE COALESCE(aki_source, '') != 'crl'
                """
            ).fetchall()
            updates = []
            clears = []
            for row in target_rows:
                issuer_norm = normalize_issuer(row["issuer"])
                aki_hex = unique.get(issuer_norm)
                if not aki_hex:
                    if row["aki_source"] == "crl_issuer":
                        clears.append((row["rowid"],))
                    continue
                if row["authority_key_identifier"] == aki_hex and row["aki_source"] == "crl_issuer":
                    continue
                updates.append((aki_hex, row["rowid"]))

            cleared = 0
            if clears:
                cursor = conn.executemany(
                    """
                    UPDATE revoked_certs
                    SET authority_key_identifier = NULL, aki_source = NULL
                    WHERE rowid = ? AND aki_source = 'crl_issuer'
                    """,
                    clears,
                )
                cleared = cursor.rowcount

            updated = 0
            if updates:
                cursor = conn.executemany(
                    """
                    UPDATE revoked_certs
                    SET authority_key_identifier = ?, aki_source = 'crl_issuer'
                    WHERE rowid = ? AND COALESCE(aki_source, '') != 'crl'
                    """,
                    updates,
                )
                updated = cursor.rowcount
            conn.commit()

        return {
            "direct_records": len(direct_rows),
            "unique_issuers": len(unique),
            "conflicting_issuers": len(conflicts),
            "updated": updated,
            "cleared": cleared,
        }

    def get_pending_lookup_records(
        self,
        source: str,
        *,
        require_aki: bool = False,
        limit: Optional[int] = None,
        ignore_retry: bool = False,
        newest_first: bool = False,
    ) -> List[Dict]:
        """Return missing-key records currently eligible for one lookup source."""
        now = _utcnow_iso()
        clauses = [
            "(r.public_key IS NULL OR r.key_hash IS NULL)",
            "r.cleaned_at IS NULL",
            "NOT EXISTS (SELECT 1 FROM record_exclusions e "
            "WHERE e.serial_number = r.serial_number AND e.issuer = r.issuer "
            "AND e.active = 1 AND (e.expires_at IS NULL OR e.expires_at > ?))",
        ]
        params: List = [source, now]
        if require_aki:
            clauses.extend(
                [
                    "r.authority_key_identifier IS NOT NULL",
                    "r.authority_key_identifier != ''",
                ]
            )
        if not ignore_retry:
            clauses.append("(s.next_retry_after IS NULL OR s.next_retry_after <= ?)")
            params.append(now)
        limit_sql = ""
        if limit is not None:
            limit_sql = " LIMIT ?"
            params.append(limit)

        order = (
            "julianday(r.revocation_date) DESC, r.serial_number, r.issuer"
            if newest_first
            else "CASE WHEN r.revocation_date > datetime('now', '-30 days') THEN 0 ELSE 1 END, "
            "COALESCE(s.consecutive_misses, 0) ASC, r.revocation_date DESC"
        )
        query = f"""
            SELECT r.serial_number, r.issuer, r.authority_key_identifier,
                   r.revocation_date, COALESCE(s.consecutive_misses, 0) AS source_misses
            FROM revoked_certs r INDEXED BY idx_revoked_pending
            LEFT JOIN lookup_state s
              ON s.serial_number = r.serial_number
             AND s.issuer = r.issuer
             AND s.source = ?
            WHERE {" AND ".join(clauses)}
            ORDER BY {order}
            {limit_sql}
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            return [dict(row) for row in conn.execute(query, params).fetchall()]

    @staticmethod
    def _miss_retry_at(revocation_date: Optional[str], misses: int) -> str:
        now = datetime.now(timezone.utc)
        recent = False
        if revocation_date:
            try:
                parsed = datetime.fromisoformat(revocation_date.replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                recent = parsed >= now - timedelta(days=30)
            except ValueError:
                pass
        hours = 24 if recent else _retry_delay_hours(misses)
        return (now + timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def _update_public_key(cursor, result: LookupRecordResult, source: str, now: str):
        info = result.info or {}
        cursor.execute(
            """
            UPDATE revoked_certs
            SET public_key = ?, key_hash = ?, is_precert = ?,
                key_algorithm = ?, key_size = ?, validated_type = ?,
                notbefore = ?, notafter = ?, cert_sha256 = ?,
                public_key_source = ?, public_key_obtained_at = ?
            WHERE serial_number = ? AND issuer = ?
            """,
            (
                info.get("publickey"),
                info.get("key_hash"),
                1 if info.get("is_precert") else 0,
                info.get("key_algorithm"),
                info.get("key_size"),
                info.get("validated_type"),
                info.get("notbefore"),
                info.get("notafter"),
                info.get("cert_sha256"),
                source,
                now,
                result.record["serial_number"],
                result.record["issuer"],
            ),
        )

    def record_lookup_results(
        self, source: str, results: List[LookupRecordResult]
    ) -> Dict[str, int]:
        """Persist record outcomes without sharing retry state between sources."""
        now = _utcnow_iso()
        counts: Dict[str, int] = {}
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("BEGIN IMMEDIATE")
            for result in results:
                outcome = result.outcome
                counts[outcome.value] = counts.get(outcome.value, 0) + 1
                serial_number = result.record["serial_number"]
                issuer = result.record["issuer"]
                current = cursor.execute(
                    """
                    SELECT consecutive_misses, consecutive_errors, last_completed_at
                    FROM lookup_state
                    WHERE serial_number = ? AND issuer = ? AND source = ?
                    """,
                    (serial_number, issuer, source),
                ).fetchone()
                misses = current[0] if current else 0
                errors = current[1] if current else 0
                completed_at = current[2] if current else None
                next_retry = None

                if outcome == LookupOutcome.FOUND:
                    self._update_public_key(cursor, result, source, now)
                    misses = 0
                    errors = 0
                    completed_at = now
                elif outcome == LookupOutcome.NOT_FOUND:
                    misses += 1
                    errors = 0
                    completed_at = now
                    revocation_row = cursor.execute(
                        """
                        SELECT revocation_date FROM revoked_certs
                        WHERE serial_number = ? AND issuer = ?
                        """,
                        (serial_number, issuer),
                    ).fetchone()
                    next_retry = self._miss_retry_at(
                        revocation_row[0] if revocation_row else None, misses
                    )
                else:
                    errors += 1

                cursor.execute(
                    """
                    INSERT INTO lookup_state (
                        serial_number, issuer, source, last_outcome,
                        consecutive_misses, consecutive_errors, last_attempt_at,
                        last_completed_at, next_retry_after, last_status_code,
                        last_error_class
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(serial_number, issuer, source) DO UPDATE SET
                        last_outcome = excluded.last_outcome,
                        consecutive_misses = excluded.consecutive_misses,
                        consecutive_errors = excluded.consecutive_errors,
                        last_attempt_at = excluded.last_attempt_at,
                        last_completed_at = excluded.last_completed_at,
                        next_retry_after = excluded.next_retry_after,
                        last_status_code = excluded.last_status_code,
                        last_error_class = excluded.last_error_class
                    """,
                    (
                        serial_number,
                        issuer,
                        source,
                        outcome.value,
                        misses,
                        errors,
                        now,
                        completed_at,
                        next_retry,
                        result.status_code,
                        result.error_class or None,
                    ),
                )
            conn.commit()
        return counts

    def get_lookup_state(self, serial_number: str, issuer: str, source: str) -> Optional[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                """
                SELECT * FROM lookup_state
                WHERE serial_number = ? AND issuer = ? AND source = ?
                """,
                (serial_number, issuer, source),
            ).fetchone()
            return dict(row) if row else None

    # ----- synchronization audit -----------------------------------------

    def start_sync_run(self, run_id: str) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO sync_runs (
                    run_id, started_at, release_status, report_json
                ) VALUES (?, ?, 'running', ?)
                """,
                (
                    run_id,
                    _utcnow_iso(),
                    json.dumps({}, sort_keys=True),
                ),
            )
            conn.commit()

    def record_source_run(
        self,
        run_id: str,
        source: str,
        status: str,
        stats: Dict,
        circuit_reason: str = "",
    ) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO source_runs (
                    run_id, source, status, stats_json, circuit_reason
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (run_id, source, status, json.dumps(stats, sort_keys=True), circuit_reason or None),
            )
            conn.commit()

    def finish_sync_run(self, run_id: str, release_status: str, report: Dict) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                UPDATE sync_runs
                SET finished_at = ?, release_status = ?, report_json = ?
                WHERE run_id = ?
                """,
                (_utcnow_iso(), release_status, json.dumps(report, sort_keys=True), run_id),
            )
            conn.commit()

    def get_previous_source_stats(self, source: str, exclude_run_id: str = "") -> Optional[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                """
                SELECT sr.stats_json
                FROM source_runs sr JOIN sync_runs r ON r.run_id = sr.run_id
                WHERE sr.source = ? AND sr.run_id != ? AND r.release_status != 'blocked'
                ORDER BY r.started_at DESC LIMIT 1
                """,
                (source, exclude_run_id),
            ).fetchone()
        if not row:
            return None
        try:
            return json.loads(row[0])
        except (TypeError, json.JSONDecodeError):
            return None

    def integrity_check(self) -> str:
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute("PRAGMA integrity_check").fetchone()[0]

    def get_all_compromised_keys(self) -> List[Dict]:
        """Return all records that have a public key and have not been cleaned up."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM revoked_certs WHERE public_key IS NOT NULL AND cleaned_at IS NULL"
            )
            return [dict(row) for row in cursor.fetchall()]

    def get_db_stats(self) -> Dict:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            stats = {}
            cursor.execute("SELECT count(*) FROM revoked_certs WHERE cleaned_at IS NULL")
            stats["total_revoked"] = cursor.fetchone()[0]

            cursor.execute(
                "SELECT count(*) FROM revoked_certs WHERE public_key IS NOT NULL AND cleaned_at IS NULL"
            )
            stats["total_with_public_key"] = cursor.fetchone()[0]

            cursor.execute(
                "SELECT count(DISTINCT public_key) FROM revoked_certs WHERE public_key IS NOT NULL AND cleaned_at IS NULL"
            )
            stats["unique_public_keys"] = cursor.fetchone()[0]

            cursor.execute(
                """
                SELECT count(*) FROM record_exclusions
                WHERE active = 1 AND (expires_at IS NULL OR expires_at > ?)
                """,
                (_utcnow_iso(),),
            )
            stats["active_exclusions"] = cursor.fetchone()[0]

            cursor.execute(
                """
                SELECT count(*) FROM revoked_certs
                WHERE (public_key IS NULL OR key_hash IS NULL) AND cleaned_at IS NULL
                """
            )
            stats["missing_public_key"] = cursor.fetchone()[0]

            cursor.execute("SELECT count(*) FROM revoked_certs WHERE cleaned_at IS NOT NULL")
            stats["cleaned"] = cursor.fetchone()[0]

            return stats

    def get_record_by_serial_and_issuer(self, serial_number: str, issuer: str) -> Optional[Dict]:
        """Look up a specific record by serial number and issuer."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM revoked_certs WHERE serial_number = ? AND issuer = ?",
                (serial_number, issuer),
            )
            row = cursor.fetchone()
            return dict(row) if row else None

    # ----- exact record exclusions ----------------------------------------

    def set_record_exclusion(
        self,
        serial_number: str,
        issuer: str,
        *,
        reason_code: str,
        rationale: str,
        created_by: str,
        expires_at: Optional[str] = None,
    ) -> bool:
        """Exclude one exact record; broad issuer-pattern exclusions are unsupported."""
        with sqlite3.connect(self.db_path) as conn:
            exists = conn.execute(
                "SELECT 1 FROM revoked_certs WHERE serial_number = ? AND issuer = ?",
                (serial_number, issuer),
            ).fetchone()
            if not exists:
                return False
            conn.execute(
                """
                INSERT INTO record_exclusions (
                    serial_number, issuer, reason_code, rationale,
                    created_by, created_at, expires_at, active
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                ON CONFLICT(serial_number, issuer) DO UPDATE SET
                    reason_code = excluded.reason_code,
                    rationale = excluded.rationale,
                    created_by = excluded.created_by,
                    created_at = excluded.created_at,
                    expires_at = excluded.expires_at,
                    active = 1
                """,
                (
                    serial_number,
                    issuer,
                    reason_code,
                    rationale,
                    created_by,
                    _utcnow_iso(),
                    expires_at,
                ),
            )
            conn.commit()
            return True

    def clear_record_exclusion(self, serial_number: str, issuer: str) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """
                UPDATE record_exclusions SET active = 0
                WHERE serial_number = ? AND issuer = ? AND active = 1
                """,
                (serial_number, issuer),
            )
            conn.commit()
            return cursor.rowcount == 1

    # ----- crl_status ------------------------------------------------------

    def register_crl_sources(self, sources: List[Dict]):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.executemany(
                """
                INSERT INTO crl_status (url, ccadb_record_id, ca_owner, certificate_name, sha256_fp)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(url) DO UPDATE SET
                    ccadb_record_id = COALESCE(NULLIF(excluded.ccadb_record_id, ''), crl_status.ccadb_record_id),
                    ca_owner        = COALESCE(NULLIF(excluded.ca_owner, ''),        crl_status.ca_owner),
                    certificate_name= COALESCE(NULLIF(excluded.certificate_name, ''),crl_status.certificate_name),
                    sha256_fp       = COALESCE(NULLIF(excluded.sha256_fp, ''),       crl_status.sha256_fp)
                """,
                (
                    (
                        s["url"],
                        s.get("ccadb_record_id", ""),
                        s.get("ca_owner", ""),
                        s.get("certificate_name", ""),
                        s.get("sha256_fp", ""),
                    )
                    for s in sources
                ),
            )
            conn.commit()

    def record_crl_success(self, url: str, content_hash: str):
        now = _utcnow_iso()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO crl_status (url, last_hash, last_update, download_status, consecutive_failures)
                VALUES (?, ?, ?, 200, 0)
                ON CONFLICT(url) DO UPDATE SET
                    last_hash = excluded.last_hash,
                    last_update = excluded.last_update,
                    download_status = 200,
                    consecutive_failures = 0,
                    last_error = NULL,
                    last_failure_at = NULL,
                    first_failure_at = NULL
                """,
                (url, content_hash, now),
            )
            conn.commit()

    def record_crl_failure(self, url: str, status_code: int, error: str):
        now = _utcnow_iso()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            # Make sure the row exists
            cursor.execute("SELECT first_failure_at FROM crl_status WHERE url = ?", (url,))
            row = cursor.fetchone()
            first_failure = row[0] if row and row[0] else now
            cursor.execute(
                """
                INSERT INTO crl_status (
                    url, download_status, consecutive_failures, last_error,
                    last_failure_at, first_failure_at
                )
                VALUES (?, ?, 1, ?, ?, ?)
                ON CONFLICT(url) DO UPDATE SET
                    download_status = excluded.download_status,
                    consecutive_failures = COALESCE(crl_status.consecutive_failures, 0) + 1,
                    last_error = excluded.last_error,
                    last_failure_at = excluded.last_failure_at,
                    first_failure_at = COALESCE(crl_status.first_failure_at, excluded.first_failure_at)
                """,
                (url, status_code, error, now, first_failure),
            )
            conn.commit()

    def get_crl_failures(self) -> List[Dict]:
        """Return all CRL URLs that currently have at least one consecutive failure."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT url, download_status, consecutive_failures, last_error,
                       last_failure_at, first_failure_at, ccadb_record_id,
                       ca_owner, certificate_name, sha256_fp
                FROM crl_status
                WHERE COALESCE(consecutive_failures, 0) > 0
                ORDER BY consecutive_failures DESC
                """
            )
            return [dict(row) for row in cursor.fetchall()]
