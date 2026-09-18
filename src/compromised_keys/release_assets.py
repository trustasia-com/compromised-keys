"""Build and verify reproducible data-release assets."""

import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, Optional

from compromised_keys.data_manager import SCHEMA_VERSION, DataManager
from compromised_keys.exporter import Exporter

DATABASE_FILENAME = "compromised_keys.db.zst"
MANIFEST_FILENAME = "db-manifest.json"
CHECKSUMS_FILENAME = "SHA256SUMS"
REQUIRED_TABLES = (
    "revoked_certs",
    "lookup_state",
    "record_exclusions",
    "sync_runs",
    "source_runs",
    "crl_status",
)
REQUIRED_EXPORTS = (
    "compromised_keys.csv",
    "compromised_keys.bf",
    "metadata.json",
    "misses_report.json",
    "db_stats.json",
)
REQUIRED_COLUMNS = {
    "revoked_certs": {
        "serial_number",
        "issuer",
        "revocation_date",
        "authority_key_identifier",
        "aki_source",
        "public_key",
        "key_hash",
        "is_precert",
        "key_algorithm",
        "key_size",
        "validated_type",
        "notbefore",
        "notafter",
        "cert_sha256",
        "public_key_source",
        "public_key_obtained_at",
        "cleaned_at",
        "cleanup_reason",
    },
    "lookup_state": {
        "serial_number",
        "issuer",
        "source",
        "last_outcome",
        "consecutive_misses",
        "consecutive_errors",
        "last_attempt_at",
        "last_completed_at",
        "next_retry_after",
        "last_status_code",
        "last_error_class",
    },
    "record_exclusions": {
        "serial_number",
        "issuer",
        "reason_code",
        "rationale",
        "created_by",
        "created_at",
        "expires_at",
        "active",
    },
    "crl_status": {
        "url",
        "last_hash",
        "last_update",
        "parsed_hash",
        "download_status",
        "consecutive_failures",
        "last_error",
        "last_failure_at",
        "first_failure_at",
        "ccadb_record_id",
        "ca_owner",
        "certificate_name",
        "sha256_fp",
    },
    "sync_runs": {
        "run_id",
        "started_at",
        "finished_at",
        "release_status",
        "report_json",
    },
    "source_runs": {"run_id", "source", "status", "stats_json", "circuit_reason"},
}


REQUIRED_PRIMARY_KEYS = {
    "revoked_certs": ["serial_number", "issuer"],
    "lookup_state": ["serial_number", "issuer", "source"],
    "record_exclusions": ["serial_number", "issuer"],
    "crl_status": ["url"],
    "sync_runs": ["run_id"],
    "source_runs": ["run_id", "source"],
}


class ReleaseAssetError(RuntimeError):
    """Raised when a release snapshot cannot be created or trusted."""


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _zstandard():
    try:
        import zstandard
    except ImportError as error:
        raise ReleaseAssetError(
            "Zstandard support is required; install compromised-keys[release]"
        ) from error
    return zstandard


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_database(path: Path, *, manifest_tables: Optional[Dict] = None) -> Dict:
    """Verify SQLite integrity and return stable schema/table statistics."""
    path = Path(path)
    if not path.is_file():
        raise ReleaseAssetError(f"Database does not exist: {path}")

    try:
        uri = path.resolve().as_uri() + "?mode=ro"
        with sqlite3.connect(uri, uri=True) as conn:
            integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
            if integrity != "ok":
                raise ReleaseAssetError(f"SQLite integrity check failed: {integrity}")

            available_tables = {
                row[0]
                for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
            }
            missing = set(REQUIRED_TABLES) - available_tables
            if missing:
                raise ReleaseAssetError(
                    "Database schema is missing required tables: " + ", ".join(sorted(missing))
                )

            selected_tables = set(REQUIRED_TABLES)
            if manifest_tables is not None:
                if (
                    not isinstance(manifest_tables, dict)
                    or not selected_tables <= manifest_tables.keys()
                ):
                    raise ReleaseAssetError("Invalid database table manifest")
                selected_tables = set(manifest_tables)
                if not selected_tables <= available_tables:
                    raise ReleaseAssetError("Manifest declares missing database tables")

            tables = {}
            for table in sorted(selected_tables):
                quoted = table.replace('"', '""')
                tables[table] = conn.execute(f'SELECT count(*) FROM "{quoted}"').fetchone()[0]

            columns = {
                table: [row[1] for row in conn.execute(f'PRAGMA table_info("{table}")')]
                for table in REQUIRED_TABLES
            }
            user_version = conn.execute("PRAGMA user_version").fetchone()[0]
            if user_version != SCHEMA_VERSION:
                raise ReleaseAssetError(f"Unsupported database schema version: {user_version}")
            for table, required in REQUIRED_COLUMNS.items():
                if set(columns[table]) != required:
                    raise ReleaseAssetError(f"Unexpected database columns: {table}")
                info = conn.execute(f'PRAGMA table_info("{table}")').fetchall()
                primary_key = [row[1] for row in sorted(info, key=lambda row: row[5]) if row[5]]
                if primary_key != REQUIRED_PRIMARY_KEYS[table]:
                    raise ReleaseAssetError(f"Unexpected database primary key: {table}")
    except (OSError, sqlite3.DatabaseError) as error:
        raise ReleaseAssetError(f"Unable to verify SQLite database: {error}") from error

    return {
        "integrity_check": integrity,
        "user_version": user_version,
        "tables": tables,
        "columns": columns,
    }


def create_snapshot(source: Path, destination: Path) -> Dict:
    """Create a consistent SQLite snapshot with the online backup API."""
    source = Path(source)
    destination = Path(destination)
    if not source.is_file():
        raise ReleaseAssetError(f"Source database does not exist: {source}")

    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp")
    temporary.unlink(missing_ok=True)
    try:
        with sqlite3.connect(source) as source_conn, sqlite3.connect(temporary) as destination_conn:
            source_conn.backup(destination_conn)
        result = check_database(temporary)
        os.replace(temporary, destination)
        return result
    except (OSError, sqlite3.DatabaseError) as error:
        raise ReleaseAssetError(f"Unable to create SQLite snapshot: {error}") from error
    finally:
        temporary.unlink(missing_ok=True)


def compress_zstd(source: Path, destination: Path) -> None:
    """Compress a file with a deterministic Zstandard content stream."""
    zstandard = _zstandard()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as input_stream, destination.open("wb") as output_stream:
        compressor = zstandard.ZstdCompressor(level=10, threads=0)
        compressor.copy_stream(input_stream, output_stream)


def _sanitize_release_snapshot(path: Path) -> Dict:
    """Keep download checkpoints, but omit private CRL failure diagnostics."""
    with sqlite3.connect(path) as conn:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT GLOB 'sqlite_*'"
            )
        }
        unexpected = tables - set(REQUIRED_TABLES)
        if unexpected:
            raise ReleaseAssetError("Unreviewed database tables: " + ", ".join(sorted(unexpected)))
        conn.execute("""
            UPDATE crl_status
            SET download_status = CASE WHEN download_status = 200 THEN 200 ELSE NULL END,
                consecutive_failures = 0, last_error = NULL,
                last_failure_at = NULL, first_failure_at = NULL
        """)
        for table, column, keys in (
            ("sync_runs", "report_json", ("run_id",)),
            ("source_runs", "stats_json", ("run_id", "source")),
        ):
            for row in conn.execute(f"SELECT {', '.join(keys)}, {column} FROM {table}").fetchall():
                if row[-1] is not None:
                    value = _public_report(json.loads(row[-1]))
                    conn.execute(
                        f"UPDATE {table} SET {column}=? WHERE "
                        + " AND ".join(f"{key}=?" for key in keys),
                        (json.dumps(value, sort_keys=True), *row[:-1]),
                    )
        conn.commit()
        # Removed diagnostic text must not survive in free pages of the public file.
        conn.execute("VACUUM")
    return check_database(path)


def _public_report(value):
    """Raw exception messages can include CRL URLs and local paths."""
    if isinstance(value, dict):
        return {
            key: _public_report(item)
            for key, item in value.items()
            if key not in {"error", "last_error"}
        }
    if isinstance(value, list):
        return [_public_report(item) for item in value]
    return value


def _verify_release_run(snapshot: Path, metadata: Dict, report: Dict, export_dir: Path) -> None:
    with sqlite3.connect(snapshot) as conn:
        latest = conn.execute(
            "SELECT run_id FROM sync_runs ORDER BY started_at DESC, rowid DESC LIMIT 1"
        ).fetchone()
        if not latest or latest[0] != report.get("run_id"):
            raise ReleaseAssetError("Sync report is not the latest database run")
        saved = conn.execute(
            "SELECT report_json FROM sync_runs WHERE run_id=? AND finished_at IS NOT NULL "
            "AND release_status IN ('ready', 'degraded')",
            (report.get("run_id"),),
        ).fetchone()
    if not saved or json.loads(saved[0]) != report:
        raise ReleaseAssetError("Sync report does not match a completed run in this database")
    export = report.get("stages", {}).get("export", {})
    if export.get("status") != "ok" or export.get("version") != metadata.get("version"):
        raise ReleaseAssetError("Sync report and export version do not match")
    dm = DataManager(str(snapshot))
    stats = dm.get_db_stats()
    if (
        stats != report.get("database")
        or metadata.get("total_keys") != stats["total_with_public_key"]
    ):
        raise ReleaseAssetError("Database changed after synchronization; run sync again")
    if json.loads((export_dir / "db_stats.json").read_text()) != stats:
        raise ReleaseAssetError("Database statistics do not match the snapshot")
    # Equal counts alone cannot detect edits or swapped exports. Reproduce both data files.
    with tempfile.TemporaryDirectory(prefix="verify-exports-", dir=snapshot.parent) as directory:
        verifier = Exporter(directory)
        records = dm.get_all_compromised_keys()
        verifier.export_to_csv(records)
        verifier.generate_bloom_filter(records)
        for filename in ("compromised_keys.csv", "compromised_keys.bf"):
            if sha256_file(Path(directory) / filename) != sha256_file(export_dir / filename):
                raise ReleaseAssetError(f"Export does not match database contents: {filename}")


def restore_zstd(source: Path, destination: Path, *, expected_size: int) -> None:
    """Decompress a Zstandard file."""
    zstandard = _zstandard()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as input_stream, destination.open("wb") as output_stream:
        decompressor = zstandard.ZstdDecompressor()
        written = 0
        with decompressor.stream_reader(input_stream) as reader:
            while chunk := reader.read(1024 * 1024):
                written += len(chunk)
                if written > expected_size:
                    raise ReleaseAssetError("Restored database exceeds declared size")
                output_stream.write(chunk)
        if written != expected_size:
            raise ReleaseAssetError("Restored database size does not match manifest")


def _write_json(path: Path, value: Dict) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _write_checksums(paths: Iterable[Path], destination: Path) -> None:
    lines = [f"{sha256_file(path)}  {path.name}" for path in sorted(paths)]
    destination.write_text("\n".join(lines) + "\n", encoding="ascii")


def _read_checksums(path: Path) -> Dict[str, str]:
    try:
        entries = {}
        for line in path.read_text(encoding="ascii").splitlines():
            digest, filename = line.split(None, 1)
            filename = filename.strip()
            if (
                len(digest) != 64
                or any(c not in "0123456789abcdefABCDEF" for c in digest)
                or not filename
                or Path(filename).name != filename
                or "\\" in filename
                or filename in entries
            ):
                raise ValueError
            entries[filename] = digest.lower()
        return entries
    except (OSError, ValueError) as error:
        raise ReleaseAssetError(f"Invalid checksum manifest: {path}") from error


def prepare_release(
    db_path: Path,
    export_dir: Path,
    output_dir: Path,
    sync_status: Optional[Dict] = None,
) -> Dict:
    """Build a complete, checksummed data-release directory."""
    db_path = Path(db_path)
    export_dir = Path(export_dir)
    output_dir = Path(output_dir)

    if not sync_status:
        raise ReleaseAssetError("A completed sync report is required for a data release")
    release_status = sync_status.get("release", {}).get("status")
    if release_status not in {"ready", "degraded"}:
        raise ReleaseAssetError(
            f"Sync report does not permit release: {release_status or 'missing status'}"
        )

    for filename in REQUIRED_EXPORTS:
        if not (export_dir / filename).is_file():
            raise ReleaseAssetError(f"Missing required release asset: {export_dir / filename}")

    try:
        metadata = json.loads((export_dir / "metadata.json").read_text(encoding="utf-8"))
        expected_files = {"csv": "compromised_keys.csv", "bloom_filter": "compromised_keys.bf"}
        if set(metadata["files"]) != set(expected_files):
            raise ReleaseAssetError("Invalid export file manifest")
        for kind, filename in expected_files.items():
            entry = metadata["files"][kind]
            if entry["filename"] != filename:
                raise ReleaseAssetError("Invalid export asset filename")
            export_path = export_dir / entry["filename"]
            if not export_path.is_file() or sha256_file(export_path) != entry["sha256"]:
                raise ReleaseAssetError(f"Export checksum mismatch: {export_path.name}")
    except (KeyError, TypeError, json.JSONDecodeError, OSError) as error:
        raise ReleaseAssetError("Invalid export metadata") from error

    output_dir.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}-", dir=str(output_dir.parent)))
    old_output = output_dir.with_name(f".{output_dir.name}.old")
    try:
        snapshot = temporary / "compromised_keys.db"
        create_snapshot(db_path, snapshot)
        _verify_release_run(snapshot, metadata, sync_status, export_dir)
        database_status = _sanitize_release_snapshot(snapshot)
        compressed = temporary / DATABASE_FILENAME
        compress_zstd(snapshot, compressed)

        for filename in REQUIRED_EXPORTS:
            shutil.copy2(export_dir / filename, temporary / filename)

        manifest = {
            "schema_version": f"{SCHEMA_VERSION}.0",
            "generated_at": _utcnow(),
            "database": {
                "filename": DATABASE_FILENAME,
                "sha256": sha256_file(snapshot),
                "compressed_sha256": sha256_file(compressed),
                "size_bytes": snapshot.stat().st_size,
                "compressed_size_bytes": compressed.stat().st_size,
                **database_status,
            },
            "sync_status": _public_report(sync_status),
        }
        _write_json(temporary / MANIFEST_FILENAME, manifest)
        snapshot.unlink()

        checksum_targets = [
            path
            for path in temporary.iterdir()
            if path.is_file() and path.name != CHECKSUMS_FILENAME
        ]
        _write_checksums(checksum_targets, temporary / CHECKSUMS_FILENAME)

        if old_output.exists():
            shutil.rmtree(old_output)
        if output_dir.exists():
            output_dir.replace(old_output)
        temporary.replace(output_dir)
        if old_output.exists():
            shutil.rmtree(old_output)
        return manifest
    except Exception:
        if not output_dir.exists() and old_output.exists():
            old_output.replace(output_dir)
        raise
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def restore_release(asset_dir: Path, output_path: Path) -> Dict:
    """Verify release checksums and atomically restore its database snapshot."""
    asset_dir = Path(asset_dir)
    output_path = Path(output_path)
    for suffix in ("", "-wal", "-shm", "-journal"):
        existing = Path(str(output_path) + suffix)
        if existing.exists() or existing.is_symlink():
            raise ReleaseAssetError(
                f"Restore destination already exists: {existing}. Use a new output path."
            )
    checksums = _read_checksums(asset_dir / CHECKSUMS_FILENAME)

    for filename in (DATABASE_FILENAME, MANIFEST_FILENAME):
        expected = checksums.get(filename)
        path = asset_dir / filename
        if not expected or not path.is_file() or sha256_file(path) != expected:
            raise ReleaseAssetError(f"Release checksum mismatch: {filename}")

    try:
        manifest = json.loads((asset_dir / MANIFEST_FILENAME).read_text(encoding="utf-8"))
        database = manifest["database"]
        if manifest.get("schema_version") != f"{SCHEMA_VERSION}.0" or not isinstance(
            database, dict
        ):
            raise ReleaseAssetError("Unsupported database release manifest")
        if type(database.get("size_bytes")) is not int or database["size_bytes"] <= 0:
            raise ReleaseAssetError("Invalid database size in manifest")
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise ReleaseAssetError("Invalid database release manifest") from error

    compressed = asset_dir / DATABASE_FILENAME
    if sha256_file(compressed) != database.get("compressed_sha256"):
        raise ReleaseAssetError("Release checksum mismatch: compressed database")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_name(f".{output_path.name}.tmp")
    temporary.unlink(missing_ok=True)
    try:
        restore_zstd(compressed, temporary, expected_size=database["size_bytes"])
        if sha256_file(temporary) != database.get("sha256"):
            raise ReleaseAssetError("Release checksum mismatch: restored database")
        restored_status = check_database(temporary, manifest_tables=database.get("tables"))
        if restored_status["columns"] != database.get("columns") or restored_status[
            "user_version"
        ] != database.get("user_version"):
            raise ReleaseAssetError("Restored database schema does not match manifest")
        if restored_status["tables"] != database.get("tables"):
            raise ReleaseAssetError("Restored database table counts do not match manifest")
        os.replace(temporary, output_path)
        return manifest
    finally:
        temporary.unlink(missing_ok=True)
