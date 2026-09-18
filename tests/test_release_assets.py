import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from compromised_keys.exporter import Exporter
from compromised_keys.release_assets import (
    ReleaseAssetError,
    check_database,
    create_snapshot,
    prepare_release,
    restore_release,
)


def _write_required_exports(export_dir: Path, data_manager, status="ready") -> dict:
    export_dir.mkdir(parents=True)
    version = Exporter(str(export_dir)).export_all(data_manager.get_all_compromised_keys())
    stats = data_manager.get_db_stats()
    (export_dir / "db_stats.json").write_text(json.dumps(stats))
    (export_dir / "misses_report.json").write_text("{}\n")
    report = {
        "run_id": "test-run",
        "release": {"status": status},
        "database": stats,
        "stages": {"export": {"status": "ok", "version": version}},
    }
    data_manager.start_sync_run(report["run_id"])
    data_manager.finish_sync_run(report["run_id"], status, report)
    return report


def test_check_database_rejects_non_sqlite(tmp_path):
    path = tmp_path / "broken.db"
    path.write_bytes(b"not sqlite")

    with pytest.raises(ReleaseAssetError):
        check_database(path)


def test_snapshot_is_consistent(tmp_path, data_manager, sample_certs):
    data_manager.save_revoked_certs(sample_certs)
    snapshot = tmp_path / "snapshot.db"

    result = create_snapshot(Path(data_manager.db_path), snapshot)

    assert result["integrity_check"] == "ok"
    assert result["tables"]["revoked_certs"] == len(sample_certs)
    assert snapshot.is_file()


def test_prepare_and_restore_release_round_trip(tmp_path, data_manager, sample_certs):
    data_manager.save_revoked_certs(sample_certs)
    export_dir = tmp_path / "exports"
    output_dir = tmp_path / "release"
    report = _write_required_exports(export_dir, data_manager)

    manifest = prepare_release(
        Path(data_manager.db_path),
        export_dir,
        output_dir,
        report,
    )
    restored = tmp_path / "restored.db"
    restored_manifest = restore_release(output_dir, restored)

    assert manifest["database"]["sha256"] == restored_manifest["database"]["sha256"]
    assert check_database(restored)["integrity_check"] == "ok"
    assert check_database(restored)["tables"]["revoked_certs"] == len(sample_certs)
    assert (output_dir / "compromised_keys.db.zst").is_file()
    assert (output_dir / "db-manifest.json").is_file()
    assert (output_dir / "SHA256SUMS").is_file()


def test_restore_rejects_checksum_mismatch(tmp_path, data_manager):
    export_dir = tmp_path / "exports"
    output_dir = tmp_path / "release"
    report = _write_required_exports(export_dir, data_manager, "degraded")
    prepare_release(
        Path(data_manager.db_path),
        export_dir,
        output_dir,
        report,
    )
    (output_dir / "compromised_keys.db.zst").write_bytes(b"tampered")

    with pytest.raises(ReleaseAssetError, match="checksum"):
        restore_release(output_dir, tmp_path / "restored.db")


def test_prepare_release_requires_all_exports(tmp_path, data_manager):
    export_dir = tmp_path / "exports"
    export_dir.mkdir()

    with pytest.raises(ReleaseAssetError, match="Missing required release asset"):
        prepare_release(
            Path(data_manager.db_path),
            export_dir,
            tmp_path / "release",
            {"release": {"status": "ready"}},
        )


def test_prepare_release_rejects_blocked_sync(tmp_path, data_manager):
    export_dir = tmp_path / "exports"
    _write_required_exports(export_dir, data_manager)

    with pytest.raises(ReleaseAssetError, match="does not permit release"):
        prepare_release(
            Path(data_manager.db_path),
            export_dir,
            tmp_path / "release",
            {"release": {"status": "blocked"}},
        )


def test_manifest_can_verify_additional_preserved_tables(tmp_path, data_manager):
    with sqlite3.connect(data_manager.db_path) as conn:
        conn.execute("CREATE TABLE archived_audit (message TEXT)")
        conn.execute("INSERT INTO archived_audit VALUES ('retained')")
    path = Path(data_manager.db_path)
    tables = {**check_database(path)["tables"], "archived_audit": 1}
    assert check_database(path, manifest_tables=tables)["tables"] == tables
    with pytest.raises(ReleaseAssetError, match="missing database tables"):
        check_database(path, manifest_tables={**tables, "missing_audit": 1})


def test_snapshot_preserves_extra_data_without_requiring_it(tmp_path, data_manager):
    with sqlite3.connect(data_manager.db_path) as conn:
        conn.execute("CREATE TABLE archived_audit (message TEXT)")
        conn.execute("INSERT INTO archived_audit VALUES ('retained')")
    output = tmp_path / "snapshot.db"
    create_snapshot(Path(data_manager.db_path), output)
    with sqlite3.connect(output) as conn:
        assert conn.execute("SELECT message FROM archived_audit").fetchone()[0] == "retained"


def test_release_omits_crl_failures_without_changing_source(tmp_path, data_manager, sample_certs):
    data_manager.save_revoked_certs(sample_certs)
    url = "https://ca.example/crl"
    marker = "PRIVATE_CRL_DIAGNOSTIC_DO_NOT_PUBLISH"
    data_manager.record_crl_success(url, "downloaded-content")
    data_manager.save_revoked_certs([], crl_hash="downloaded-content")
    data_manager.record_crl_failure(url, 503, marker)
    with sqlite3.connect(data_manager.db_path) as conn:
        conn.execute("ANALYZE")
    source = Path(data_manager.db_path)
    export_dir = tmp_path / "exports"
    output_dir = tmp_path / "release"
    data_manager.start_sync_run("old-failure")
    data_manager.finish_sync_run("old-failure", "blocked", {"stages": {"crl": {"error": marker}}})
    data_manager.record_source_run("old-failure", "crl", "failed", {"error": marker})
    report = _write_required_exports(export_dir, data_manager)
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    (export_dir / "crl_failures.json").write_text(marker)
    output_dir.mkdir()
    (output_dir / "crl_failures.json").write_text("stale report")

    prepare_release(source, export_dir, output_dir, report)
    restored = tmp_path / "restored.db"
    restore_release(output_dir, restored)

    assert not (output_dir / "crl_failures.json").exists()
    assert "crl_failures.json" not in (output_dir / "SHA256SUMS").read_text()
    assert marker.encode() not in restored.read_bytes()
    assert hashlib.sha256(source.read_bytes()).hexdigest() == source_hash
    assert data_manager.get_crl_failures()[0]["last_error"] == marker
    with sqlite3.connect(restored) as conn:
        assert conn.execute(
            "SELECT last_hash, parsed_hash, download_status, consecutive_failures, "
            "last_error, last_failure_at, first_failure_at FROM crl_status WHERE url = ?",
            (url,),
        ).fetchone() == ("downloaded-content", "downloaded-content", None, 0, None, None, None)
        assert conn.execute("SELECT count(*) FROM revoked_certs").fetchone()[0] == len(sample_certs)


def test_release_rejects_unrecorded_report(tmp_path, data_manager):
    exports = tmp_path / "exports"
    report = _write_required_exports(exports, data_manager)
    report["run_id"] = "from-another-database"
    with pytest.raises(ReleaseAssetError, match="latest database run"):
        prepare_release(Path(data_manager.db_path), exports, tmp_path / "release", report)


def test_old_success_cannot_bypass_a_newer_failed_run(tmp_path, data_manager):
    exports = tmp_path / "exports"
    report = _write_required_exports(exports, data_manager)
    data_manager.start_sync_run("new-failure")
    data_manager.finish_sync_run("new-failure", "blocked", {"release": {"status": "blocked"}})
    with pytest.raises(ReleaseAssetError, match="latest database run"):
        prepare_release(Path(data_manager.db_path), exports, tmp_path / "release", report)


def test_release_rejects_database_edits_even_with_same_counts(tmp_path, data_manager, sample_certs):
    from compromised_keys.lookup import LookupOutcome, LookupRecordResult

    data_manager.save_revoked_certs(sample_certs)
    data_manager.record_lookup_results(
        "test",
        [
            LookupRecordResult(
                sample_certs[0], LookupOutcome.FOUND, info={"publickey": "abc", "key_hash": "123"}
            )
        ],
    )
    exports = tmp_path / "exports"
    report = _write_required_exports(exports, data_manager)
    with sqlite3.connect(data_manager.db_path) as conn:
        conn.execute("UPDATE revoked_certs SET public_key='changed' WHERE public_key IS NOT NULL")
    with pytest.raises(ReleaseAssetError, match="does not match database contents"):
        prepare_release(Path(data_manager.db_path), exports, tmp_path / "release", report)


@pytest.mark.parametrize("filenames", [{}, {"csv": {"filename": "../outside"}}])
def test_release_rejects_incomplete_or_unsafe_file_manifest(tmp_path, data_manager, filenames):
    exports = tmp_path / "exports"
    report = _write_required_exports(exports, data_manager)
    path = exports / "metadata.json"
    metadata = json.loads(path.read_text())
    metadata["files"] = filenames
    path.write_text(json.dumps(metadata))
    with pytest.raises(ReleaseAssetError, match="manifest"):
        prepare_release(Path(data_manager.db_path), exports, tmp_path / "release", report)


def test_release_rejects_unreviewed_extra_table(tmp_path, data_manager):
    exports = tmp_path / "exports"
    report = _write_required_exports(exports, data_manager)
    with sqlite3.connect(data_manager.db_path) as conn:
        conn.execute("CREATE TABLE local_credentials (secret TEXT)")
    with pytest.raises(ReleaseAssetError, match="Unreviewed database tables"):
        prepare_release(Path(data_manager.db_path), exports, tmp_path / "release", report)


@pytest.mark.parametrize(
    "change", ["PRAGMA user_version=1", "ALTER TABLE revoked_certs DROP COLUMN aki_source"]
)
def test_check_database_rejects_unsupported_schema(data_manager, change):
    with sqlite3.connect(data_manager.db_path) as conn:
        conn.execute(change)
    with pytest.raises(ReleaseAssetError, match="schema version|columns"):
        check_database(Path(data_manager.db_path))


def test_restore_rejects_oversized_content_without_leaving_database(tmp_path, data_manager):
    from compromised_keys.release_assets import sha256_file

    exports = tmp_path / "exports"
    report = _write_required_exports(exports, data_manager)
    assets = tmp_path / "release"
    prepare_release(Path(data_manager.db_path), exports, assets, report)
    manifest_path = assets / "db-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["database"]["size_bytes"] = 1
    manifest_path.write_text(json.dumps(manifest))
    checksums = assets / "SHA256SUMS"
    checksums.write_text(
        "\n".join(
            f"{sha256_file(assets / name)}  {name}"
            for line in checksums.read_text().splitlines()
            for name in [line.split(None, 1)[1]]
        )
        + "\n"
    )
    destination = tmp_path / "restored.db"
    with pytest.raises(ReleaseAssetError, match="exceeds declared size"):
        restore_release(assets, destination)
    assert not destination.exists()
    assert not (tmp_path / ".restored.db.tmp").exists()


@pytest.mark.parametrize("suffix", ["", "-wal", "-shm", "-journal"])
def test_restore_refuses_existing_database_or_sidecar(tmp_path, suffix):
    destination = tmp_path / "existing.db"
    existing = Path(str(destination) + suffix)
    existing.write_bytes(b"keep existing history")
    with pytest.raises(ReleaseAssetError, match="destination already exists"):
        restore_release(tmp_path / "assets", destination)
    assert existing.read_bytes() == b"keep existing history"


def test_restore_refuses_dangling_symlink(tmp_path):
    destination = tmp_path / "existing.db"
    destination.symlink_to(tmp_path / "missing.db")
    with pytest.raises(ReleaseAssetError, match="destination already exists"):
        restore_release(tmp_path / "assets", destination)
    assert destination.is_symlink()
