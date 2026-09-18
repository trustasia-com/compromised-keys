import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from compromised_keys.data_manager import DataManager
from compromised_keys.lookup import LookupOutcome, LookupRecordResult


def _result(record, outcome, info=None, status=None):
    return LookupRecordResult(record, outcome, info=info, status_code=status)


def test_unsupported_database_is_not_modified(tmp_path):
    path = tmp_path / "unsupported.db"
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE revoked_certs (serial_number TEXT, issuer TEXT)")
        conn.execute("INSERT INTO revoked_certs VALUES ('01', 'CN=Test')")
    before = path.read_bytes()
    with pytest.raises(RuntimeError, match="Unsupported database schema"):
        DataManager(str(path))
    assert path.read_bytes() == before


def test_current_database_preserves_inactive_records(data_manager, sample_certs):
    data_manager.save_revoked_certs(sample_certs)
    with sqlite3.connect(data_manager.db_path) as conn:
        conn.execute(
            "UPDATE revoked_certs SET cleaned_at = '2026-01-01' WHERE serial_number = ?",
            (sample_certs[0]["serial_number"],),
        )
    expected = data_manager.get_db_stats()
    reopened = DataManager(data_manager.db_path)
    assert reopened.get_db_stats() == expected
    assert expected["total_revoked"] == 2
    assert expected["cleaned"] == 1
    assert all(
        row["serial_number"] != sample_certs[0]["serial_number"]
        for row in reopened.get_pending_lookup_records("operator_ct")
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("serial_number", None),
        ("serial_number", ""),
        ("issuer", None),
        ("issuer", ""),
        ("validated_type", "NoAudit"),
        ("is_precert", 2),
    ],
)
def test_certificate_constraints_reject_invalid_values(data_manager, sample_certs, field, value):
    data_manager.save_revoked_certs(sample_certs)
    with sqlite3.connect(data_manager.db_path) as conn, pytest.raises(sqlite3.IntegrityError):
        conn.execute(f"UPDATE revoked_certs SET {field} = ?", (value,))


def test_pending_index_selects_only_active_incomplete_records(data_manager):
    with sqlite3.connect(data_manager.db_path) as conn:
        conn.executemany(
            "INSERT INTO revoked_certs (serial_number, issuer, public_key, key_hash, cleaned_at) "
            "VALUES (?, 'CN=Test', ?, ?, ?)",
            [
                ("01", None, None, None),
                ("02", "key", None, None),
                ("03", "key", "hash", None),
                ("04", None, None, "2026-01-01"),
            ],
        )
        before = conn.execute("SELECT * FROM revoked_certs ORDER BY serial_number").fetchall()

    reopened = DataManager(data_manager.db_path)

    assert {r["serial_number"] for r in reopened.get_pending_lookup_records("operator_ct")} == {
        "01",
        "02",
    }
    with sqlite3.connect(data_manager.db_path) as conn:
        assert (
            conn.execute("SELECT * FROM revoked_certs ORDER BY serial_number").fetchall() == before
        )
        # Forcing this index also verifies that its predicate matches pending selection.
        assert (
            conn.execute(
                "SELECT count(*) FROM revoked_certs INDEXED BY idx_revoked_pending "
                "WHERE cleaned_at IS NULL AND (public_key IS NULL OR key_hash IS NULL)"
            ).fetchone()[0]
            == 2
        )


def test_save_revocations_updates_crl_aki(data_manager, sample_certs):
    record = {**sample_certs[0], "authority_key_identifier": "AABB"}
    data_manager.save_revoked_certs([record])
    data_manager.save_revoked_certs([{**record, "authority_key_identifier": "00EE"}])

    saved = data_manager.get_record_by_serial_and_issuer(record["serial_number"], record["issuer"])
    assert saved["authority_key_identifier"] == "00ee"
    assert saved["aki_source"] == "crl"


def test_pending_is_independent_per_source(data_manager, sample_certs):
    data_manager.save_revoked_certs(sample_certs)
    first = sample_certs[0]
    data_manager.record_lookup_results("operator_ct", [_result(first, LookupOutcome.NOT_FOUND)])

    assert first["serial_number"] not in {
        row["serial_number"] for row in data_manager.get_pending_lookup_records("operator_ct")
    }
    assert any(
        row["serial_number"] == first["serial_number"]
        for row in data_manager.get_pending_lookup_records("crtsh_postgres")
    )


def test_errors_do_not_increment_misses_or_create_backoff(data_manager, sample_certs):
    record = sample_certs[0]
    data_manager.save_revoked_certs([record])
    data_manager.record_lookup_results(
        "operator_ct",
        [_result(record, LookupOutcome.HTTP_SERVER_ERROR, status=503)],
    )

    state = data_manager.get_lookup_state(record["serial_number"], record["issuer"], "operator_ct")
    assert state["consecutive_misses"] == 0
    assert state["consecutive_errors"] == 1
    assert state["next_retry_after"] is None
    assert data_manager.get_pending_lookup_records("operator_ct")


def test_only_not_found_increments_source_miss(data_manager, sample_certs):
    record = sample_certs[0]
    data_manager.save_revoked_certs([record])
    data_manager.record_lookup_results("crtsh_postgres", [_result(record, LookupOutcome.NOT_FOUND)])
    state = data_manager.get_lookup_state(
        record["serial_number"], record["issuer"], "crtsh_postgres"
    )
    assert state["consecutive_misses"] == 1
    assert state["consecutive_errors"] == 0
    assert state["last_completed_at"]
    assert state["next_retry_after"]


def test_recent_miss_retries_daily_and_old_miss_weekly(data_manager):
    now = datetime.now(timezone.utc)
    recent = {
        "serial_number": "01",
        "issuer": "CN=Recent",
        "revocation_date": (now - timedelta(days=2)).isoformat(),
    }
    old = {
        "serial_number": "02",
        "issuer": "CN=Old",
        "revocation_date": (now - timedelta(days=90)).isoformat(),
    }
    data_manager.save_revoked_certs([recent, old])
    data_manager.record_lookup_results(
        "operator_ct",
        [_result(recent, LookupOutcome.NOT_FOUND), _result(old, LookupOutcome.NOT_FOUND)],
    )

    recent_retry = datetime.strptime(
        data_manager.get_lookup_state("01", "CN=Recent", "operator_ct")["next_retry_after"],
        "%Y-%m-%d %H:%M:%S",
    ).replace(tzinfo=timezone.utc)
    old_retry = datetime.strptime(
        data_manager.get_lookup_state("02", "CN=Old", "operator_ct")["next_retry_after"],
        "%Y-%m-%d %H:%M:%S",
    ).replace(tzinfo=timezone.utc)
    assert timedelta(hours=23) < recent_retry - now < timedelta(hours=25)
    assert timedelta(days=6) < old_retry - now < timedelta(days=8)


def test_found_writes_key_metadata_and_source(data_manager, sample_certs):
    record = sample_certs[0]
    data_manager.save_revoked_certs([record])
    data_manager.record_lookup_results(
        "crtsh_postgres",
        [
            _result(
                record,
                LookupOutcome.FOUND,
                {
                    "publickey": "deadbeef",
                    "key_hash": "hash",
                    "key_algorithm": "RSA",
                    "key_size": 2048,
                    "validated_type": "DV",
                    "is_precert": True,
                    "cert_sha256": "cert-hash",
                },
            )
        ],
    )

    saved = data_manager.get_record_by_serial_and_issuer(record["serial_number"], record["issuer"])
    assert saved["public_key"] == "deadbeef"
    assert saved["public_key_source"] == "crtsh_postgres"
    assert saved["public_key_obtained_at"]
    assert saved["validated_type"] == "DV"
    assert saved["is_precert"] == 1
    assert (
        data_manager.get_lookup_state(record["serial_number"], record["issuer"], "crtsh_postgres")[
            "last_outcome"
        ]
        == "found"
    )


def test_exact_exclusion_requires_full_identity_and_supports_dry_run_at_cli_layer(
    data_manager, sample_certs
):
    data_manager.save_revoked_certs(sample_certs)
    record = sample_certs[0]
    assert data_manager.set_record_exclusion(
        record["serial_number"],
        record["issuer"],
        reason_code="manual_review",
        rationale="Known non-TLS test hierarchy",
        created_by="operator@example.test",
    )
    pending = data_manager.get_pending_lookup_records("operator_ct")
    assert record["serial_number"] not in {row["serial_number"] for row in pending}
    assert data_manager.get_db_stats()["active_exclusions"] == 1
    assert data_manager.clear_record_exclusion(record["serial_number"], record["issuer"])
    assert data_manager.get_db_stats()["active_exclusions"] == 0


def test_require_aki_and_ignore_retry(data_manager, sample_certs):
    records = [
        {**sample_certs[0], "authority_key_identifier": "aabb"},
        sample_certs[1],
    ]
    data_manager.save_revoked_certs(records)
    assert len(data_manager.get_pending_lookup_records("operator_ct", require_aki=True)) == 1
    data_manager.record_lookup_results(
        "operator_ct", [_result(records[0], LookupOutcome.NOT_FOUND)]
    )
    assert not data_manager.get_pending_lookup_records("operator_ct", require_aki=True)
    assert data_manager.get_pending_lookup_records(
        "operator_ct", require_aki=True, ignore_retry=True
    )


def test_crl_status_and_sync_audit(data_manager):
    data_manager.record_crl_failure("https://example.test/a.crl", 503, "down")
    assert data_manager.get_crl_failures()[0]["consecutive_failures"] == 1
    data_manager.record_crl_success("https://example.test/a.crl", "hash")
    assert data_manager.get_crl_failures() == []

    data_manager.start_sync_run("run-1")
    data_manager.record_source_run("run-1", "crl", "ok", {"success_rate": 0.99})
    data_manager.finish_sync_run("run-1", "ready", {"release": {"status": "ready"}})
    assert data_manager.get_previous_source_stats("crl") == {"success_rate": 0.99}
    assert data_manager.integrity_check() == "ok"


def test_propagate_unique_crl_aki_by_issuer(data_manager, sample_certs):
    records = [
        {**sample_certs[0], "authority_key_identifier": "aabb"},
        sample_certs[1],
    ]
    data_manager.save_revoked_certs(records)
    stats = data_manager.propagate_unique_crl_aki_by_issuer()
    assert stats["updated"] == 1
    second = data_manager.get_record_by_serial_and_issuer(
        sample_certs[1]["serial_number"], sample_certs[1]["issuer"]
    )
    assert second["authority_key_identifier"] == "aabb"
    assert second["aki_source"] == "crl_issuer"


def test_crl_checkpoint_rolls_back_with_invalid_records(data_manager):
    import pytest

    url, digest = "https://example.test/crl", "abc123"
    data_manager.record_crl_success(url, digest)
    with pytest.raises(KeyError):
        data_manager.save_revoked_certs([{}], crl_hash=digest)
    assert data_manager.crl_needs_parsing(url, digest)
    data_manager.save_revoked_certs([], crl_hash=digest)
    assert not data_manager.crl_needs_parsing(url, digest)
