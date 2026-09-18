import json
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from compromised_keys import cli
from compromised_keys.lookup import LookupOutcome, LookupProviderResult, LookupRecordResult
from compromised_keys.main import CompromisedKeysManager, SyncError
from compromised_keys.parser import CCADBScope


async def test_crl_parse_failure_is_retried_before_checkpoint(
    monkeypatch, tmp_path, data_manager, crl_der
):
    import hashlib

    from compromised_keys.downloader import Downloader

    path = tmp_path / "cached.crl"
    path.write_bytes(crl_der)
    url = "https://example.test/crl"
    digest = hashlib.sha256(crl_der).hexdigest()
    data_manager.record_crl_success(url, digest)
    manager = CompromisedKeysManager.__new__(CompromisedKeysManager)
    manager.data_manager = data_manager
    manager.downloader = Downloader(cache_dir=str(tmp_path / "cache"), data_manager=data_manager)
    monkeypatch.setattr(manager.downloader, "download_ccadb_records", lambda: "ccadb.csv")

    async def download(_groups):
        return [(str(path), data_manager.crl_needs_parsing(url, digest))]

    monkeypatch.setattr(manager.downloader, "download_crl_groups", download)
    monkeypatch.setattr("compromised_keys.main.ProcessPoolExecutor", ThreadPoolExecutor)
    monkeypatch.setattr(
        "compromised_keys.main.CCADBParser.load_intermediate_scope",
        lambda _path: CCADBScope(1, 1, [{"url": url}]),
    )
    original = data_manager.save_revoked_certs

    def fail(*_args, **_kwargs):
        raise OSError("injected persistence failure")

    monkeypatch.setattr(data_manager, "save_revoked_certs", fail)
    failed = await manager.crl_sync_only()
    assert failed["crl_parse_errors"] == 1
    assert data_manager.crl_needs_parsing(url, digest)
    monkeypatch.setattr(data_manager, "save_revoked_certs", original)
    recovered = await manager.crl_sync_only()
    assert recovered["crl_parse_errors"] == 0
    assert not data_manager.crl_needs_parsing(url, digest)
    repeated = await manager.crl_sync_only()
    assert repeated["crl_parse_targets"] == 0
    assert repeated["crl_unchanged_skipped"] == 1


@pytest.mark.parametrize("failed_stage", ["crl", "export"])
async def test_sync_failure_retains_blocked_report(monkeypatch, data_manager, failed_stage):
    manager = CompromisedKeysManager.__new__(CompromisedKeysManager)
    manager.data_manager = data_manager
    manager.ct_enabled = False

    async def crl_sync():
        if failed_stage == "crl":
            raise SyncError("injected CRL failure")
        return {}

    def export():
        raise OSError("injected export failure")

    monkeypatch.setattr(manager, "crl_sync_only", crl_sync)
    monkeypatch.setattr(manager, "_export_all", export)
    with pytest.raises(SyncError) as error:
        await manager.run_once(include_crtsh=False)
    assert error.value.report["release"]["status"] == "blocked"
    assert error.value.report["stages"][failed_stage]["status"] == "failed"


async def test_crl_sync_uses_tls_scope_and_full_crl_mirrors(monkeypatch):
    calls = []

    class Downloader:
        def download_ccadb_records(self):
            return "ccadb.csv"

        async def download_crl_groups(self, url_groups):
            calls.append(url_groups)
            return []

    manager = CompromisedKeysManager.__new__(CompromisedKeysManager)
    manager.downloader = Downloader()
    manager.data_manager = SimpleNamespace(
        propagate_unique_crl_aki_by_issuer=lambda: {
            "updated": 3,
            "conflicting_issuers": 1,
        }
    )
    manager._register_crl_sources = lambda _sources: None
    monkeypatch.setattr(
        "compromised_keys.main.CCADBParser.load_intermediate_scope",
        lambda _path: CCADBScope(
            records_total=10,
            eligible_intermediates=2,
            crl_sources=[
                {
                    "url": "https://example.test/ca-primary.crl",
                    "urls": [
                        "https://example.test/ca-primary.crl",
                        "https://example.test/ca-mirror.crl",
                    ],
                    "crl_type": "full",
                }
            ],
            declared_crl_urls=2,
        ),
    )

    stats = await manager.crl_sync_only()

    assert calls == [
        [
            [
                "https://example.test/ca-primary.crl",
                "https://example.test/ca-mirror.crl",
            ]
        ]
    ]
    assert stats["ccadb_records_total"] == 10
    assert stats["ccadb_eligible_intermediates"] == 2
    assert stats["crl_urls_found"] == 2
    assert stats["crl_download_targets"] == 1
    assert stats["crl_issuer_aki_updated"] == 3


async def test_crl_sync_fails_closed_when_ccadb_download_fails():
    manager = CompromisedKeysManager.__new__(CompromisedKeysManager)
    manager.downloader = SimpleNamespace(download_ccadb_records=lambda: None)
    with pytest.raises(SyncError, match="CCADB"):
        await manager.crl_sync_only()


class CTProvider:
    async def query_records_async(self, records, concurrency=0):
        by_serial = {record["serial_number"]: record for record in records}
        return LookupProviderResult(
            records=[
                LookupRecordResult(
                    by_serial["0a1b2c3d4e"],
                    LookupOutcome.FOUND,
                    info={"publickey": "aa", "key_hash": "hash"},
                ),
                LookupRecordResult(
                    by_serial["ff00ee11dd"],
                    LookupOutcome.HTTP_SERVER_ERROR,
                    status_code=503,
                ),
                LookupRecordResult(by_serial["aabbccddee"], LookupOutcome.NOT_FOUND),
            ],
            requests_total=3,
            requests_failed=1,
        )


async def test_ct_sync_persists_outcomes_without_turning_errors_into_misses(
    data_manager, sample_certs
):
    records = [{**record, "authority_key_identifier": "aabb"} for record in sample_certs]
    data_manager.save_revoked_certs(records)
    manager = CompromisedKeysManager.__new__(CompromisedKeysManager)
    manager.data_manager = data_manager
    manager.ct_client = CTProvider()

    stats = await manager.ct_sync_only()

    assert stats["status"] == "degraded"
    assert stats["updated"] == 1
    assert stats["outcomes"] == {
        "found": 1,
        "http_server_error": 1,
        "not_found": 1,
    }
    error_state = data_manager.get_lookup_state(
        records[1]["serial_number"], records[1]["issuer"], "operator_ct"
    )
    miss_state = data_manager.get_lookup_state(
        records[2]["serial_number"], records[2]["issuer"], "operator_ct"
    )
    assert error_state["consecutive_misses"] == 0
    assert error_state["next_retry_after"] is None
    assert miss_state["consecutive_misses"] == 1
    assert miss_state["next_retry_after"]


async def test_ct_error_does_not_block_crtsh_source(data_manager, sample_certs):
    record = {**sample_certs[0], "authority_key_identifier": "aabb"}
    data_manager.save_revoked_certs([record])
    data_manager.record_lookup_results(
        "operator_ct", [LookupRecordResult(record, LookupOutcome.TIMEOUT)]
    )
    pending = data_manager.get_pending_lookup_records("crtsh_postgres")
    assert [row["serial_number"] for row in pending] == [record["serial_number"]]


def test_release_gate_blocks_required_quality_failures(tmp_path, data_manager):
    manager = CompromisedKeysManager.__new__(CompromisedKeysManager)
    manager.data_manager = data_manager
    manager.exporter = SimpleNamespace()
    manager._verify_exports = lambda: True
    report = {
        "stages": {
            "crl": {
                "ccadb_records_total": 10,
                "ccadb_eligible_intermediates": 2,
                "crl_urls_found": 100,
                "crl_files_downloaded": 90,
            },
            "ct": {"status": "failed"},
            "crtsh": {"status": "degraded"},
        }
    }
    baseline = {"total_revoked": 0, "total_with_public_key": 0}
    current = {"total_revoked": 0, "total_with_public_key": 0}

    gate = manager._release_gate(report, baseline, current, {"success_rate": 0.99})

    assert gate["status"] == "blocked"
    assert "crl_success_rate_below_95_percent" in gate["blockers"]
    assert "crl_success_rate_drop_over_2_points" in gate["blockers"]
    assert "optional_source_ct_degraded" in gate["warnings"]


def test_release_gate_allows_optional_source_degradation(data_manager):
    manager = CompromisedKeysManager.__new__(CompromisedKeysManager)
    manager.data_manager = data_manager
    manager._verify_exports = lambda: True
    report = {
        "stages": {
            "crl": {
                "ccadb_records_total": 10,
                "ccadb_eligible_intermediates": 2,
                "crl_urls_found": 150,
                "crl_download_targets": 100,
                "crl_files_downloaded": 99,
            },
            "ct": {"status": "degraded"},
            "crtsh": {"status": "ok"},
        }
    }
    baseline = {"total_revoked": 0, "total_with_public_key": 0}
    gate = manager._release_gate(report, baseline, baseline, {"success_rate": 0.99})
    assert gate["status"] == "degraded"
    assert gate["blockers"] == []


def test_cli_parses_sync_full_history_and_exact_exclusion():
    sync = cli.parse_args(
        [
            "sync",
            "--crtsh-mode",
            "postgres",
            "--crtsh-limit",
            "100",
            "--report",
            "sync.json",
        ]
    )
    history = cli.parse_args(["ct-sync", "--full-history"])
    exclusion = cli.parse_args(
        [
            "exclude-record",
            "01",
            "CN=Issuer",
            "--reason-code",
            "manual",
            "--rationale",
            "reviewed",
            "--created-by",
            "operator@example.test",
        ]
    )
    assert sync.crtsh_limit == 100
    assert history.full_history is True
    assert exclusion.apply is False
    assert exclusion.issuer == "CN=Issuer"


def test_cli_exclusion_defaults_to_preview(monkeypatch, capsys, data_manager, sample_certs):
    data_manager.save_revoked_certs([sample_certs[0]])
    monkeypatch.setattr("compromised_keys.data_manager.DataManager", lambda: data_manager)
    args = SimpleNamespace(
        verbose=False,
        quiet=False,
        serial=sample_certs[0]["serial_number"],
        issuer=sample_certs[0]["issuer"],
        reason_code="manual",
        rationale="reviewed",
        created_by="operator@example.test",
        expires_at="",
        apply=False,
    )
    cli.cmd_exclude_record(args)
    output = json.loads(capsys.readouterr().out)
    assert output["record_exists"] is True
    assert output["apply"] is False
    assert data_manager.get_db_stats()["active_exclusions"] == 0
