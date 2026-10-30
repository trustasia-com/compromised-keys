import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from compromised_keys import release_publish
from compromised_keys.release_assets import ReleaseAssetError, _write_checksums, sha256_file
from compromised_keys.release_publish import GitHubPublisher, publish_bundle, stage_release

TAG = "data-v2026.09.20.1200"
REPO = "example/keys"
COMMIT = "a" * 40


@pytest.fixture
def bundle(tmp_path):
    assets = tmp_path / "exports"
    assets.mkdir()
    for name in release_publish.ASSETS:
        (assets / name).write_text(json.dumps({"version": TAG, "name": name}))
    (assets / "db_stats.json").write_text(
        json.dumps(
            {
                "total_revoked": 1200,
                "total_with_public_key": 1000,
                "missing_public_key": 200,
                "unique_public_keys": 900,
                "cleaned": 0,
                "active_exclusions": 2,
            }
        )
    )
    (assets / "db-manifest.json").write_text(
        json.dumps(
            {
                "sync_status": {
                    "database_before": {
                        "total_revoked": 1100,
                        "total_with_public_key": 850,
                        "missing_public_key": 250,
                        "unique_public_keys": 800,
                        "cleaned": 0,
                        "active_exclusions": 2,
                    },
                    "release": {"status": "degraded"},
                    "stages": {
                        "ct": {"status": "ok", "updated": 130},
                        "crtsh": {"status": "degraded", "updated": 20, "error": "PRIVATE_URL"},
                    },
                }
            }
        )
    )
    _write_checksums(assets.iterdir(), assets / "SHA256SUMS")
    root = tmp_path / "retained"
    assert stage_release(assets, root, COMMIT, REPO) == TAG
    return root


class FakeGitHub(GitHubPublisher):
    def __init__(self, repository):
        super().__init__(repository)
        self.releases = {}
        self.uploads = []
        self.fail_upload = None

    def release(self, tag):
        return self.releases.get(tag)

    def _gh(self, *args, **kwargs):
        command, tag = args[1:3]
        if command == "create":
            self.releases[tag] = {
                "draft": True,
                "target_commitish": COMMIT,
                "assets": [],
                "body": args[args.index("--notes") + 1],
            }
        elif command == "upload":
            path = Path(args[3])
            self.uploads.append((tag, path.name))
            if self.fail_upload == "before":
                raise ReleaseAssetError("unexpected EOF")
            release = self.releases[tag]
            release["assets"] = [a for a in release["assets"] if a["name"] != path.name]
            release["assets"].append(
                {
                    "name": path.name,
                    "size": path.stat().st_size,
                    "state": "uploaded",
                    "digest": "sha256:" + sha256_file(path),
                }
            )
            if self.fail_upload == "after":
                self.fail_upload = None
                raise ReleaseAssetError("unexpected EOF after server stored bytes")
        elif command == "edit":
            self.releases[tag]["draft"] = False
            self.releases[tag]["body"] = args[args.index("--notes") + 1]
        elif command == "delete-asset":
            self.releases[tag]["assets"] = [
                asset for asset in self.releases[tag]["assets"] if asset["name"] != args[3]
            ]
        else:
            pytest.fail(f"Unexpected GitHub command: {args}")
        return ""


def test_resume_upload_after_network_failure(monkeypatch, bundle):
    github = FakeGitHub(REPO)
    monkeypatch.setattr(release_publish, "GitHubPublisher", lambda _repo: github)
    waits = []
    monkeypatch.setattr(release_publish.time, "sleep", waits.append)
    github.fail_upload = "before"
    with pytest.raises(ReleaseAssetError, match="6 attempts"):
        publish_bundle(bundle, TAG, REPO)
    assert len(github.uploads) == 6
    assert waits == [60, 120, 240, 300, 300]
    assert github.releases[TAG]["draft"]
    assert "data-latest" not in github.releases
    assert (bundle / TAG / "assets" / "compromised_keys.db.zst").exists()

    github.fail_upload = "after"
    github.uploads.clear()
    waits.clear()
    publish_bundle(bundle, TAG, REPO)
    assert waits == []
    assert not github.releases[TAG]["draft"]
    assert not github.releases["data-latest"]["draft"]
    notes = github.releases[TAG]["body"]
    assert notes == github.releases["data-latest"]["body"]
    assert "| 1,200 | +100 |" in notes
    assert "| 200 | -50 |" in notes
    assert "| 1,000 | +150 |" in notes
    assert "| CT | ok | 130 |" in notes
    assert "| crt.sh | degraded | 20 |" in notes
    assert "PRIVATE_URL" not in notes
    assert len(github.uploads) == 2 * (len(release_publish.ASSETS) + 1)
    assert github.uploads[-1] == ("data-latest", "SHA256SUMS")
    github.uploads.clear()
    publish_bundle(bundle, TAG, REPO)
    assert github.uploads == []
    assert github.releases[TAG]["body"] == notes


def test_old_bundle_notes_do_not_invent_changes(bundle):
    assets = bundle / TAG / "assets"
    (assets / "db-manifest.json").write_text("{}")
    notes = release_publish.release_notes(TAG, COMMIT, assets)
    assert "| 1,200 | N/A |" in notes
    assert "| CT | unknown | N/A |" in notes
    assert "previous published release" in notes


def test_existing_release_description_is_updated_without_uploads(monkeypatch, bundle):
    github = FakeGitHub(REPO)
    monkeypatch.setattr(release_publish, "GitHubPublisher", lambda _: github)
    publish_bundle(bundle, TAG, REPO)
    github.releases[TAG]["body"] = "Old description"
    github.uploads.clear()
    publish_bundle(bundle, TAG, REPO)
    assert github.uploads == []
    assert "| 1,200 | +100 |" in github.releases[TAG]["body"]


def test_refuse_to_overwrite_published_version(monkeypatch, bundle):
    github = FakeGitHub(REPO)
    monkeypatch.setattr(release_publish, "GitHubPublisher", lambda _repo: github)
    publish_bundle(bundle, TAG, REPO)
    github.releases[TAG]["assets"][0]["digest"] = "sha256:" + "0" * 64
    github.uploads.clear()
    with pytest.raises(ReleaseAssetError, match="Published version differs"):
        publish_bundle(bundle, TAG, REPO)
    assert github.uploads == []


def test_retry_old_version_does_not_roll_back_latest(monkeypatch, bundle):
    github = FakeGitHub(REPO)
    monkeypatch.setattr(release_publish, "GitHubPublisher", lambda _repo: github)
    github.releases["data-latest"] = {"body": "Rolling mirror of data-v2026.09.21.1200"}
    publish_bundle(bundle, TAG, REPO)
    assert all(tag == TAG for tag, _ in github.uploads)


def test_rolling_alias_replaces_raw_csv_with_compressed_asset(monkeypatch, bundle):
    github = FakeGitHub(REPO)
    monkeypatch.setattr(release_publish, "GitHubPublisher", lambda _repo: github)
    github.releases["data-latest"] = {
        "draft": False,
        "body": "data-v2026.09.19.1200",
        "target_commitish": COMMIT,
        "assets": [{"name": "compromised_keys.csv", "state": "uploaded"}],
    }
    publish_bundle(bundle, TAG, REPO)
    names = {asset["name"] for asset in github.releases["data-latest"]["assets"]}
    assert "compromised_keys.csv" not in names
    assert "compromised_keys.csv.gz" in names


def test_corrupt_bundle_never_contacts_github(monkeypatch, bundle):
    (bundle / TAG / "assets" / "compromised_keys.db.zst").write_bytes(b"corrupt")
    monkeypatch.setattr(
        release_publish, "GitHubPublisher", lambda _: pytest.fail("Contacted GitHub")
    )
    with pytest.raises(ReleaseAssetError, match="checksum mismatch"):
        publish_bundle(bundle, TAG, REPO)


def test_stage_preserves_existing_version(bundle, tmp_path):
    source = tmp_path / "exports"
    assert stage_release(source, bundle, COMMIT, REPO) == TAG
    with pytest.raises(ReleaseAssetError, match="different bundle"):
        stage_release(source, bundle, "b" * 40, REPO)


def test_release_network_failure_is_not_absence(monkeypatch):
    responses = iter(
        [
            SimpleNamespace(returncode=1, stderr="connection reset", stdout=""),
            SimpleNamespace(returncode=0, stderr="", stdout='{"draft": true}'),
        ]
    )
    monkeypatch.setattr(release_publish.subprocess, "run", lambda *a, **k: next(responses))
    monkeypatch.setattr(release_publish.time, "sleep", lambda _: None)
    assert GitHubPublisher(REPO).release(TAG) == {"draft": True}


@pytest.mark.parametrize(
    "failure", ["TLS handshake timeout", "HTTP 503", "HTTP 403: rate limit exceeded", "timeout"]
)
def test_request_retry_backoff_and_exhaustion(monkeypatch, failure):
    calls = []
    waits = []

    def run(*args, **kwargs):
        calls.append(args)
        if failure == "timeout":
            raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])
        return SimpleNamespace(returncode=1, stderr=failure, stdout="")

    monkeypatch.setattr(release_publish.subprocess, "run", run)
    monkeypatch.setattr(release_publish.time, "sleep", waits.append)
    with pytest.raises(ReleaseAssetError):
        GitHubPublisher(REPO).release(TAG)
    assert len(calls) == 6
    assert waits == [60, 120, 240, 300, 300]


def test_upload_permission_error_is_not_retried(monkeypatch, bundle):
    github = FakeGitHub(REPO)
    github.ensure_release(TAG, COMMIT, "test")
    monkeypatch.setattr(release_publish, "GitHubPublisher", lambda _: github)
    monkeypatch.setattr(
        release_publish.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(returncode=1, stderr="HTTP 403: forbidden", stdout=""),
    )
    monkeypatch.setattr(github, "_gh", GitHubPublisher._gh.__get__(github))
    monkeypatch.setattr(
        release_publish.time, "sleep", lambda _: pytest.fail("Retried permission error")
    )
    with pytest.raises(release_publish.PermanentGitHubError, match="403"):
        publish_bundle(bundle, TAG, REPO)


def test_retry_settings_are_configurable(monkeypatch):
    monkeypatch.setenv("RELEASE_REQUEST_ATTEMPTS", "2")
    monkeypatch.setenv("RELEASE_RETRY_DELAY_SECONDS", "90")
    waits = []
    monkeypatch.setattr(release_publish.time, "sleep", waits.append)
    monkeypatch.setattr(
        release_publish.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(returncode=1, stderr="connection reset", stdout=""),
    )
    with pytest.raises(ReleaseAssetError):
        GitHubPublisher(REPO).release(TAG)
    assert waits == [90]
    monkeypatch.setenv("RELEASE_RETRY_DELAY_SECONDS", "0")
    with pytest.raises(ReleaseAssetError, match="positive integer"):
        GitHubPublisher(REPO)
