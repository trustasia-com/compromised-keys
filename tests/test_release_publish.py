import json
from pathlib import Path

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
    monkeypatch.setattr(release_publish.time, "sleep", lambda _: None)
    github.fail_upload = "before"
    with pytest.raises(ReleaseAssetError, match="4 attempts"):
        publish_bundle(bundle, TAG, REPO)
    assert github.releases[TAG]["draft"]
    assert "data-latest" not in github.releases
    assert (bundle / TAG / "assets" / "compromised_keys.db.zst").exists()

    github.fail_upload = "after"
    github.uploads.clear()
    publish_bundle(bundle, TAG, REPO)
    assert not github.releases[TAG]["draft"]
    assert not github.releases["data-latest"]["draft"]
    assert len(github.uploads) == 2 * (len(release_publish.ASSETS) + 1)
    assert github.uploads[-1] == ("data-latest", "SHA256SUMS")
    github.uploads.clear()
    publish_bundle(bundle, TAG, REPO)
    assert github.uploads == []


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
    from types import SimpleNamespace

    responses = iter(
        [
            SimpleNamespace(returncode=1, stderr="connection reset", stdout=""),
            SimpleNamespace(returncode=0, stderr="", stdout='{"draft": true}'),
        ]
    )
    monkeypatch.setattr(release_publish.subprocess, "run", lambda *a, **k: next(responses))
    monkeypatch.setattr(release_publish.time, "sleep", lambda _: None)
    assert GitHubPublisher(REPO).release(TAG) == {"draft": True}
