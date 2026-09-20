"""Persist verified release bundles and resume GitHub uploads file by file."""

import argparse
import json
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from compromised_keys.release_assets import (
    CHECKSUMS_FILENAME,
    DATABASE_FILENAME,
    MANIFEST_FILENAME,
    ReleaseAssetError,
    _read_checksums,
    sha256_file,
)

ASSETS = {
    DATABASE_FILENAME,
    MANIFEST_FILENAME,
    "compromised_keys.csv.gz",
    "compromised_keys.bf",
    "metadata.json",
    "misses_report.json",
    "db_stats.json",
}


def validate_tag(tag: str) -> str:
    if not re.fullmatch(r"data-v\d{4}\.\d{2}\.\d{2}\.\d{4}", tag):
        raise ReleaseAssetError("Invalid data release tag")
    return tag


def verify_assets(directory: Path) -> dict:
    checksums = _read_checksums(directory / CHECKSUMS_FILENAME)
    if set(checksums) != ASSETS or {p.name for p in directory.iterdir()} != ASSETS | {
        CHECKSUMS_FILENAME
    }:
        raise ReleaseAssetError("Unexpected or missing publication assets")
    if (directory / CHECKSUMS_FILENAME).is_symlink():
        raise ReleaseAssetError("Publication checksums must not be a symlink")
    for name, expected in checksums.items():
        path = directory / name
        if path.is_symlink() or not path.is_file() or sha256_file(path) != expected:
            raise ReleaseAssetError(f"Publication checksum mismatch: {name}")
    checksums[CHECKSUMS_FILENAME] = sha256_file(directory / CHECKSUMS_FILENAME)
    return checksums


def stage_release(assets: Path, root: Path, commit: str, repository: str) -> str:
    checksums = verify_assets(assets)
    tag = validate_tag(json.loads((assets / "metadata.json").read_text())["version"])
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ReleaseAssetError("Publication requires a full source commit SHA")
    publication = {"tag": tag, "commit": commit, "repository": repository, "checksums": checksums}
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination = root / tag
    if destination.exists():
        if json.loads((destination / "publication.json").read_text()) != publication:
            raise ReleaseAssetError("A different bundle already exists for this version")
        verify_assets(destination / "assets")
        return tag
    temporary = Path(tempfile.mkdtemp(prefix=".staging-", dir=root))
    try:
        shutil.copytree(assets, temporary / "assets")
        verify_assets(temporary / "assets")
        (temporary / "publication.json").write_text(json.dumps(publication, indent=2) + "\n")
        temporary.rename(destination)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
    return tag


class GitHubPublisher:
    def __init__(self, repository: str):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
            raise ReleaseAssetError("Invalid GitHub repository")
        self.repository = repository

    def _gh(self, *args, missing_ok=False, attempts=4, timeout=120):
        for attempt in range(attempts):
            try:
                result = subprocess.run(
                    ["gh", *args], capture_output=True, text=True, timeout=timeout, check=False
                )
                if result.returncode == 0:
                    return result.stdout
                if missing_ok and "(HTTP 404)" in result.stderr:
                    return None
                error = result.stderr.strip()
                if re.search(r"HTTP (400|401|403|404|422)\b", error):
                    raise ReleaseAssetError(error)
            except subprocess.TimeoutExpired:
                error = "GitHub command timed out"
            if attempt + 1 < attempts:
                print(f"GitHub request failed; retry {attempt + 2}/{attempts}", flush=True)
                time.sleep(min(5 * 2**attempt, 30))
        raise ReleaseAssetError(error)

    def release(self, tag):
        result = self._gh("api", f"repos/{self.repository}/releases/tags/{tag}", missing_ok=True)
        if result is not None:
            return json.loads(result)
        # The tag endpoint may omit drafts. Authenticated listing includes them.
        pages = json.loads(
            self._gh(
                "api", f"repos/{self.repository}/releases?per_page=100", "--paginate", "--slurp"
            )
        )
        return next(
            (release for page in pages for release in page if release["tag_name"] == tag), None
        )

    def ensure_release(self, tag, commit, notes):
        # Re-read after an uncertain create response instead of creating a second release.
        for attempt in range(4):
            existing = self.release(tag)
            if existing is not None:
                if tag != "data-latest" and existing["target_commitish"] != commit:
                    raise ReleaseAssetError("Existing release has a different source commit")
                return existing
            try:
                self._gh(
                    "release",
                    "create",
                    tag,
                    "--repo",
                    self.repository,
                    "--draft",
                    "--target",
                    commit,
                    "--latest=false",
                    "--title",
                    tag,
                    "--notes",
                    notes,
                    attempts=1,
                )
            except ReleaseAssetError:
                if attempt == 3:
                    raise
                time.sleep(5 * (attempt + 1))
        existing = self.release(tag)
        if existing is None:
            raise ReleaseAssetError("Release creation could not be confirmed")
        return existing

    def matches(self, tag, asset, path, digest):
        if asset.get("state") != "uploaded" or asset.get("size") != path.stat().st_size:
            return False
        if asset.get("digest"):
            return asset["digest"] == f"sha256:{digest}"
        # Older GitHub assets may lack a digest: compare downloaded bytes, not just size.
        with tempfile.TemporaryDirectory(prefix="verify-github-asset-") as directory:
            self._gh(
                "release",
                "download",
                tag,
                "--repo",
                self.repository,
                "--pattern",
                path.name,
                "--dir",
                directory,
                "--clobber",
                timeout=600,
            )
            return sha256_file(Path(directory) / path.name) == digest

    def publish(self, tag, commit, assets, checksums, notes):
        release = self.ensure_release(tag, commit, notes)
        mutable = tag == "data-latest" or release["draft"]
        expected = set(checksums)
        remote_names = {a["name"] for a in release["assets"]}
        obsolete = remote_names - expected
        if obsolete and not (tag == "data-latest" and obsolete == {"compromised_keys.csv"}):
            raise ReleaseAssetError(f"Unexpected assets in {tag}; manual review required")
        # Publish checksums last so rolling-alias readers can detect mixed versions.
        for name in sorted(expected, key=lambda name: (name == CHECKSUMS_FILENAME, name)):
            path = assets / name
            for attempt in range(5):
                release = self.release(tag)
                if release is None:
                    raise ReleaseAssetError("Release disappeared during upload")
                remote = next((a for a in release["assets"] if a["name"] == name), None)
                if remote and self.matches(tag, remote, path, checksums[name]):
                    print(f"Verified {tag}/{name}", flush=True)
                    break
                if not mutable or (tag != "data-latest" and not release["draft"]):
                    raise ReleaseAssetError(f"Published version differs: {tag}/{name}")
                if attempt == 4:
                    raise ReleaseAssetError(f"Upload failed after 4 attempts: {tag}/{name}")
                print(f"Uploading {tag}/{name}, attempt {attempt + 1}/4", flush=True)
                try:
                    self._gh(
                        "release",
                        "upload",
                        tag,
                        str(path),
                        "--repo",
                        self.repository,
                        "--clobber",
                        attempts=1,
                        timeout=600,
                    )
                except ReleaseAssetError:
                    # An EOF can arrive after GitHub has stored the asset. Verify before retrying.
                    time.sleep(min(5 * 2**attempt, 30))
        for name in obsolete:
            self._gh("release", "delete-asset", tag, name, "--repo", self.repository, "--yes")
        release = self.release(tag)
        if release is None or {a["name"] for a in release["assets"]} != expected:
            raise ReleaseAssetError("Remote asset set changed during publication")
        for asset in release["assets"]:
            if not self.matches(tag, asset, assets / asset["name"], checksums[asset["name"]]):
                raise ReleaseAssetError("Remote checksum verification failed")
        if release["draft"] or tag == "data-latest":
            self._gh(
                "release",
                "edit",
                tag,
                "--repo",
                self.repository,
                "--draft=false",
                "--latest=false",
                "--notes",
                notes,
            )


def publish_bundle(root: Path, tag: str, repository: str):
    bundle = root / validate_tag(tag)
    publication = json.loads((bundle / "publication.json").read_text())
    checksums = verify_assets(bundle / "assets")
    if (
        publication["tag"] != tag
        or publication["repository"] != repository
        or publication["checksums"] != checksums
    ):
        raise ReleaseAssetError("Publication bundle does not match its recorded identity")
    commit = publication["commit"]
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ReleaseAssetError("Invalid publication source commit")
    notes = (
        f"Compromised Keys Data {tag}\n\nSource commit: {commit}\nVerify assets with SHA256SUMS."
    )
    publisher = GitHubPublisher(repository)
    publisher.publish(tag, commit, bundle / "assets", checksums, notes)
    latest = publisher.release("data-latest")
    latest_version = re.search(
        r"\bdata-v\d{4}\.\d{2}\.\d{2}\.\d{4}\b", (latest or {}).get("body") or ""
    )
    if latest_version and latest_version[0] > tag:
        print("A newer data-latest is already published; leaving it unchanged.", flush=True)
    else:
        publisher.publish("data-latest", commit, bundle / "assets", checksums, notes)
    (bundle / "published").touch()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["stage", "publish"])
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--assets", type=Path)
    parser.add_argument("--commit")
    parser.add_argument("--tag")
    args = parser.parse_args()
    if args.mode == "stage":
        if args.assets is None or args.commit is None:
            parser.error("stage requires --assets and --commit")
        print(stage_release(args.assets, args.root, args.commit, args.repo))
    else:
        if args.tag is None:
            parser.error("publish requires --tag")
        publish_bundle(args.root, args.tag, args.repo)


if __name__ == "__main__":
    main()
