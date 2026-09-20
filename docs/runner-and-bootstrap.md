# Internal Runner And Initial Data Bootstrap

The daily data workflow is intentionally limited to a dedicated self-hosted runner.
It must never run untrusted pull-request code or share a runner with general CI.

## Repository configuration

1. Register a Linux self-hosted runner with both `self-hosted` and
   `compromised-keys-sync` labels. Isolate its OS account and wipe the Actions workspace
   between jobs. If the runner is ephemeral, mount controlled persistent storage for
   the operational database and reports.
   Runner names do not select jobs: an existing runner must also have the custom label.
   For an organization runner, its runner group must allow this repository and its
   public visibility. Keep access limited to trusted production workflows.
2. Create the `data-production` GitHub Environment. Restrict deployment branches to
   `main`. Required reviewers pause every run, including scheduled runs; enable them
   only if daily updates should wait for approval.
3. Configure Actions secret `CT_SERVER_HOST` at repository, organization, or Environment
   scope. An existing repository secret works without creating another copy; an organization
   secret must grant access to this repository. An Environment secret of the same name
   takes precedence. The workflow exposes it only to synchronization and stops if absent.
4. Add environment variable `INITIAL_DB_PATH`. It must be an absolute path to the
   reviewed historical SQLite database on runner-controlled storage, outside the
   Actions workspace. This path is used only for the first data release.
5. Allow Actions to create releases with `GITHUB_TOKEN`. Keep the default repository
   workflow permission read-only; the data job requests `contents: write` explicitly.

The runner needs outbound HTTPS for GitHub, CCADB, CT, and CRL endpoints, and outbound
TCP 5432 for crt.sh PostgreSQL. Preinstall GitHub CLI and Python 3.14 (including pip
and venv), available as `python3.14`. Provide at least 5 GiB of free temporary disk
and a reliable connection to `uploads.github.com:443` for publishing assets.

## First data release

The job also checks that the ref is `main` before dispatch to the private runner.
Dependencies use a per-job virtual environment. CRL cache lives outside checkout at
`$RUNNER_TOOL_CACHE/compromised-keys-crl-cache`; keep it service-account-only. An
ephemeral runner may lose this cache without losing database checkpoints. Public CRLs
may require outbound HTTP as well as HTTPS; prevent those requests from reaching
internal addresses with network-level controls too.

Private sync logs and CRL failure reports are stored under
`$RUNNER_TOOL_CACHE/compromised-keys-reports/<run-id>-<attempt>/`, outside checkout.
Restrict this directory to the runner account and apply your internal retention policy.
For ephemeral runners, retain it on controlled storage before removing the host.

Before dispatching, independently back up the database and verify:

```bash
sqlite3 /controlled/path/compromised_keys.db 'PRAGMA integrity_check;'
```

Set `INITIAL_DB_PATH` to that file and manually dispatch **Daily Data Sync** with
`bootstrap=true`. The job takes a consistent snapshot of the reviewed database, runs a complete update,
checks release gates, creates and restores a candidate snapshot, publishes one
immutable `data-v...` release, and only then creates `data-latest`.

Bootstrap is refused when `data-latest` or the runner database already exists. The
operational database lives at `$RUNNER_TOOL_CACHE/compromised-keys-state/compromised_keys.db`,
outside checkout and accessible only to the runner account. Every run verifies and
continues this database, preserving increments and failure counters even when a run
fails or publication is blocked. If it is absent, restore verified `data-latest`.
Never remove the operational database to retry a failed run; back it up independently.

## Operations and recovery

Verified bundles persist at `$RUNNER_TOOL_CACHE/compromised-keys-releases/<version>/`.
After upload failure, dispatch **Daily Data Sync** with `publish_tag` set to the version
in the failed job summary and `bootstrap=false`:

```bash
gh workflow run daily_sync.yml --ref main \
  -f publish_tag=data-v2026.09.20.1200 -f bootstrap=false
```

This mode verifies and publishes the saved bundle without reading the operational
database or repeating sync, export, or compression. **Re-run jobs** retains the original
inputs and will repeat sync if that was the original mode. Missing or corrupt bundles
fail immediately; only versions retained by this workflow support publication retries.
Keep this directory on persistent storage. Successful bundles receive a `published`
marker and can be removed under your retention policy; retain and back up unpublished bundles.

Each file gets up to four upload attempts, each capped at ten minutes. Remote digests
are checked before retrying, so a completed upload is reused even after a lost response.
Fixed versions stay in draft until all assets verify; published versions are never
overwritten. The rolling alias is updated last, with checksums uploaded last. Its update
is not atomic, so consumers must verify `SHA256SUMS`. Retrying an older version does not
replace a newer `data-latest`.

- The schedule `0 18 * * *` is 18:00 UTC, or 02:00 Asia/Shanghai on the following
  calendar day.
- The workflow does not use `pull_request_target` and the dedicated runner must not
  be assigned to public pull requests.
- If updating the rolling alias fails, retry with the same `publish_tag`; the published
  fixed version is verified and its uploads are skipped.
- Remove `INITIAL_DB_PATH` after the first successful release or leave it pointing to
  read-only controlled storage; the workflow cannot use it once `data-latest` exists.
- Rotate `CT_SERVER_HOST` at its configured secret scope without editing source.

See [Release Process And Quality Gates](release-process.md) for release-blocking
conditions.
