# Operations

## Environment

Use Python 3.10 or later and install `.[postgres,release]`. Keep the database, cache,
exports, logs, and backups on persistent storage. Do not commit runtime artifacts.

The public pipeline does not require an operator CT source. Configure
`CT_SERVER_HOST` only in the runtime secret store. Never put an internal hostname in
source, documentation, reports, or release notes.

## Preflight And Initial State

Run the local preflight before every new installation:

```bash
compromised-keys doctor
```

A failure stops the command with exit code 1. A missing database is only a warning:
an empty database is sufficient for evaluation, but it cannot reproduce historical
records. Restore `data-latest` with `restore-release` before production continuity
syncs. If `data-latest` has not been published, production continuity sync is not yet
available. Use `doctor --no-crtsh` when the planned run also uses `sync --no-crtsh`.

## Routine Sync

```bash
compromised-keys sync \
  --crtsh-mode postgres \
  --crtsh-limit 5000 \
  --report reports/sync_report.json
```

Review `release.status`, `release.blockers`, source outcomes, circuit reasons, CRL
success rate, key counts, and `missing_der` counts. `ready` and `degraded` may be
released; `blocked` must not be released.

The initial CRL stage may process tens of thousands of URLs. INFO logs show progress
every 1,000 completions. Use `--verbose` only for per-URL troubleshooting because it
also includes individual successful downloads and intermediate retries.

## Incremental Updates And Recovery

Full CRL mirrors are attempted in order until one returns a parseable CRL. HTTP 200
error pages do not count as success. Overlapping groups share downloads within a run;
partitioned CRLs remain independent. At most twice `CRL_PARSE_WORKERS` parsing tasks
are in flight, and the download worker pool is bounded.

`crl_status.parsed_hash` commits in the same SQLite transaction as revocation rows.
Unchanged cache files are skipped only after this checkpoint exists. Download, parsing,
or database failures cannot permanently suppress parsing on the next run.

PostgreSQL results commit after each query batch; operator CT results commit after
each manager batch. Restart the same command after an interruption. Source circuits
stop additional submissions in the current pass without permanently skipping records.
CLI writers use a per-database process lock; do not remove its file while running.
Different databases must not share writable cache or export directories.

Exports use same-directory temporary files and atomic replacement, with metadata
written last. Empty exports replace stale data with a header-only CSV and readable
empty Bloom Filter. This is not an atomic transaction across files: consumers must
verify checksums from one version before use.

### Tuning And Measurement

Defaults: `CRL_DOWNLOAD_CONCURRENCY=50`, at most 10 connections per host,
`CRL_PARSE_WORKERS=min(4, CPU count)`, `CRL_MAX_BYTES=134217728` (128 MiB per response).
Lower concurrency and parser workers on memory-constrained hosts. Oversized CRLs fail
explicitly. Do not raise public crt.sh traffic simply to improve throughput.

Each stage reports `duration_seconds`. Compare `crl_parse_targets`,
`crl_unchanged_skipped`, `crl_parse_errors`, and public-key `updated` counts.
`total_revoked_found` counts observations in processed CRLs, not new database rows.
CT `selected`, `submitted`, and `deferred` distinguish selection from completed work.

`sync` exits 0 for `ready`/`degraded` and 1 for a blocked or failed run. CRL parsing
errors block release. `--report` also retains required CRL/export-stage failures.
Completed batches survive a later failure; a killed process may lack a final report.
Never publish stale exports after a failed run.

## Historical CT Pass

```bash
CT_SERVER_HOST=https://ct.example.com compromised-keys ct-sync --full-history
```

This ignores source retry times for missing-key records. Queries start with
[revocation-based windows](sources-and-retries.md#ct-query-windows); only successful
misses are retried with both lower bounds as `2010-01-01`, `not_before_to` through
today, and `not_after_to` through one calendar year from today. Routine sync uses
the narrow window without the broad retry.

## Diagnostics

```bash
compromised-keys stats
compromised-keys analyze-misses
compromised-keys crl-health --out reports/crl_failures.json
```

`analyze-misses` groups source outcomes and separately reports `missing_der`. Preserve
the JSON report with the run report when investigating provider behavior.
CRL failure details stay in the local `reports/` directory and are not release assets.

## Exact Exclusions

Issuer substring exclusions are intentionally unsupported. Preview is the default:

```bash
compromised-keys exclude-record SERIAL 'CN=Exact Issuer' \
  --reason-code manual_review \
  --rationale 'Documented investigation result' \
  --created-by operator@example.com
```

Repeat with `--apply` after review. Clear one exact exclusion with
`clear-exclusion SERIAL 'CN=Exact Issuer'`, also using `--apply` only after preview.

## Backups

Keep an independent backup of the historical database. Use SQLite's online backup API
or stop writers before copying it. Verify backups with `PRAGMA integrity_check` and
compare record and key counts before replacing production data.
