# Release Process And Quality Gates

Historical SQLite data cannot be fully reconstructed from currently reachable
upstreams. It is therefore a versioned release asset, while source code remains in
Git.

## Hard Gates

A run is `blocked` when any of these checks fail:

- CCADB retrieval or scope validation failed, or the eligible scope is empty;
- fewer than 95% of selected CRLs are available;
- any downloaded CRL cannot be parsed or committed;
- CRL success rate dropped by more than 2 percentage points from the previous
  non-blocked run;
- SQLite `integrity_check` is not `ok`;
- active record or accepted-key count decreased without an explicit reviewed process;
- CSV or Bloom Filter digest differs from `metadata.json`.

CT or crt.sh errors produce `degraded`, not `blocked`, because they are optional
supplementation sources. Required-source failures remain blocking even if old cached
data exists.

## Build And Publish

1. Verify the persistent runner database; restore `data-latest` only when it is absent.
2. Run the complete synchronization and save `sync_report.json`.
3. Generate CRL health, missing-key, and database reports.
4. Run `prepare-release` with the sync report. It must match a completed run saved in
   the database and the export version. Database statistics and reproduced CSV/Bloom
   Filter contents must match the supplied exports; stale or mixed inputs are rejected.
5. Verify `SHA256SUMS`, `db-manifest.json`, export metadata, and a test restore.
6. Publish one immutable `data-vYYYY.MM.DD.HHMM` release.
7. Update `data-latest` only after the immutable release succeeds.

The automated implementation runs only on the dedicated `compromised-keys-sync`
self-hosted runner and the protected `data-production` Environment. Before the first
`data-latest` exists, a maintainer must perform the one-time reviewed bootstrap in
[Internal Runner And Initial Data Bootstrap](runner-and-bootstrap.md). Scheduled runs
never initialize an empty production database.

Every release contains the compressed database, CSV, Bloom Filter, metadata,
missing-key and database statistics, manifest, and checksums. Consumers should pin
immutable tags and verify all assets before use.

CRL failure reports and sync logs remain on the runner; they are not uploaded as
release assets or Actions artifacts. The public SQLite snapshot omits CRL failure
codes, counters, error messages and failure timestamps, while preserving downloaded
content and parsing checkpoints. Restoring this snapshot starts fresh CRL failure
counters; keep local reports for diagnostic history. The source database is unchanged.
Raw exception messages in historical audit JSON are also removed from public snapshots.
Unexpected tables or columns block release until their publication scope is reviewed.
