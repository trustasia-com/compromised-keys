# Compromised Keys

[![CI](https://github.com/trustasia-com/compromised-keys/actions/workflows/ci.yml/badge.svg)](https://github.com/trustasia-com/compromised-keys/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/code-MIT-blue.svg)](LICENSE)
[![Data: CDLA Permissive 2.0](https://img.shields.io/badge/data-CDLA--Permissive--2.0-green.svg)](DATA_NOTICE.md)

[中文说明](README.zh-CN.md)

`compromised-keys` is a WebPKI data toolchain that collects certificates revoked
with `reasonCode: keyCompromise`, recovers their public keys from public certificate
sources, and exports data for pre-issuance risk checks and security analysis.

The repository contains source code, tests, and release automation. Historical data
is distributed separately through [GitHub Releases](https://github.com/trustasia-com/compromised-keys/releases).

## Security model

This dataset is a risk signal, not proof that a key is safe or compromised:

- A Bloom Filter miss means only that the fingerprint is absent from that release.
- A Bloom Filter hit can be a false positive and must be confirmed against the CSV or database.
- Source publication delays, inaccessible CRLs, missing certificates, and parsing limits can cause gaps.
- CRL signatures and full certificate chains are not verified; DER identity checks do not authenticate sources.
- Production users should record the release tag and SHA256 and retain independent controls.

See [SECURITY.md](SECURITY.md) before using the data in a blocking control.

## Pipeline

```text
CCADB REST API (TLS-capable intermediate certificates)
  -> CA CRLs
  -> reasonCode=keyCompromise records and CRL-derived AKI
  -> SQLite history database
  -> optional operator-configured CT Provider
  -> public crt.sh PostgreSQL supplementation
  -> CSV + Bloom Filter + metadata + verified database snapshot
  -> GitHub Releases
```

AKI values are stored as lowercase hexadecimal. Daily processing uses AKI values
from CRLs, including propagation only when one normalized issuer has exactly one
direct CRL AKI. The CCADB scope selects CRLs from TLS-capable intermediate
certificates only; changes to that scope do not delete historical records.

Lookup state is isolated by source. HTTP errors, timeouts, malformed responses,
missing DER, and provider outages never count as a valid miss and never suppress a
different source. See [Sources and retries](docs/sources-and-retries.md).

## Install

Python 3.10 or later is required; Python 3.14 is recommended. Python 3.9 is excluded
because current security-fixed HTTP dependencies no longer support it.

```bash
git clone https://github.com/trustasia-com/compromised-keys.git
cd compromised-keys
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install ".[postgres,release]"
compromised-keys doctor
```

`doctor` performs local preflight checks and does not contact CCADB, crt.sh, or a CT
Provider. A missing history database is reported as a warning rather than an
installation failure.

For development:

```bash
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e ".[dev,postgres,release]"
pre-commit install
```

## Choose the initial database

For a local evaluation, start with the empty database reported by `doctor`. The first
sync creates SQLite tables and collects only records still visible from current
upstream sources. To verify CRL collection without installing the PostgreSQL extra:

```bash
compromised-keys doctor --no-crtsh
compromised-keys crl-sync
```

The production database is historical and cannot be fully reconstructed from current
CRLs. Once the project has published its initial `data-latest` release, restore it
before a production or continuity sync:

```bash
gh release download data-latest --dir data-release
compromised-keys restore-release \
  --asset-dir data-release \
  --output compromised_keys.db
compromised-keys doctor
```

Restoration requires a new output path and refuses to overwrite an existing database.
If you already have a working database, keep it and run `sync` to update it.

If GitHub CLI reports `release not found`, the reviewed initial seed is not public
yet. Continue only with the empty-database evaluation; do not treat it as the complete
dataset or use it to create a production release.

## Run a complete sync

```bash
compromised-keys sync --report reports/sync_report.json
```

The command retrieves all CCADB certificate records through the paginated REST API,
validates the TLS-capable intermediate certificate scope, collects matching CRLs,
propagates CRL AKIs, runs the optional CT Provider and public crt.sh supplementation,
and performs a final export. CCADB scope changes do not delete historical records.
The first CRL pass can contain tens of thousands of URLs and take substantial time.
Normal logs report progress every 1,000 URLs; individual downloads and intermediate
retries are visible with `--verbose`. Some unreachable CRLs are expected and are
summarized at the end and by `crl-health`.

Useful phase commands:

| Command | Purpose |
|:--|:--|
| `crl-sync` | Select TLS-capable intermediate CRLs from CCADB, download them, and parse key-compromise revocations. |
| `supplement --mode postgres` | Recover missing certificates from the public crt.sh PostgreSQL service. |
| `ct-sync` | Query an optional compatible CT Provider. |
| `export` | Regenerate CSV, Bloom Filter, and metadata from SQLite. |
| `prepare-release` | Create a verified and checksummed data-release directory. |
| `restore-release` | Verify release checksums and atomically restore its SQLite database. |
| `check <csr>` | Pre-screen one or more PEM CSRs against the local Bloom Filter. |
| `validate-cert <cert>` | Validate a public certificate against an existing revoked record. |
| `doctor` | Check the local database, output directories, and optional sync dependencies. |
| `stats` | Print database statistics as JSON. |
| `analyze-misses` | Report revoked records that still lack public keys. |
| `crl-health` | Report CRL download failures. |
| `exclude-record` | Preview or apply an audited exclusion for one exact serial+issuer. |
| `clear-exclusion` | Preview or clear one exact record exclusion. |

Run `compromised-keys <command> --help` for all options.

## Optional CT Provider

Set a compatible provider endpoint only when one is available:

```bash
CT_SERVER_HOST=https://ct.example.com compromised-keys ct-sync
```

Requests contain Base64 encodings of the binary AKI and certificate serial number.
The client groups records by AKI, sorts by UTC revocation date, limits batches to
1,000 serials, and defaults to five concurrent requests. Certificate-validity windows are
derived from each batch's revocation dates and the TLS BR validity limits.
An explicit historical pass uses:

```bash
CT_SERVER_HOST=https://ct.example.com compromised-keys ct-sync --full-history
```

This ignores retry times and retries narrow-window misses with lower bounds of
`2010-01-01`, `not_before_to` through today, and `not_after_to` through one calendar
year from today. See [CT query windows](docs/sources-and-retries.md#ct-query-windows)
for the bounds and historical exceptions.
Returned DER certificates are parsed locally and checked against the requested
identity before any public key is accepted. New DER-backed public-key updates derive
`validated_type` from CA/B Forum policy OIDs and set `is_precert` only for a critical
CT Precertificate Poison extension.

The operator endpoint is never embedded in a data release. Release reports identify
this source as `operator_ct`.

## Configuration

Keep both the database and cache between runs. Required-stage failures and blocked
release gates make `sync` exit with code 1; `--report` retains CRL/export failure
details. Optional-source degradation does not suppress other sources. See
[operations](docs/operations.md) for recovery and resource tuning.

| Variable | Default | Description |
|:--|:--|:--|
| `COMPROMISED_KEYS_DB` | `compromised_keys.db` | SQLite history database. |
| `COMPROMISED_KEYS_DATA_DIR` | `data/latest` | CSV, Bloom Filter, and report directory. |
| `COMPROMISED_KEYS_CACHE_DIR` | `cache` | CCADB and CRL cache. |
| `CCADB_API_URL` | CCADB production REST API | AllCertificateRecords API endpoint. |
| `CCADB_API_START_DECADE` | `1990` | First `ValidFrom` decade to retrieve. |
| `CCADB_API_END_DECADE` | `2100` | Last `ValidFrom` decade to retrieve. |
| `CCADB_CACHE_TTL_HOURS` | `24` | Reuse the normalized local API snapshot for this many hours. |
| `CRTSH_PG_DSN` | `postgresql://guest@crt.sh:5432/certwatch` | Public read-only crt.sh database. |
| `CRTSH_MODE` | `postgres` | `postgres` or rate-limited `http`. |
| `CT_SERVER_HOST` | empty | Optional compatible CT Provider base or `/search` URL. |
| `CT_BATCH_SIZE` | `1000` | CT serials per request, capped at 1,000. |
| `CT_CONCURRENCY` | `5` | Maximum concurrent CT requests. |
| `CRL_DOWNLOAD_CONCURRENCY` | `50` | Maximum concurrent CRL download workers. |
| `CRL_PARSE_WORKERS` | CPU count capped at `4` | CRL parsing processes. |
| `CRL_MAX_BYTES` | `134217728` | Maximum CRL response size, 128 MiB. |

## Data releases

Each immutable `data-vYYYY.MM.DD.HHMM` release and the rolling `data-latest` alias contain:

- `compromised_keys.db.zst`
- `compromised_keys.csv`
- `compromised_keys.bf`
- `metadata.json`
- `db-manifest.json`
- `SHA256SUMS`
- CRL health, missing-record, and database statistics reports

Restore a downloaded release with built-in checksum and SQLite integrity validation:

```bash
gh release download data-latest --dir data-release
compromised-keys restore-release \
  --asset-dir data-release \
  --output compromised_keys.db
```

Use immutable version tags in production. The rolling alias may be changing while it
is downloaded; retry if verification detects an inconsistent asset set.

## Documentation

- [Architecture](docs/architecture.md)
- [Data model](docs/data-model.md) and [published schema](docs/data-schema.md)
- [Source outcomes and retry policy](docs/sources-and-retries.md)
- [Operations](docs/operations.md)
- [Internal runner and initial data bootstrap](docs/runner-and-bootstrap.md)
- [Release gates](docs/release-process.md)
- [Chinese documentation index](docs/zh-CN/README.md)

## Docker

The image has a `compromised-keys` entrypoint. Its Python base is pinned by digest and
the runtime runs as an unprivileged user without Linux capabilities. The Compose
service performs one sync and exits; it does not restart an empty database forever.

```bash
docker compose build
docker compose run --rm compromised-keys doctor --no-crtsh
docker compose up
```

The commands above are an empty-database evaluation. For a continuity sync, download
`data-latest` on the host and restore it into the named volume first:

```bash
gh release download data-latest --dir data-release
docker compose run --rm \
  -v "$PWD/data-release:/release:ro" \
  compromised-keys restore-release \
  --asset-dir /release --output /data/compromised_keys.db
docker compose run --rm compromised-keys doctor
docker compose up
```

The container persists `/data/compromised_keys.db`, `/data/latest`, and `/cache` in
named volumes. Use `docker compose run --rm compromised-keys sync --loop` only after
the initial database has been selected deliberately.

## Fingerprints

- RSA: `SHA256` of the unsigned modulus bytes with leading zero bytes removed.
- EC: `SHA256` of the unsigned public-point X coordinate bytes.

The CSV is the exact lookup source. The serialized `pybloom_live` Bloom Filter uses a
target false-positive rate of 0.1%.

`check` examines all CSR inputs: exit 0 means all were unlisted, 1 means an input
could not be checked, and 2 means at least one possible match (taking precedence over
1). Confirm possible matches against same-version exact data; unlisted is not safe.

## Contributing and reporting

See [CONTRIBUTING.md](CONTRIBUTING.md) for development and certificate-submission
rules. Report vulnerabilities through GitHub Private Vulnerability Reporting or
email `support@trustasia.com`; do not open a public vulnerability issue.

## License and data terms

Source code is licensed under the [MIT License](LICENSE). Data releases have separate
source and rights terms in [DATA_NOTICE.md](DATA_NOTICE.md). No warranty of coverage,
correctness, fitness, or non-infringement is provided.
