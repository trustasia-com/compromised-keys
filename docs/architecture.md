# Architecture

## Purpose

The project builds a historical risk-key dataset from WebPKI certificates revoked
with `reasonCode=keyCompromise`. It publishes public-key fingerprints and supporting
certificate metadata, never private keys. A dataset miss is not proof of key safety.

## Pipeline

1. Download all CCADB certificate records through the REST API.
2. Select records where `CertificateRecordType=IntermediateCertificate` and
   `TLS Capable=True`.
3. Download their CRLs and retain key-compromise revocations.
4. Store CRL AKI as lowercase hexadecimal and propagate it only when one normalized
   issuer has exactly one directly observed CRL AKI.
5. Query an optional operator CT service by binary AKI and serial encoded as Base64.
6. Query public crt.sh through PostgreSQL or the HTTP fallback.
7. Parse returned DER locally, validate identity, and derive key and certificate facts.
8. Export CSV, Bloom Filter, metadata, and a verified SQLite snapshot.

CCADB scope controls new CRL collection. A scope change never deletes historical
records. Routine lookups use CRL-derived AKI.

Under [CCADB Policy section 6.2](https://www.ccadb.org/policy), every URL in one
`JSON Array of all Full CRL URLs` entry must serve an identical CRL. The downloader
therefore treats those URLs as ordered alternatives and stops after the first
successful retrieval. Every Partitioned CRL URL remains an independent required
download. Reports count disclosed endpoints in `crl_urls_found`, logical required
CRLs in `crl_download_targets`, and calculate CRL success rates from the latter.

## Trust Boundaries

- **Required:** CCADB, in-scope CRLs, SQLite integrity, and export integrity. Failure
  blocks a data release.
- **Optional:** operator CT and crt.sh. Failure marks a run degraded but does not
  suppress other sources or block an otherwise valid release.
- **Operator-private:** `CT_SERVER_HOST`, credentials, raw logs, caches, and local
  backups. They are not release assets.
- **Published:** source code and documentation in Git; accumulated SQLite history and
  generated exports in checksummed GitHub Releases.

## Modules

The standard `src/compromised_keys/` package layout is intentional: tests and installed
CLI commands import the same package rather than accidentally importing the repository
root. Runtime data stays outside `src`; tests exercise temporary databases only.

CRL responses are structurally validated before mirror success. URL groups are only
deduplicated as equivalent groups; partial overlap cannot discard extra mirrors or
partitioned targets. Downloads share same-URL tasks, source registration uses a batch
transaction.
See [operations](operations.md) for transactional parsing checkpoints and batch recovery.

| Module | Responsibility |
|:--|:--|
| `downloader.py`, `parser.py` | CCADB and CRL acquisition, scope validation, parsing. |
| `data_manager.py` | Database initialization, facts, source state, exclusions, run audit. |
| `lookup.py` | Shared outcomes and source circuit breaker. |
| `ct_client.py` | Optional operator CT request and DER validation. |
| `crt_sh_crawler.py` | Public PostgreSQL and HTTP supplementation. |
| `crypto_utils.py` | Certificate parsing, key fingerprints, policy and precert metadata. |
| `exporter.py`, `release_assets.py` | Exports, snapshots, checksums, restore validation. |
| `main.py`, `cli.py` | Pipeline orchestration and operator commands. |
| `atomic_io.py`, `public_http.py` | Atomic generated files and public-CRL network boundaries. |
