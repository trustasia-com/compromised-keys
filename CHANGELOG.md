# Changelog

Source releases use `vX.Y.Z`; data releases use `data-vYYYY.MM.DD.HHMM`.

## Unreleased

- Collect key-compromise revocations from CRLs disclosed by TLS-capable CCADB intermediates.
- Supplement public keys through an optional CT provider and public crt.sh.
- Store hexadecimal identities, certificate metadata, source-specific retries, and audit reports.
- Export CSV and Bloom Filter data with checksums and verified SQLite snapshots.
- Provide a CLI, Docker deployment, GitHub Actions, and English and Chinese documentation.
- Publish source code under MIT and data under the terms in DATA_NOTICE.md.
- Validate certificate identity, preserve incremental history, and verify release assets against the database.
- Keep operational failure diagnostics private and refuse to overwrite existing history during restoration.
