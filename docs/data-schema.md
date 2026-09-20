# Published Data Schema

## CSV

`compromised_keys.csv` contains one row per accepted certificate record with a public
key. Releases distribute it as `compromised_keys.csv.gz`; local exports remain uncompressed.
Important fields are:

| Field | Encoding and meaning |
|:--|:--|
| `serial_number` | Certificate serial as lowercase hexadecimal. |
| `issuer` | Issuer distinguished name retained from the revocation record. |
| `revocation_date` | Upstream CRL revocation timestamp. |
| `key_hash` | Project fingerprint used by exact and Bloom Filter lookup. |
| `public_key` | DER SubjectPublicKeyInfo encoded as hexadecimal. |
| `cert_sha256` | SHA-256 of the accepted DER certificate when available. |
| `key_algorithm`, `key_size` | Parsed public-key metadata. |
| `validated_type` | `DV`, `OV`, `IV`, `EV`, or empty, derived from policy OIDs. |
| `is_precert` | `1` only for a critical CT Precertificate Poison extension. |
| `notbefore`, `notafter` | Parsed certificate validity timestamps. |
| `public_key_source` | Source that supplied the accepted key. |
| `public_key_obtained_at` | UTC acceptance timestamp. |
| `crt_sh_url` | Convenience serial search URL; not a unique record identifier. |

## Fingerprints

- RSA: SHA-256 of unsigned modulus bytes after removing leading zero bytes.
- EC: SHA-256 of unsigned public-point X-coordinate bytes.

The Bloom Filter stores `key_hash` values with a target false-positive rate of 0.1%.
A hit must be confirmed against the CSV or SQLite database from the same release.

## Release Metadata

`metadata.json` declares schema version `3.0`, release version, timestamp, key count,
filenames, and SHA-256 digests. `db-manifest.json` adds uncompressed/compressed database
digests, sizes, schema columns, table counts, SQLite integrity result, and sync report.
`SHA256SUMS` covers every distributed release asset.
For published CSV, `files.csv` describes the gzip asset; `files.csv.uncompressed`
describes the original CSV, including its filename, digest, and size.
