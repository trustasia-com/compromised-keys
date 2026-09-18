# Data Model

The SQLite database uses schema version 3 and separates certificate facts from
provider-specific query state.

| Table | Purpose |
|:--|:--|
| `revoked_certs` | Serial and issuer identity, revocation date, AKI provenance, public key and certificate metadata. |
| `lookup_state` | Outcome, miss/error counters and next retry for each `(serial_number, issuer, source)`. |
| `record_exclusions` | Exact operator exclusions with reason, actor, timestamps and optional expiry. |
| `crl_status` | CCADB source attribution, download health and parsing checkpoint. |
| `sync_runs`, `source_runs` | Complete-run and per-source statistics and status. |

Serial and AKI are lowercase hexadecimal. CT requests convert these values to bytes
and then Base64; the stored values remain hexadecimal.
Certificate identities cannot be null or empty. Validation type and precertificate
flags are constrained to their documented values; unknown values remain null.

`crl_status.last_hash` identifies downloaded content. `parsed_hash` commits in the
same transaction as the corresponding revocation rows.
The pending-record index contains only active records with a missing public key or
key hash; it does not duplicate public-key material.

## Record Metadata

- `validated_type`: `DV`, `OV`, `IV`, `EV`, or null, derived from certificate policy OIDs.
- `is_precert=1`: the certificate contains the critical CT Precertificate Poison extension.
- `public_key_source` and `public_key_obtained_at`: accepted-key provenance and timestamp.
- `cleaned_at`: records with a value are inactive and excluded from lookup and export.
- `cleanup_reason`: the reason associated with an inactive record.

Runtime state and exclusions are not interchangeable with certificate facts.
Normal synchronization does not delete historical records.
See [published fields](data-schema.md) and [retry rules](sources-and-retries.md).
