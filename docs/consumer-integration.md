# Consumer Integration

This guide is for certificate authorities and other systems that consume the
published compromised-key dataset. Consumers do not need to run the collection
pipeline. They should retrieve a verified data release and keep a last-known-good
version available.

## Recommended Architecture

Production CA systems should use a separate updater with outbound network access:

```text
GitHub immutable release
        |
        v
isolated updater -> checksum and database validation -> internal artifact store
                                                        |
                                                        v
                                      issuance and monitoring systems
```

The updater needs read-only access to public releases. Signing systems should not
hold GitHub credentials or write to the downloaded dataset. Larger deployments
should download once, publish the verified bundle to an internal artifact store,
and let all CA nodes consume that internal copy.

## Version Selection

Poll every 30 to 60 minutes for the newest immutable tag matching
`data-vYYYY.MM.DD.HHMM`. Do not use the rolling `data-latest` alias as the production
version identifier: its files are replaced one at a time and may be inconsistent
during an update.

One way to discover the latest immutable release with GitHub CLI is:

```bash
REPOSITORY=trustasia-com/compromised-keys
TAG="$(gh release list --repo "$REPOSITORY" --limit 30 \
  --json tagName,isDraft,isPrerelease \
  --jq '[.[] | select(.isDraft == false and .isPrerelease == false) |
    .tagName | select(test("^data-v[0-9]{4}\\.[0-9]{2}\\.[0-9]{2}\\.[0-9]{4}$"))]
    | sort | last')"
test -n "$TAG"
```

Store the selected tag with every local deployment and audit decision. A newer tag
must never be replaced by an older one unless an operator performs a documented
rollback.

## Verified Update

Download into a version-specific staging directory on the same filesystem as the
active data. Never write over files that are currently in use.

```bash
BASE=/var/lib/compromised-keys
REPOSITORY=trustasia-com/compromised-keys
STAGING="$(mktemp -d "$BASE/.incoming-${TAG}.XXXXXX")"

gh release download "$TAG" --repo "$REPOSITORY" --dir "$STAGING/assets"
(
  cd "$STAGING/assets"
  sha256sum --check SHA256SUMS
)

compromised-keys restore-release \
  --asset-dir "$STAGING/assets" \
  --output "$STAGING/compromised_keys.db"
```

`restore-release` verifies release checksums, the database manifest, decompression,
SQLite integrity, and the expected public schema. An update is usable only when both
the complete `SHA256SUMS` check and `restore-release` succeed.

After validation, move the staging directory to `releases/$TAG` and atomically replace
a `current` symlink. Reload consumers only after the pointer changes. Retain at least
the previous two verified releases for rollback. If any step fails, delete only the
staging directory, continue serving the last-known-good release, and alert an operator.

For higher assurance, an organization can sign the verified bundle with its own
artifact-signing key before internal distribution. The release checksum file detects
incomplete or corrupted downloads, but it is distributed with the release and is not
an independent publisher signature.

## Issuance Check

Use the release as a pre-issuance risk control:

1. Compute the project `key_hash` from the CSR public key.
2. Test the hash against `compromised_keys.bf` for a fast negative result.
3. Confirm every Bloom Filter hit against `key_hash` in the CSV or SQLite database
   from the same immutable release.
4. Apply the CA's documented policy to an exact match, normally rejecting issuance
   or routing it to security review.
5. Record the release tag, release digest, key hash, result, and policy action in the
   issuance audit trail.

The fingerprint is not SHA-256 of SubjectPublicKeyInfo:

- RSA: SHA-256 of unsigned modulus bytes after leading zero bytes are removed.
- EC: SHA-256 of the unsigned public-point X coordinate bytes.

`compromised-keys check request.csr` implements the project fingerprint and Bloom
Filter check for integration tests and low-volume use. Exit code `0` means no Bloom
Filter match, `2` means a possible match, and `1` means the CSR could not be checked.
A possible match still requires exact confirmation. An unlisted key is not proof that
the private key is safe, and unsupported key algorithms must not be treated as clean.

For high-volume issuance, load the exact `key_hash` column into an indexed local store
or service. Keep the Bloom Filter and exact data bound to the same release tag during
reloads.

## Scheduling And Failure Policy

The upstream project currently publishes on a daily schedule. Consumer polling can
run more frequently without increasing collection traffic because it only checks
GitHub release metadata.

A practical starting policy is:

- check for a new immutable release every 30 minutes, with a small randomized delay;
- warn when the active release is more than 36 hours old;
- escalate when it is more than 48 hours old;
- keep serving the last-known-good release during download or validation failures;
- define separately whether extreme staleness blocks issuance, because automatic
  fail-closed behavior can stop CA operations.

Monitor the active tag, release publication time, last successful update, failed
update count, checksum result, database validation result, and exact-match count.
Alerting must be based on the age of the active verified release, not only on whether
the updater process exited successfully.

A `systemd` timer is sufficient for a single updater. In clustered or offline CA
environments, schedule only the internal mirror job against GitHub and distribute the
approved immutable bundle through existing artifact-management controls.

For example, install the verified update procedure above as
`/usr/local/sbin/update-compromised-keys`, then use:

```ini
# /etc/systemd/system/compromised-keys-update.service
[Unit]
Description=Update the verified compromised-key dataset
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=compromised-keys
ExecStart=/usr/local/sbin/update-compromised-keys
```

```ini
# /etc/systemd/system/compromised-keys-update.timer
[Unit]
Description=Check for a compromised-key data release

[Timer]
OnBootSec=5m
OnCalendar=*-*-* *:00,30:00
RandomizedDelaySec=5m
Persistent=true

[Install]
WantedBy=timers.target
```

Enable it with `systemctl enable --now compromised-keys-update.timer`. The update
script should exit nonzero on any discovery, download, checksum, restore, mirror, or
reload failure so service monitoring can alert on the failure.
