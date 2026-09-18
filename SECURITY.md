# Security Policy

## Reporting a vulnerability

Do not disclose an unpatched vulnerability in a public Issue, Discussion, or pull
request.

Use one of these private channels:

1. GitHub Private Vulnerability Reporting for this repository;
2. email `support@trustasia.com` with subject `[compromised-keys security]`.

Include the affected version, impact, reproduction steps, and any suggested
mitigation. Do not include private keys, production credentials, access tokens, or
unrelated personal data. The company support group will route reports internally and
aims to acknowledge them within three business days.

## Supported versions

Security fixes are made against the latest source release. Historical data releases
are immutable; corrections are published as a new data version.

## Dependency And Container Security

The project requires a Python version supported by current security-fixed runtime
dependencies. CI audits the resolved Python environment with `pip-audit` and scans
the built container with Trivy every week and on source changes. Direct dependencies,
GitHub Actions, pre-commit hooks, and the Python base image are monitored by
Dependabot; Actions and container bases are pinned to immutable commit or image
digests.

The published Docker configuration runs as a non-root user, drops Linux capabilities,
and enables `no-new-privileges`. CI reports every High or Critical image finding and
blocks findings for which an upstream fix exists. Findings without a Debian fix remain
visible but cannot be remediated in the image; weekly base-image digest updates are used
to pick up fixes as they become available. Do not otherwise suppress a finding without
documenting why it is unreachable or mitigated.

## Data-use limitations

Public CRL URLs and every redirect are limited to HTTP(S) public unicast addresses;
private, loopback, link-local and multicast destinations are rejected, including DNS
answers. This restriction does not apply to the operator-configured CT endpoint.
Dedicated runners must still enforce outbound firewall restrictions, have no unrelated
credentials, and never run untrusted PR code. Use separate writable caches per dataset.

CRLs are structurally parsed but their signatures and complete certificate chains are
**not verified** against an authenticated CA certificate. AKI/serial matching is an
identity consistency check, not cryptographic proof of authenticity. In particular,
HTTP CRLs can be modified in transit. Treat the dataset as a risk signal, not sole
evidence for an automatic industry-wide blocking decision. Independent signature and
issuer verification remains necessary for that use case.

`compromised-keys` is one security signal, not a complete key-compromise oracle.

- A Bloom Filter miss means only that the key is absent from that filter version.
- A Bloom Filter hit may be a false positive and must be confirmed against the CSV
  or SQLite database from the same release.
- Upstream publication delays and missing source certificates can cause dataset gaps.
- A negative result must not be described as proof that a private key is secure.

## Release integrity

Every data release contains `SHA256SUMS` and `db-manifest.json`. Use
`compromised-keys restore-release` or equivalent independent checks before trusting a
database snapshot. Stop on any checksum, schema, or SQLite integrity failure.

Report suspected release tampering through the private channels above.

CSV fields retain upstream certificate text. Import CSV as text and disable spreadsheet
formula execution; do not enable active content from downloaded data.
