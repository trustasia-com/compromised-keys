# Contributing

## Development setup

```bash
git clone https://github.com/trustasia-com/compromised-keys.git
cd compromised-keys
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e ".[dev,postgres,release]"
pre-commit install
```

Run the local checks before opening a pull request:

```bash
ruff check .
ruff format --check .
pytest
python -m pip_audit --skip-editable
python -m build
python -m twine check dist/*
docker build --tag compromised-keys:local .
```

Focus tests on certificate identity, lookup outcomes, data integrity, and export/restore
behavior. Avoid assertions on documentation wording, exact dependency versions, or
behavior already covered by another test. CI audits dependencies and builds the container.

Do not commit databases, generated data,
download caches, logs, internal service addresses, credentials, or private keys.

## CT Provider implementations

CT Providers implement the generic batch interface and return a structured outcome
for every selected record:

```python
from compromised_keys.ct_client import BaseCTProvider
from compromised_keys.lookup import LookupProviderResult


class MyCTProvider(BaseCTProvider):
    async def query_records(self, records, concurrency=5):
        return LookupProviderResult(records=[])
```

A provider must distinguish `not_found` from transport, HTTP, parsing, identity, DER,
and key-algorithm failures. Only a successful, structurally valid empty response may
produce `not_found`. Tests and documentation must use `https://ct.example.com`, not a
real private endpoint.

## Certificate submissions

Use the Certificate Submission Issue template for a public PEM certificate whose
serial number and issuer already match a tracked key-compromise revocation.

- Submit public certificates only.
- Never submit a private key, password, token, or confidential certificate.
- Automated validation comments on the Issue but does not modify production data.
- A maintainer reviews valid submissions before applying them in a controlled run.

The project does not accept batch certificate files through pull requests in the
initial release.

## Data changes

Git does not contain the historical SQLite database. Changes that affect schema,
fingerprints, filtering, or source interpretation must include data-preservation and
release-compatibility tests. Never replace `data-latest` from a new empty database.
Database changes must be transactional and preserve records, key metadata, and active
exclusions. Test both fresh databases and copies of the supported release schema.

## Pull requests

1. Keep the change focused.
2. Explain user-visible behavior and data impact.
3. Include tests and update English and Chinese documentation when applicable.
4. Confirm that no runtime data or private configuration is included.
5. Wait for review and CI before merge.

By contributing code, you agree to license your contribution under MIT. Contributions
to project-owned data selection or metadata are provided under the data terms in
[DATA_NOTICE.md](DATA_NOTICE.md), to the extent you have the right to do so.
