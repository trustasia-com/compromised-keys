# Data Notice

This notice applies to data releases published by the `compromised-keys` project.
It does not change the [MIT License](LICENSE) that applies to the source code.

## Project data grant

To the extent that TrustAsia or project contributors own copyright, database rights,
or other licensable rights in the selection, arrangement, and original metadata of a
data release, those rights are made available under the
[Community Data License Agreement - Permissive, Version 2.0](https://cdla.dev/permissive-2-0/)
(`CDLA-Permissive-2.0`). This grant does not override rights or obligations attached
to third-party source material.

## Sources

Data releases may contain facts and public certificate material derived from:

- [Common CA Database (CCADB)](https://www.ccadb.org/), whose published usage terms
  make CCADB data available under CDLA-Permissive-2.0 and require attribution;
- certificate revocation lists published by certificate authorities;
- public Certificate Transparency data returned by a user-configured CT Provider;
- the public [crt.sh](https://crt.sh/) certificate search and read-only PostgreSQL service;
- public certificates submitted by contributors and accepted after validation.

The project identifies these sources for transparency. It does not claim ownership
of third-party certificates, CRLs, trademarks, or source records and does not grant
rights that their owners or publishers have not granted. Source-specific terms and
applicable law continue to apply.

Suggested attribution:

```text
Compromised Keys data, TrustAsia and contributors,
https://github.com/trustasia-com/compromised-keys
Includes data derived from CCADB, CA CRLs, Certificate Transparency, and crt.sh.
```

## Responsible use

Releases contain public-key and certificate metadata, not private keys. Public
certificates can nevertheless contain names or other information subject to local
law. Users are responsible for determining whether their collection, retention,
redistribution, and decision-making uses are lawful and appropriate.

The data can be incomplete, delayed, duplicated, or incorrect. It is provided
without a guarantee of coverage, accuracy, merchantability, fitness for a particular
purpose, or non-infringement. A dataset miss is not evidence that a key is safe.

Questions, correction requests, and data-rights requests may be sent to
`support@trustasia.com`. Include the release tag, record identifier, requested action,
and a way to verify the request when applicable.
