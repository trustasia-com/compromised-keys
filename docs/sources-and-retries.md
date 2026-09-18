# Sources, Outcomes, And Retries

## Record Outcomes

Each completed source attempt records an outcome for its records.

| Outcome | Meaning | Counts as successful miss |
|:--|:--|:--:|
| `found` | Identity and DER validated; key accepted. | No |
| `not_found` | Successful, structurally valid query returned no match within its query scope. | Yes |
| `invalid_local_identity` | Local AKI or serial cannot be encoded safely. | No |
| `malformed_response` | Provider response or certificate cannot be parsed. | No |
| `missing_der` | Result identity exists but DER is absent. | No |
| `identity_mismatch` | Returned identity or downloaded certificate does not match. | No |
| `unsupported_key` | Certificate key cannot be fingerprinted. | No |
| `rate_limited` | Provider returned HTTP 429. | No |
| `http_client_error` | Non-429 HTTP 4xx response. | No |
| `http_server_error` | HTTP 5xx response. | No |
| `timeout`, `network_error` | Request did not complete reliably. | No |
| `provider_unavailable` | Setup failed or the source circuit is open. | No |

Only `not_found` increments `consecutive_misses`. All error outcomes increment
`consecutive_errors`, preserve successful-miss history, and do not set record-level
error backoff. Another source remains immediately eligible.

## Successful-Miss Retry

- Revoked within 30 days: retry after 1 day.
- Older revocation, fewer than 10 misses: retry after 7 days.
- 10 or more valid misses: retry after 30 days.
- No miss count creates a permanent exclusion.

An explicit full-history CT run ignores `next_retry_after` but still honors exact
operator exclusions and still requires an AKI.

## CT Query Windows

Requests group one AKI, sort UTC revocation dates newest first, and batch at most
1,000 serials per request. For each batch, let `r_min` and `r_max` be its earliest
and latest revocation dates:

- `not_before_to = r_max + 1 day`.
- `not_after_from = r_min - 1 day`.
- For each possible issuance period below, intersect that period with
  `[r_min - 1 day - validity, r_max + 1 day]`.
- `not_before_from` is the earliest date across the nonempty intersections.
- `not_after_to` is the latest possible expiry across those intersections.

| Issuance period starts | Maximum validity used |
|:--|:--|
| 2012-07-01 | 60 calendar months, including the exception available through June 2016 |
| 2016-07-01 | 39 calendar months |
| 2018-03-01 | 825 days |
| 2020-09-01 | 398 days |
| 2026-03-15 | 200 days |
| 2027-03-15 | 100 days |
| 2029-03-15 | 47 days |

Sources: [Ballot 193](https://cabforum.org/2017/03/17/ballot-193-825-day-certificate-lifetimes/),
[TLS BR 1.8.4 section 6.3.2](https://cabforum.org/uploads/CA-Browser-Forum-BR-1.8.4-redline.pdf),
and [current TLS BR section 6.3.2](https://cabforum.org/working-groups/server/baseline-requirements/requirements/).
Rules apply to issuance, not revocation: an older, longer-lived certificate must
remain in the window after a rule change. Calendar months are not treated as 30 days.

These are search bounds for TLS subscriber certificates, not evidence of BR
compliance. Backdated revocations, revocations after expiry, CA certificates, and
nonconforming validity periods can fall outside them. Normal runs use the narrow
scope. `--full-history` ignores retry times and retries only successful narrow-scope
misses using the historical range: both lower bounds `2010-01-01`, `not_before_to`
through today, and `not_after_to` through one calendar year from today. If that
fallback fails, its error replaces the narrow miss; it does not count as a successful
miss. Found certificates and missing-DER results are not queried again in the fallback.

Missing, invalid, future, or pre-2012-07-01 revocation dates are grouped separately:
normal runs omit time filters for these records; historical runs use the wide range
directly. Historical fallback can still be expensive when most records are absent.

## Source Circuit Breaker

A circuit affects one source for one process run. It opens after any of:

- 5 consecutive failed requests;
- at least 10 samples in the recent 20 with a failure ratio of 50% or more;
- 3 consecutive HTTP 429 responses;
- one non-429 HTTP 4xx response, indicating endpoint, authorization, or request
  configuration failure.

Queued requests rejected by a circuit receive `provider_unavailable`, not `not_found`.
Batches not yet submitted remain pending. The pipeline continues to the next source.

## Ambiguous CT Responses

If an item lacks enough identity to associate it with one requested record, or names
an identity outside the request, the client does not mark absent records as misses.
It splits the batch and retries smaller batches. A singleton that remains ambiguous
is recorded as `malformed_response` or `identity_mismatch`.
