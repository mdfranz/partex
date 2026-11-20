---
name: header-review
description: >-
  Invoke when reviewing captured or bundled HTTP responses for missing security headers,
  weak cookie attributes, or permissive CORS policies.
modes:
  - passive
checks:
  - header-security
---

# HTTP Response Header Review

Evaluate captured `HttpExchange` evidence for response-level security controls without
issuing live network requests. Apply policy rules by response type so inapplicable headers
on API payloads or redirects do not generate false positives.

## Scope and Evidence Requirements

- **Passive only.** Inspect only `HttpExchange` records already registered in the run's
  `RunStore` or loaded from an offline bundle (`LoadedBundle` via `partex review`).
- **Response-type classification.** Classify each exchange before evaluating controls:
  - **HTML document** (`Content-Type: text/html` with `2xx` status): evaluate HSTS, CSP,
    framing controls (`X-Frame-Options` or CSP `frame-ancestors`), `X-Content-Type-Options`,
    `Set-Cookie`, and CORS.
  - **API / JSON response** (`Content-Type: application/json` or non-HTML data): evaluate
    HSTS (on HTTPS), `X-Content-Type-Options`, `Set-Cookie`, and CORS. Do not require
    HTML-rendering CSP directives (`script-src`, `style-src`) or framing controls on pure
    JSON APIs.
  - **Redirect** (`3xx` status): evaluate HSTS (on HTTPS) and `Set-Cookie` if present;
    do not flag missing CSP or framing controls on bare redirect stubs.
- **Aggregation (#38).** Findings aggregate per host and issue class: one finding per
  (host, subject) with every affected evidence ID attached, so a large capture produces one
  `Missing HSTS header` finding per host, not one per exchange.
- **Precision rules (#38).** Classify session cookies by whole name tokens (`sid` must not
  match `inside`); CSRF double-submit cookies do not require `HttpOnly`; accept a quoted
  HSTS `max-age` and treat an unparseable one as a malformed-directive finding, not
  `max-age=0`; do not flag `'unsafe-inline'` when a nonce/hash makes it inert; rate passive
  wildcard-with-credentials CORS `medium` (the exploitable reflected-origin variant needs an
  active probe).
- **Insufficient evidence.** When `Content-Type` is missing or the exchange is a
  `body_refused` stub without headers, record insufficient evidence rather than guessing.
- **Secret redaction.** Never echo raw `Set-Cookie` values, session tokens, or
  `Authorization` headers in finding descriptions. Cite cookie names and attribute flags
  only; rely on `secret_fields` redaction (`<redacted>`).
- **Boundary with `auth-session-controls` (`session-cookie-config`):** pure cookie
  attribute gaps belong to this check; session semantics (session-cookie
  classification, tokens in URLs and `Referer`, token lifecycle probes) belong to
  `session-cookie-config` / `token-weakness`. When both checks run, attribute-only gaps
  must not be double-reported.

## Check Mapping (`header-security`)

| Finding Class | Condition | Expected Severity |
|---|---|---|
| Missing or weak HSTS | HTTPS response lacks `Strict-Transport-Security` or sets `max-age` below minimum policy | `low` / `medium` |
| Missing or unsafe CSP | HTML response lacks `Content-Security-Policy` or allows `unsafe-inline` / wildcard `script-src` | `medium` |
| Missing `X-Content-Type-Options` | Response lacks `X-Content-Type-Options: nosniff` | `low` |
| Weak `Set-Cookie` attributes | Session-like cookie lacks `HttpOnly`, `Secure` (on HTTPS), or `SameSite` | `low` / `medium` |
| Permissive CORS with credentials | `Access-Control-Allow-Origin: *` or unvalidated origin reflection paired with `Access-Control-Allow-Credentials: true` | `high` |

## Output Discipline

- Cite the exact `ev_*` evidence ID, HTTP status, and response header name(s) in every
  finding.
- Passive findings are deterministic functions of the `HttpExchange` set and start in
  `reported` status.
- Consult [response-policies.md](reference/response-policies.md) for header-by-header
  baselines and edge-case rules.
