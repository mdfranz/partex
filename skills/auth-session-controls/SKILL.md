---
name: auth-session-controls
description: >-
  Invoke when reviewing session cookie configuration passively or probing token
  lifecycle and validation weaknesses in live engagements.
modes:
  - passive
  - active
checks:
  - session-cookie-config
  - token-weakness
license: Apache-2.0
metadata:
  author: partex
  derived_from:
    - communitytools/skills/authentication/SKILL.md (MIT)
    - communitytools/skills/client-side/SKILL.md (MIT)
    - zhaoxuya520/reverse-skill api-security playbook (MIT)
---

# Authentication and Session Controls

Separate response-visible session controls (`session-cookie-config`, passive) from
probe-verified token lifecycle controls (`token-weakness`, active) so findings never
conflate header observation with runtime enforcement.

**Standards:** RFC 8725 (JWT Best Current Practices), RFC 7515–7519 (JWS/JWK/JWA/JWT),
RFC 6749 §5.1 (OAuth 2.0 `Cache-Control: no-store` on token responses),
`draft-ietf-httpbis-rfc6265bis`, OWASP API2:2023 (Broken Authentication), OWASP WSTG v4.2
(`WSTG-SESS-02`, `WSTG-SESS-03`, `WSTG-SESS-04`, `WSTG-SESS-06`, `WSTG-SESS-10`), CWE-347,
CWE-327, CWE-613, CWE-598 (full citations and URLs in `docs/skills/auth-session-controls.md`).

## Mode Split and Check Mapping

### 1. `session-cookie-config` (`passive`)

Inspect `HttpExchange` `Set-Cookie`, `Cache-Control`, `Location`, `Referer`, and
`WWW-Authenticate` / `Authorization` headers in captured or bundled responses:

- **Flag (`WSTG-SESS-04`, CWE-598):** Bearer tokens, JWTs, API keys, or session identifiers
  appearing in URL query/path parameters (`?access_token=`, `?token=`, `;jsessionid=`),
  `Location` redirects, or cross-origin `Referer` headers (distinguishing auth credentials
  from opaque pagination cursors such as `next_page_token`).
- **Flag (RFC 6749 §5.1):** Token-issuing responses (`POST /oauth/token`, login endpoints
  returning `access_token` / `refresh_token`) missing `Cache-Control: no-store`.
- **Flag (`WSTG-SESS-02`):** Session-bearing cookies missing `HttpOnly`, `Secure` (on HTTPS),
  or `SameSite` (`Lax`/`Strict`), or `SameSite=None` without `Secure` (subject to the
  deduplication boundary with `header-security` below).
- **Insufficient evidence:** Exchanges with no `Set-Cookie` or auth headers on public
  unauthenticated routes — mark `not_applicable` or insufficient evidence rather than
  flagging.
- **Redaction:** Cite cookie/parameter names and attribute flags only; never emit token or
  cookie values.
- **Boundary with `header-review` (`header-security`):** Pure cookie-attribute gaps
  (missing `HttpOnly`/`Secure`/`SameSite`) are the `header-security` finding class; when
  both checks run, attribute-only gaps must not be double-reported. This check's distinct
  value is session semantics: classifying session-bearing cookies, tokens in URLs and
  `Referer`-exposed redirects, `Cache-Control: no-store` on token responses, and
  probe-verified lifecycle controls.

### 2. `token-weakness` (`active`, with `verify_recipe`)

Probe token acceptance and lifecycle boundaries within `PLAN.md` §17.2 verification
depth (minimal confirmation, no brute-force cracking — see
[session-and-token-checks.md](reference/session-and-token-checks.md) for the **mandatory
invalid-token baseline pre-check** and exact probe recipes):

- **Mandatory step 0 — invalid-token baseline pre-check:** Before sending crafted JWTs, send
  one request with an obviously invalid token (`Authorization: Bearer partex.invalid.token`).
  Only probe endpoints that return `2xx` to the valid engagement token and `401`/`403` to the
  invalid token (preventing false positives on public or unauthenticated endpoints).
- **Expired-token replay (RFC 8725 §3.8, CWE-613):** Replay an expired credential or token
  against a protected endpoint; flag if accepted (`2xx`).
- **Logout / revocation invalidation (`WSTG-SESS-06`):** Capture a session token, invoke the
  declared logout/revoke endpoint (if not excluded in `scope.exclusions`), and replay the
  prior token; flag if still accepted (`2xx`).
- **Unverified signature / `alg: none` bypass (RFC 8725 §3.1, CWE-347):** Test a corrupted
  signature segment (catching missing `verify_signature` checks) and `alg: none` case
  variants (`"none"`, `"None"`, `"NONE"`, signature stripped with trailing `.` preserved) on
  JWT-authenticated endpoints; flag if accepted (`2xx`).
- **Key confusion (`RS256` → `HS256`, RFC 8725 §3.2, CWE-327):** Where the contract or
  captured tokens show an asymmetric signature algorithm and a public key is available (from
  bundle evidence or in-scope `/.well-known/jwks.json`), re-sign the token with `alg: HS256`
  using the target's SPKI/PKCS#1 PEM public key bytes as the HMAC secret; flag if accepted
  (`2xx`).
- **JWT header triage leads (`jwk`, `jku`, `x5u`, `kid`) & out-of-v1 scope:** If a captured
  JWT header carries `jwk`, `jku`, `x5u`, or injectable `kid` parameters, record them as
  coverage leads for manual triage (`WSTG-SESS-10` / PortSwigger JWT methodology), but do
  **not** launch out-of-band `jku`/`x5u` SSRF callbacks, `kid` SQLi/path-traversal payloads,
  HMAC dictionary brute-forcing, or interactive OAuth `redirect_uri`/`state`/PKCE manipulation
  from `token-weakness`.
- **Missing evidence:** If no protected endpoint or token fixture is available in the
  engagement, record `needs_follow_up` in `CoverageEntry` rather than claiming pass.

Consult [session-and-token-checks.md](reference/session-and-token-checks.md) for
distinguishing response-visible vs. probe-verified controls, the invalid-token pre-check,
and `verify_recipe` rules.
