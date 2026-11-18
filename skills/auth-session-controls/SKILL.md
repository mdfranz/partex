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

## Mode Split and Check Mapping

### 1. `session-cookie-config` (`passive`)

Inspect `HttpExchange` `Set-Cookie` and `WWW-Authenticate` / `Authorization` headers in
captured or bundled responses:

- **Flag:** Session-bearing cookies missing `HttpOnly`, `Secure` (on HTTPS), or
  `SameSite` (`Lax`/`Strict`), or `SameSite=None` without `Secure`.
- **Flag:** Bearer tokens or session identifiers appearing in URL query parameters or
  `Referer`-exposed redirects.
- **Insufficient evidence:** Exchanges with no `Set-Cookie` or auth headers on public
  unauthenticated routes — mark `not_applicable` or insufficient evidence rather than
  flagging.
- **Redaction:** Cite cookie names and attribute flags only; never emit token or cookie
  values.
- **Boundary with `header-review` (`header-security`):** Pure cookie-attribute gaps
  (missing `HttpOnly`/`Secure`/`SameSite`) are the `header-security` finding class; when
  both checks run, attribute-only gaps must not be double-reported. This check's distinct
  value is session semantics: classifying session-bearing cookies, tokens in URLs and
  `Referer`-exposed redirects, and probe-verified lifecycle controls.

### 2. `token-weakness` (`active`, with `verify_recipe`)

Probe token acceptance and lifecycle boundaries within `PLAN.md` §17.2 verification
depth (minimal confirmation, no brute-force cracking):

- **Expired-token replay:** Replay an expired credential or token against a protected
  endpoint; flag if accepted (`2xx`).
- **Logout / revocation invalidation:** Capture a session token, invoke the declared
  logout/revoke endpoint (if not excluded in `scope.exclusions`), and replay the prior
  token; flag if still accepted (`2xx`).
- **Signature / algorithm confusion:** Test `alg: none` (header rewritten, signature
  stripped) on JWT-authenticated endpoints; flag if accepted (`2xx`).
- **Key confusion (RS256 → HS256):** Where the contract or captured tokens show an
  asymmetric signature algorithm, re-sign a token using the endpoint's public key as
  an HMAC secret; flag if accepted (`2xx`). Same depth class as `alg: none`.
- **Out of v1 scope:** OAuth flow flaws (`redirect_uri` manipulation, missing `state`,
  missing PKCE, token leakage via `Referer`/logs) and brute-forcing of HMAC secrets are
  **not** part of `token-weakness`; do not drift into them during token probing.
- **Missing evidence:** If no protected endpoint or token fixture is available in the
  engagement, record `needs_follow_up` in `CoverageEntry` rather than claiming pass.

Consult [session-and-token-checks.md](reference/session-and-token-checks.md) for
distinguishing response-visible vs. probe-verified controls and `verify_recipe` rules.
