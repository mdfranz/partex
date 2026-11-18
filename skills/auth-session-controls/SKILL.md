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
    - BaaRai/ARTEX/skills/api-security/SKILL.md (AGPL-3.0)
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
  unauthenticated routes—mark `not_applicable` or insufficient evidence rather than
  flagging.
- **Redaction:** Cite cookie names and attribute flags only; never emit token or cookie
  values.

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
- **Missing evidence:** If no protected endpoint or token fixture is available in the
  engagement, record `needs_follow_up` in `CoverageEntry` rather than claiming pass.

Consult [session-and-token-checks.md](reference/session-and-token-checks.md) for
distinguishing response-visible vs. probe-verified controls and `verify_recipe` rules.
