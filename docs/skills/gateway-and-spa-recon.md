# Research: Gateway Policy (`P2.2`) & Browser SPA Reconnaissance (`M7`)

- **Priority / Milestones:**
  - **M7 (`PLAN.md` §13.6 & §15, `DEPS.md` §5–§8):** Browser Capture Harness (`src/partex/browser.py` + `playwright-cli` agent guidance port) — primary evidence feeder for `api-inventory` (P1.1) and `authorization-testing` (P1.2) on modern SPAs.
  - **P2.2 / S5 (`docs/skills/PLAN.md` §4):** `gateway-policy` skill + check (rate/size limits, API deprecation/sunset lifecycle, OWASP API4:2023 & API9:2023).
- **Standards & References:**
  - OWASP API Security Top 10 (2023):
    - [API4:2023 — Unrestricted Resource Consumption](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/)
    - [API9:2023 — Improper Inventory Management](https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/)
  - [IETF `draft-ietf-httpapi-ratelimit-headers` — `RateLimit` and `RateLimit-Policy` HTTP Header Fields](https://datatracker.ietf.org/doc/draft-ietf-httpapi-ratelimit-headers/) & [RFC 9651 — Structured Field Values for HTTP](https://www.rfc-editor.org/rfc/rfc9651)
  - [IETF RFC 6585 §4 — `429 Too Many Requests`](https://www.rfc-editor.org/rfc/rfc6585#section-4) & [RFC 9110 §10.2.3 — `Retry-After`](https://www.rfc-editor.org/rfc/rfc9110#section-10.2.3)
  - [IETF RFC 9745 — The `Deprecation` HTTP Header Field](https://www.rfc-editor.org/rfc/rfc9745) & [RFC 8594 — The `Sunset` HTTP Header Field](https://www.rfc-editor.org/rfc/rfc8594)
  - [ECMA-426 — Source Map Format Specification (v3)](https://tc39.es/ecma426/)
  - OWASP WSTG v4.2 (Client-Side & JS Bundle Analysis — `js-analysis`):
    - [WSTG-CLNT-01 — Testing for DOM-Based Cross Site Scripting](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/01-Testing_for_DOM-based_Cross_Site_Scripting)
    - [WSTG-CLNT-11 — Testing Web Messaging (`postMessage`)](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/11-Testing_Web_Messaging)
    - [PortSwigger Web Security Academy — DOM-Based Vulnerabilities](https://portswigger.net/web-security/dom-based)
  - [Chrome DevTools Protocol (CDP)](https://chromedevtools.github.io/devtools-protocol/) & [Playwright Network / Route Interception API](https://playwright.dev/python/docs/network)
  - CWEs: [CWE-770](https://cwe.mitre.org/data/definitions/770.html) (Allocation of Resources Without Limits or Throttling), [CWE-540](https://cwe.mitre.org/data/definitions/540.html) (Inclusion of Sensitive Information in Source Code / Source Maps), [CWE-798](https://cwe.mitre.org/data/definitions/798.html) (Use of Hard-coded Credentials), [CWE-79](https://cwe.mitre.org/data/definitions/79.html) (DOM XSS)

---

## 1. API Gateway Policy & Lifecycle Verification (`P2.2` / `S5`)

### 1.1 Rate-Limiting Signaling Standards (Passive + Bounded Active)

Modern API gateways (Envoy, Kong, Cloudflare, AWS API Gateway, Zuplo, Fastly) advertise
throttling policies through either the IETF Structured Fields standard or legacy `X-RateLimit-*`
headers:

| Family | Headers | Format / Semantics |
|---|---|---|
| **IETF HTTPAPI Standard** | `RateLimit-Policy`, `RateLimit` | Structured Fields (RFC 9651), e.g. `RateLimit-Policy: "default";q=100;w=60` and `RateLimit: "default";r=97;t=42` (`q` = quota, `w` = window seconds, `r` = remaining, `t` = reset seconds) |
| **Legacy De-Facto** | `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` (or `X-Rate-Limit-*`) | Note semantic split on `Reset`: GitHub/Twitter send Unix epoch seconds, whereas other gateways send delta seconds! |
| **Throttle Enforcement** | HTTP `429 Too Many Requests` + `Retry-After` | `Retry-After` is either an HTTP-date or non-negative integer seconds (RFC 9110 §10.2.3) |

**Three-Way Distinction (`docs/skills/PLAN.md` §4 P2.2):**
1. **Declared policy only:** Rate/payload limit appears in OpenAPI (`x-ratelimit-*`, `429`
   response definition, `maxLength`/`maxItems`) or gateway `ConfigExcerpt`, with **no**
   runtime header or `429` evidence in captures → report as declared-unverified (`CoverageEntry`).
2. **Passively observed / actively verified policy:** Response carries consistent `RateLimit`
   decrementing counters or enforces `429` / `413 Content Too Large` within budget.
3. **Missing policy on sensitive / high-cost operations (`OWASP API4:2023`):** Authentication
   endpoints (`/login`, `/otp`, `/password-reset`), export/report endpoints, or unbounded
   pagination (`?limit=10000` accepted without cap) show neither declared limits nor runtime
   rate-limit headers.

> **Engagement Budget Guardrail (`max_rps` / `max_requests`):**
> Active gateway checks in `partex` **never** attempt volumetric DoS! If an endpoint declares
> a quota `q=1000;w=60` that exceeds the engagement's remaining `max_requests` or `max_rps`
> ceiling, `gateway-policy` inspects passive headers and pagination/size caps (`?limit=`,
> `maxItems`) rather than burning the engagement's request budget trying to trip `429`.

### 1.2 API Deprecation & Sunset Lifecycle (`RFC 9745` & `RFC 8594`)

Complements `api-inventory` (P1.1) for zombie/legacy endpoint detection:

- **`Deprecation` (RFC 9745):** Structured Field Date prefixed with `@` Unix timestamp, e.g.
  `Deprecation: @1735689600` (note: legacy implementations also emit `Deprecation: true` or
  an HTTP-date — parse `@<int>` first with graceful fallback).
- **`Sunset` (RFC 8594):** IMF-fixdate HTTP timestamp, e.g.
  `Sunset: Wed, 01 Jul 2026 00:00:00 GMT`.
- **`Link: <...>; rel="deprecation"` or `rel="sunset"`:** Points to migration documentation.

**Check findings:**
- **Active past-Sunset zombie endpoint (`medium`, `API9:2023`):** Captured `2xx` exchange
  carries a `Sunset` timestamp strictly earlier than the capture timestamp (endpoint was
  scheduled for retirement and is still serving live traffic!).
- **Undocumented deprecation drift (`low`):** OpenAPI marks `deprecated: true` on an
  operation, yet live `2xx` responses omit `Deprecation` / `Sunset` headers (clients receive
  no programmatic warning), or vice versa.

### 1.3 Rate-Limit Trust Confusion (Header Spoofing — BaaRai / `reverse-skill` Lineage)

Gateways and backends that trust unstripped client IP forwarding headers (`X-Forwarded-For`,
`X-Real-IP`, `True-Client-IP`, `CF-Connecting-IP`) allow trivial rate-limit or IP-allowlist
bypass when the origin fails to strip untrusted headers at the edge.
- Within bounded active probing (when a small per-IP rate limit *is* tripped during authorized
  testing, returning `429`), a **single** follow-up request adding `X-Forwarded-For: 203.0.113.1`
  (RFC 5737 documentation TEST-NET-3 address) deterministically proves `XFF` trust confusion
  if `429` immediately reverts to `200 OK`!

---

## 2. Browser Capture Harness & SPA Reconnaissance (`M7`)

Modern React/Next.js/Vue/Angular SPAs conceal most of their API surface until JavaScript
executes in a real browser context. Per `DEPS.md` §5–§8 and `PLAN.md` §13.6, `partex`
replaces the Go forks' `api-recon` Node/Puppeteer scripts with engine-owned Playwright
machinery (`src/partex/browser.py`) plus data-only agent guidance.

### 2.1 Why Route Interception (`context.route("**/*", ...)`) Is the Security Seam

Playwright provides two distinct network APIs:
1. **Passive listeners** (`page.on("request")`, `page.on("response")`) — observe traffic
   *after* the browser sends it (cannot block out-of-scope requests before bytes hit the wire!).
2. **Active route interception** (`await context.route("**/*", handler)`) — pauses **every**
   navigation, `fetch`, `XHR`, WebSocket handshake, image, and script load **before** the
   socket write!

**Mandatory M7 Architecture (`PLAN.md` §13.6):**
- Attach the scope gate at `BrowserContext.route("**/*", ...)` (context-level, not just single
  `Page`, so popups, `window.open`, service workers, and iframes are also gated!).
- On every outgoing request:
  1. Run `scope.check(request.url)` and check `max_requests` / `max_rps` budgets.
  2. If out of scope (third-party analytics, CDN outside `scope.hosts`, excluded `/logout`
     path, disallowed port): call `await route.abort("blockedbyclient")` and record the scope
     refusal on the run — **zero bytes reach the out-of-scope host**.
  3. If in scope: increment the shared engagement request counter, call `await route.continue_()`
     (or `route.fetch()`), and persist the resulting `HttpExchange` immediately at response
     completion with `source="capture:browser:<seq>"`.

### 2.2 Credential-Free SPA Discovery ("Bootstrap Mocking" from `api-recon`)

Unauthenticated SPAs normally redirect `/dashboard` or `/admin` immediately back to `/login`
when `/api/me` or `/api/session` returns `401`. The ARTEX `api-recon` lineage solved this
without credentials by stubbing bootstrap endpoints in browser memory so lazy-loaded JS route
chunks (`admin-*.js`, `billing-*.js`) execute and emit their backend API paths:

- In Playwright (`--discover-stubs` / managed-Chromium localhost/recon mode):
  - `page.route` intercepts known user-bootstrap responses returning `401` only when
    explicitly enabled for discovery, **or** harvests static route maps from downloaded JS
    bundles without mutating stored `RunStore` evidence (any mocked response must **never**
    be stored as genuine server `HttpEvidence` — findings must link only to real server
    exchanges!).
- For authenticated testing (`partex browse --attach <cdp-port>` or `engagement.roles`), each
  engagement role gets its own isolated `BrowserContext` (`storage_state` isolated per role),
  tagging captured evidence so `api-inventory` (P1.1) and `authorization-testing` (P1.2)
  immediately inherit role-labeled SPA exchanges.

### 2.3 Secret Redaction Invariants on Browser Captures (`DEPS.md` §8.5)

Because an operator-attached browser (`connect_over_cdp`) holds live cookies and bearer
tokens that were never listed in `engagement.credentials`:
1. Blanket-mark every request `Cookie`, `Authorization`, `Proxy-Authorization`, and `X-CSRF-*`
   / `X-XSRF-*` / `X-API-Key` header in `secret_fields`.
2. Mark every response `Set-Cookie` header **value-only** in `secret_fields` using the shared
   RFC 6265bis splitter, leaving `; Secure; HttpOnly; SameSite=...` visible so
   `partex export-bundle` → `partex review` reproduces both `header-security` and
   `session-cookie-config` findings with zero cleartext secret exposure.
