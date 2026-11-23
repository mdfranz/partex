# Research: `header-review` (`header-security`)

- **Priority / Milestone:** P0 — Built-in passive check (M1 landed in `src/partex/checks/header_security.py`; extended across M1–M3)
- **Skill Path:** `skills/header-review/SKILL.md` (`reference/response-policies.md`)
- **Check ID & Protocol:** `header-security` (`PassiveCheck` — pure function over `Sequence[Evidence]`)
- **Standards & References:**
  - OWASP Web Security Testing Guide (WSTG) v4.2:
    - [WSTG-CONF-07 — Test HTTP Strict Transport Security](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Strict_Transport_Security)
    - [WSTG-CLNT-07 — Testing Cross Origin Resource Sharing](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing)
    - [WSTG-CLNT-09 — Testing for Clickjacking](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/09-Testing_for_Clickjacking)
    - [WSTG-CLNT-12 — Testing for Content Security Policy](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/12-Testing_for_CSP)
    - [WSTG-SESS-02 — Testing for Cookies Attributes](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes)
  - [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/) & [OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
  - [OWASP Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html) & [web.dev Strict CSP Guide](https://web.dev/articles/strict-csp)
  - [IETF RFC 6797 — HTTP Strict Transport Security (HSTS)](https://www.rfc-editor.org/rfc/rfc6797) & [RFC 7034 — HTTP Header Field X-Frame-Options](https://www.rfc-editor.org/rfc/rfc7034)
  - [W3C Content Security Policy Level 3 (CSP3)](https://www.w3.org/TR/CSP3/)
  - [IETF `draft-ietf-httpbis-rfc6265bis` — Cookies: HTTP State Management Mechanism](https://httpwg.org/http-extensions/draft-ietf-httpbis-rfc6265bis.html) & [IETF CHIPS (`Partitioned` cookie attribute — `draft-cutler-httpbis-partitioned-cookies`)](https://datatracker.ietf.org/doc/html/draft-cutler-httpbis-partitioned-cookies)
  - [WHATWG Fetch Standard — CORS Protocol](https://fetch.spec.whatwg.org/#http-cors-protocol) & [WHATWG MIME Sniffing Standard (`X-Content-Type-Options: nosniff`)](https://mimesniff.spec.whatwg.org/)
  - [PortSwigger Web Security Academy — CORS](https://portswigger.net/web-security/cors) & [PortSwigger XSS Cheat Sheet (`image/svg+xml`)](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
  - CWEs: [CWE-319](https://cwe.mitre.org/data/definitions/319.html) (Cleartext Transmission), [CWE-614](https://cwe.mitre.org/data/definitions/614.html) (Sensitive Cookie Without `Secure`), [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html) (Sensitive Cookie Without `HttpOnly`), [CWE-1275](https://cwe.mitre.org/data/definitions/1275.html) (Sensitive Cookie with Improper `SameSite`), [CWE-942](https://cwe.mitre.org/data/definitions/942.html) (Permissive Cross-domain Policy), [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html) (Improper Restriction of Rendered UI Layers / Clickjacking), [CWE-693](https://cwe.mitre.org/data/definitions/693.html) (Protection Mechanism Failure)

---

## 1. Threat Model and Response-Type Matrix

A naive header scanner flags missing `Content-Security-Policy` on every `application/json`
API response or `302 Found` redirect, flooding reports with false positives. Modern guidance
(OWASP Secure Headers Project, Mozilla Observatory) splits expectations strictly by
**transport (`https` vs `http`)**, **status class (`2xx` vs `3xx` vs `4xx/5xx`)**, and
**representation (`text/html` / `application/xhtml+xml` vs `application/json` / API data)**:

| Control | HTML Document (`2xx` `text/html`, `xhtml+xml`, `image/svg+xml`) | JSON / API Payload (`2xx` `application/json`, etc.) | Redirect (`3xx`) | Error (`4xx`/`5xx` HTML) |
|---|---|---|---|---|
| **HSTS (`Strict-Transport-Security`)** | Required on HTTPS | Required on HTTPS | Required on HTTPS (not on HTTP→HTTPS hop) | Recommended on HTTPS |
| **CSP (`Content-Security-Policy`)** | Full document CSP required (`script-src`, `object-src`, `base-uri`, `frame-ancestors`) | Script directives N/A; `frame-ancestors 'none'` optional defense-in-depth | N/A (unless HTML body rendered) | Evaluate if `text/html` body reflects input |
| **`X-Content-Type-Options: nosniff`** | Required | Required (prevents MIME-confusion XSS in older contexts) | N/A on bodyless `3xx` | Required if body present |
| **`Set-Cookie` attributes** | Evaluate whenever `Set-Cookie` present | Evaluate whenever `Set-Cookie` present | Evaluate whenever `Set-Cookie` present (login redirects!) | Evaluate whenever `Set-Cookie` present |
| **CORS (`Access-Control-Allow-*`)** | Evaluate whenever ACAO present | Evaluate whenever ACAO present | Evaluate whenever ACAO present | Evaluate whenever ACAO present |

> **Important note on `image/svg+xml` and `text/xml`:** Uploaded or inline SVG/XML documents
> execute inline `<script>` in browsers unless sandboxed (`Content-Security-Policy: sandbox`
> or `default-src 'none'`) and served with `X-Content-Type-Options: nosniff`. Treating
> `image/svg+xml` alongside document types prevents missed stored-XSS surfaces.

---

## 2. Control-by-Control Research & Edge Cases

### 2.1 HTTP Strict Transport Security (RFC 6797 / WSTG-CONF-07)

- **RFC 6797 §7.2 rule:** User agents **ignore** `Strict-Transport-Security` headers
  received over plain `http://` (because an active MITM could strip or forge them). On an
  `http://` → `https://` redirect chain, HSTS is expected on the **first `https://`
  response**, not the `http://` 301 response.
- **Directive parsing edge cases:**
  - `max-age` may be quoted (`max-age="31536000"` is legal per RFC 6797 §6.1) and directive
    names are case-insensitive (`MAX-AGE=31536000; IncludeSubDomains`).
  - `max-age=0` explicitly instructs the browser to **evict** the host from its HSTS cache
    — a higher-signal finding than merely a short TTL.
  - Multiple `Strict-Transport-Security` headers: per RFC 6797 §8.1, browsers process only
    the **first** valid HSTS header.
  - Baseline threshold: `31536000` seconds (365 days); `63072000` (2 years) +
    `includeSubDomains` + `preload` is required only for HSTS preload list submission, not
    as a mandatory vulnerability threshold.

### 2.2 Content Security Policy Level 3 (WSTG-CLNT-12 / Google CSP Evaluator)

Research on W3C CSP3 and Google's CSP Evaluator highlights three classic analyzer mistakes:

1. **The `'strict-dynamic'` + `'unsafe-inline'` backward-compatibility pattern:**
   A hardened CSP3 policy commonly looks like:
   ```http
   Content-Security-Policy: script-src 'unsafe-inline' https: 'nonce-rAnd0m123' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'
   ```
   - Per W3C CSP3 §6.6.4.2: when a `'nonce-<base64>'` or `'sha256-...'`/`'sha384-...'`/`'sha512-...'`
     source expression is present in `script-src` (or `default-src` fallback), CSP2+
     browsers **ignore `'unsafe-inline'`**.
   - When `'strict-dynamic'` is also present, CSP3 browsers **additionally ignore host and
     scheme allowlists** (`https:`, `*`, `cdn.example.com`).
   - **Check rule:** Do **not** flag `'unsafe-inline'` or `https:` in `script-src` when a
     valid nonce/hash **and** `'strict-dynamic'` are present. Flag `'unsafe-inline'` when it
     stands alone or without a nonce/hash (note: if `'nonce-...'` is paired with a broad
     host wildcard `*` *without* `'strict-dynamic'`, CSP2/3 still honors `*`!).
2. **Missing `object-src` and `base-uri` under nonce policies:**
   - `default-src` does **not** serve as a fallback for `base-uri` or `frame-ancestors`!
   - If a policy uses nonces/`'strict-dynamic'` in `script-src` without `base-uri 'none'` or
     `base-uri 'self'`, an attacker with HTML markup injection can inject
     `<base href="https://attacker.example/">` to hijack relative `<script src="/app.js">`
     loads.
   - If `object-src` is omitted and `default-src` is absent (common in `script-src`-only
     policies), `<object>`/`<embed>` remains unrestricted.
3. **Clickjacking (`frame-ancestors` vs `X-Frame-Options`):**
   - `frame-ancestors 'none'` or `'self'` in CSP obsoletes `X-Frame-Options` (`DENY` /
     `SAMEORIGIN`). If `frame-ancestors` is missing on an HTML response, check whether
     `X-Frame-Options: DENY` or `SAMEORIGIN` is present as a legacy mitigation before
     reporting unmitigated framing.
4. **Multiple CSP headers & `Report-Only`:**
   - Multiple `Content-Security-Policy` headers intersect (the browser enforces **all** of
     them, so the strictest rule wins), whereas `Content-Security-Policy-Report-Only`
     enforces **nothing**.

### 2.3 `Set-Cookie` Security, Prefixes, and CHIPS (RFC 6265bis / WSTG-SESS-02)

Per `DEPS.md` §3.3, Python's `http.cookies.SimpleCookie` must **not** be used because it
follows legacy RFC 2109 quoting/comma rules and mishandles modern `Set-Cookie` headers. In
`HttpExchange` models, note also how multi-header `Set-Cookie` lines are represented if
multiple cookies are set on a single login response.

Key RFC 6265bis & browser rules to enforce:

| Mechanism | Rule | Violation Class |
|---|---|---|
| `HttpOnly` | Required on session/auth cookies (note: intentionally *omitted* on double-submit CSRF readable cookies like `XSRF-TOKEN`) | Missing `HttpOnly` on session cookie (`medium`) |
| `Secure` | Required on all session/auth cookies on HTTPS origins | Missing `Secure` (`medium`) |
| `SameSite` | `Lax` or `Strict` for first-party sessions. Although Chromium/Firefox default omitted `SameSite` to `Lax` (with the historical 2-minute Lax+POST caveats), explicit `SameSite` remains required baseline policy because Safari/WebKit and older clients differed. `SameSite=None` **without** `Secure` is rejected by browsers | Missing `SameSite` (`low`); `SameSite=None` without `Secure` (`medium`) |
| `__Secure-` prefix | Cookie name starting with `__Secure-` **must** carry `Secure` and originate from `https://` |Broken `__Secure-` invariant — browser silently drops cookie (`medium`) |
| `__Host-` prefix | Cookie name starting with `__Host-` **must** carry `Secure`, `Path=/`, and **no `Domain` attribute** (locks cookie to exact host, defeating subdomain cookie tossing) | Broken `__Host-` invariant (`medium`) |
| `Partitioned` (CHIPS) | Cookie with `Partitioned` attribute **must** carry `Secure` (and typically `Path=/; SameSite=None` for cross-site embeds) | `Partitioned` without `Secure` (`low`/`medium`) |

**CSRF Double-Submit Cookie False-Positive Trap:**
Frameworks like Angular/Django/Laravel set a non-`HttpOnly` cookie named `XSRF-TOKEN` or
`csrftoken` specifically so client JavaScript can read it and copy it into `X-XSRF-TOKEN` /
`X-CSRFToken`. Flagging `XSRF-TOKEN` for missing `HttpOnly` is a classic scanner false
positive! `XSRF-TOKEN` still requires `Secure` (on HTTPS) and `SameSite`, *not* `HttpOnly`
(whereas `session`, `sid`, `auth`, `jwt`, `refresh` require `HttpOnly`).

**Boundary with `auth-session-controls` (`session-cookie-config`):**
Per `skills/header-review/SKILL.md`, pure `Set-Cookie` attribute gaps belong to
`header-security`. Session lifecycle, URL/query/`Referer` token exposure, and active token
replay belong to `auth-session-controls`.

### 2.4 Cross-Origin Resource Sharing (WSTG-CLNT-07)

| ACAO Value | `Access-Control-Allow-Credentials` | Assessment |
|---|---|---|
| `*` | absent or `false` | **Compliant** on public resources; only noteworthy if response clearly contains authenticated/private data (browsers block credentialed reads with `*`, though intranet/IP-authenticated APIs can still be read cross-origin!) |
| `*` | `true` | **Misconfiguration (`high`):** Fetch spec forbids `*` + credentials (browsers block it), proving broken server CORS configuration that often accompanies fallback reflection |
| `null` | `true` | **Exploitable (`high`):** Attacker uses `<iframe sandbox="allow-scripts">` to generate `Origin: null` and read credentialed responses |
| Concrete origin matching request `Origin` | `true` | **Passive nuance:** In passive review of a *single* exchange where `Origin: https://app.example.com` matches the site's own frontend, `ACAO: https://app.example.com` + `ACAC: true` is normal! Flag in passive mode when: (a) an untrusted/third-party `Origin` is reflected, (b) `http://` insecure origin is allowed on an `https://` target with `ACAC: true`, or (c) `Vary: Origin` is missing when ACAO dynamically reflects `Origin` (web cache poisoning / cross-origin cache deception risk) |

### 2.5 Complementary Browser Isolation Headers (v1 Scope Boundary)

Modern OWASP Secure Headers guidance also tracks:
- `Referrer-Policy` (`strict-origin-when-cross-origin` or `no-referrer`; flag explicit
  `unsafe-url` on authenticated pages because it leaks full URL paths/query strings cross-origin).
- `Cross-Origin-Opener-Policy` (`same-origin` — prevents `window.opener` cross-window leaks).
- `Cross-Origin-Resource-Policy` (`same-origin` / `same-site`).
- `Permissions-Policy` (restricting `camera=()`, `microphone=()`, `geolocation=()`).

**ParTEx v1 recommendation:** Keep `header-security` focused on the five high-signal classes
in `PLAN.md` §10 (HSTS, CSP, `X-Content-Type-Options`, `Set-Cookie`, CORS) so M1–M3 fixture
outputs stay crisp and deterministic; if `Referrer-Policy: unsafe-url` is added later, route
URL-token leakage through `session-cookie-config` (`auth-session-controls`).

---

## 3. Implementation Refinements Identified for `header_security.py`

Comparing current `src/partex/checks/header_security.py` against the research above highlights
targeted hardening opportunities when extending the P0 fixture (`PARTX_SKILL_PLAN.md` §4):

1. **Wire-order header pairs & case-insensitive helpers (addressed in #39):** HTTP header
   field names are case-insensitive (RFC 9110 §5.1) and responses often emit multiple
   `Set-Cookie` or `Content-Security-Policy` headers; using wire-order `(name, value)` pairs
   with case-insensitive `get_header` / `get_all` preserves repeated `Set-Cookie` lines and
   handles lowercase HTTP/2 captures (`import-har`, browser harness).
2. **CSP3 `'strict-dynamic'` + nonce/hash awareness:** Update `_check_csp` so
   `'unsafe-inline'` is not flagged when paired with `'nonce-...'`/`'sha256-...'` and
   `'strict-dynamic'`, while checking `object-src` and `base-uri` when nonces are used.
3. **CSRF cookie `HttpOnly` carve-out & `__Host-`/`__Secure-` checks:** Exempt explicit
   double-submit CSRF cookie names (`csrf`, `xsrf`) from the `HttpOnly` requirement (still
   requiring `Secure` and `SameSite`), and validate `__Host-` / `__Secure-` / `Partitioned`
   invariants.
4. **Bodyless `3xx` redirect handling:** Skip `X-Content-Type-Options: nosniff` and `CSP`
   findings on `3xx` redirect stubs without HTML bodies, per `skills/header-review/SKILL.md`.

---

## 4. Fixture Triad Design (`fixtures/bundles/` & `fixtures/skills/header-review/`)

1. **Clean case:**
   - HTTPS `200 text/html` with `Strict-Transport-Security: max-age=31536000; includeSubDomains`,
     enforcing CSP (`default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'`),
     `X-Content-Type-Options: nosniff`, and `__Host-session=<redacted>; Secure; HttpOnly; SameSite=Lax; Path=/`.
   - HTTPS `200 application/json` with HSTS and `X-Content-Type-Options: nosniff` (no CSP
     required → zero findings).
   - HTTPS `302 Found` redirect with HSTS (no CSP / no `nosniff` required → zero findings).
2. **Violation cases (one exchange per class):**
   - Missing/short HSTS (`max-age=60` and `max-age=0`).
   - Missing CSP and unsafe CSP (`script-src 'self' 'unsafe-inline'` without nonce/`strict-dynamic`),
     contrasted with a **compliant** CSP3 `'nonce-abc' 'strict-dynamic'` policy.
   - Missing `X-Content-Type-Options` on `200` HTML/JSON responses.
   - Session cookie missing `HttpOnly`/`Secure`/`SameSite`, plus broken `__Host-` cookie with
     `Domain=example.test`.
   - CORS `Access-Control-Allow-Origin: null` + `Access-Control-Allow-Credentials: true`.
3. **Insufficient-evidence / inapplicable cases:**
   - Plain `http://` `301` redirect to `https://` (HSTS inapplicable on the `http://` hop).
   - `body_refused` / missing `Content-Type` stub exchange.
