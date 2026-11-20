# Response Header Policy Reference

Detailed evaluation rules for the `header-security` passive check across HTML, API, and
redirect `HttpExchange` records.

## 1. HTTP Strict Transport Security (HSTS)

- **Applies to:** All `https://` responses (`2xx`, `3xx`, `4xx`, `5xx`). Not applicable
  to plain `http://` responses (unless evaluating an HTTP-to-HTTPS redirect chain, where
  the final HTTPS response carries the header).
- **Baseline:** `Strict-Transport-Security: max-age=31536000` (or `63072000` with
  `includeSubDomains`).
- **Violations:**
  - Header absent on an HTTPS response.
  - `max-age=0` (actively disables HSTS) or `max-age` below 1 year (`31536000`).
  - **Malformed max-age (#38):** a quoted value (`max-age="31536000"`) is valid and accepted;
    a missing or unparseable `max-age` is its own `Malformed HSTS max-age directive` finding,
    never treated as `max-age=0`.

## 2. Content Security Policy (CSP)

- **Applies to:** `2xx` HTML document responses (`text/html`, `application/xhtml+xml`).
  Inapplicable to `application/json` API responses and `3xx` redirects without HTML bodies.
- **Baseline:** Present `Content-Security-Policy` defining `default-src` / `script-src`
  without `'unsafe-inline'`, `'unsafe-eval'`, or scheme/host wildcards (`*`, `http:`), and
  restricting framing via `frame-ancestors 'none'` or `'self'`.
- **Precision (#38):**
  - `'unsafe-inline'` alongside a `'nonce-…'`/`'sha256-…'` source is ignored by CSP2+
    browsers — not a violation. `'unsafe-eval'` is still honored alongside nonces and stays
    one.
  - A full CSP3 fallback pattern (`'nonce-…' 'strict-dynamic' https:`) makes host-source
    wildcards legacy-only — not a violation.
- **Multiple enforced headers (#52):** browsers apply every enforced policy (intersection).
  A weakness counts only when **every** enforced header permits it; framing counts as
  CSP-controlled only when every header defines `frame-ancestors`.
- **Report-only (#52):** `Content-Security-Policy-Report-Only` never enforces. A weakness
  that exists only in a report-only policy is never reported as enforced; when the enforced
  policy is unsafe and a report-only policy removes the weakness, the finding says a
  stricter report-only policy is deployed but not enforced.
- **Violations:**
  - Header absent on an HTML response.
  - `script-src` or `default-src` permits `'unsafe-inline'`, `'unsafe-eval'`, or `*`
    (after the precision rules above).
  - `Content-Security-Policy-Report-Only` present without an enforcing policy (missing
    enforced CSP; note the unenforced report-only policy).

## 3. MIME Sniffing Protection

- **Applies to:** All `2xx` responses with a body (HTML, JSON, scripts, static assets).
- **Baseline:** `X-Content-Type-Options: nosniff`.
- **Violations:** Header absent or set to a value other than `nosniff`.

## 4. Cookie Attributes (`Set-Cookie`)

- **Applies to:** Any response emitting one or more `Set-Cookie` headers.
- **Baseline:** Cookies carrying session or authentication state require `Secure` (on
  HTTPS), `HttpOnly`, and `SameSite=Lax` or `SameSite=Strict` (`SameSite=None` requires
  `Secure`).
- **Redaction rule:** Record only the cookie **name** and missing/weak attribute flags in
  finding output. Never include the cookie value in `title`, `description`, or
  `remediation`.
- **Classification (#38):** match session-like names by whole name tokens (separators and
  camelCase boundaries; `__Secure-`/`__Host-` prefixes stripped) plus a curated classic-name
  list — `sid` inside `inside` or `user` inside `user_prefs` is not a session cookie.
  CSRF double-submit cookies (`csrf`/`xsrf` tokens) are security-relevant but legitimately
  JS-readable: `Secure`/`SameSite` apply, `HttpOnly` does not.
- **Boundary:** Attribute gaps are this check's finding class. Session semantics —
  classifying session-bearing cookies, tokens in URLs or `Referer`-exposed redirects,
  and probe-verified token lifecycle — belong to `auth-session-controls`
  (`session-cookie-config` / `token-weakness`); do not double-report attribute-only
  gaps when both checks run.

## 5. Cross-Origin Resource Sharing (CORS)

- **Applies to:** Responses containing `Access-Control-Allow-Origin` (ACAO).
- **Violations:**
  - `Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true`
    (browsers reject `*` + credentials, but server intent indicates misconfiguration;
    flag if reflected origin or wildcard is paired with credentials).
  - `Access-Control-Allow-Origin: null` with `Access-Control-Allow-Credentials: true`.
  - Dynamic reflection of an arbitrary `Origin` request header into ACAO alongside
    `Access-Control-Allow-Credentials: true`.
- **Compliant case:** `Access-Control-Allow-Origin: *` without credentials on explicitly
  public, unauthenticated static/API responses is acceptable; do not flag without
  credentialed or sensitive context.
- **Severity (#38):** the passive `*`/`null` + credentials pair is `medium` — browsers
  reject the literal combination; the genuinely exploitable reflected-origin variant needs
  an active probe to confirm.

## 6. Framing / Clickjacking Controls (#52)

- **Applies to:** `2xx` HTML document responses. Inapplicable to JSON APIs and `3xx`
  redirect stubs.
- **Baseline:** either `X-Frame-Options: DENY|SAMEORIGIN` **or** an enforced CSP
  `frame-ancestors` directive. `X-Frame-Options: ALLOW-FROM` is obsolete (ignored by modern
  browsers) and treated as absent, with the reason named in the finding.
- **Violations:**
  - **Missing framing policy** (`low`): neither control present on an HTML response.
  - **Weak frame-ancestors policy:** the enforced `frame-ancestors` permits —
    - `*` or a bare scheme source (`https:`) — `medium` (any site can frame);
    - any `http:` source, a loopback host (`localhost`, `127.0.0.1`, `[::1]`), or a
      wildcard subdomain of shared hosting (`*.pages.dev`, `*.vercel.app`, `*.netlify.app`,
      `*.github.io`, `*.herokuapp.com`, `*.web.app`, `*.azurewebsites.net` — the suffix
      list is data, extended as suffixes surface) — `low`.
- **Report-only:** a report-only `frame-ancestors` never counts as enforcement; when one is
  deployed alongside an unsafe enforced policy, the finding says so.
- **Source normalization:** explicit host sources are compared case-insensitively with
  trailing slashes and ports honored (`https://Partner.Example.com:8443/` is a normal
  explicit origin, not a finding).

## 7. Finding aggregation (#38)

- Findings aggregate **per host and issue class**: one finding per `(host, subject, title,
  variant)` with every affected evidence ID attached. A 500-exchange bundle yields one
  `Missing HSTS header` finding per host, not one per exchange.
- Cookie attribute gaps union across the affected responses (missing attributes are listed
  once); severity is `medium` when the union holds more than one missing attribute.
- Descriptions name the affected host and the count of captured responses; distinct
  weaknesses sharing a title (wildcard vs `null` CORS, different weak source lists) stay
  separate findings.
