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

## 2. Content Security Policy (CSP)

- **Applies to:** `2xx` HTML document responses (`text/html`, `application/xhtml+xml`).
  Inapplicable to `application/json` API responses and `3xx` redirects without HTML bodies.
- **Baseline:** Present `Content-Security-Policy` defining `default-src` / `script-src`
  without `'unsafe-inline'`, `'unsafe-eval'`, or scheme/host wildcards (`*`, `http:`), and
  restricting framing via `frame-ancestors 'none'` or `'self'`.
- **Violations:**
  - Header absent on an HTML response.
  - `script-src` or `default-src` permits `'unsafe-inline'`, `'unsafe-eval'`, or `*`.
  - `Content-Security-Policy-Report-Only` present without an enforcing policy (note as
    report-only; does not enforce).

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
