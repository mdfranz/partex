# Version Disclosure Verification Criteria

Reference patterns and verdict rules for the `version-disclosure` active check and its
`verify_recipe` replay.

## 1. Version Banner Signatures (`WSTG-INFO-02`, `WSTG-INFO-08`, RFC 9110 §10.2.4, CWE-200)

Flag headers when they disclose **both** a product/runtime identifier and a version or
build token:

- `Server`: e.g. `Apache/2.4.57 (Ubuntu)`, `nginx/1.18.0`, `Werkzeug/3.0.1 Python/3.11.6`
- `X-Powered-By`: e.g. `PHP/8.1.2`, `Next.js 14.1.0`
- `X-AspNet-Version` / `X-AspNetMvc-Version` / `X-Generator`

Do not treat empty headers, stripped generic tokens (`Server: nginx`), or the HTTP protocol
version prefix in `Via: 1.1 varnish` (RFC 9110 §7.6.3) as software version leaks.

## 2. Stack Trace and Debug Page Signatures (`WSTG-ERRH-01`, RFC 9457, CWE-209)

Flag `4xx`/`5xx` error bodies containing any of:

- Language runtime tracebacks (`Traceback (most recent call last):`, `at java.lang.`,
  `System.NullReferenceException`, `Fatal error: ... in /var/www/`).
- Framework debug screens (Django `DEBUG = True` yellow page, Werkzeug interactive
  debugger, Rails `ActionController::RoutingError` with local paths).
- Absolute filesystem paths (`/home/`, `/var/www/`, `/app/`, `C:\inetpub\`).

Do **not** flag clean RFC 9457 (`application/problem+json`) client error payloads, structured
422 validation arrays, or bare default templates (`Whitelabel Error Page` without stack frames).

## 3. Replay Verdict Rules

| Replay Outcome | Verdict | Finding Status Transition |
|---|---|---|
| Same header key + matching version regex, or matching stack-trace marker | `confirmed` | `reported` → `verified` |
| HTTP response received, header stripped / genericized or clean custom error page returned | `not_reproduced` | `reported` → `verification_failed` |
| Transport error, timeout, or `max_requests` budget exhausted | `inconclusive` | remains `reported` |

Every `Verification` record (`vf_*`) must cite the newly captured `ev_*` exchange IDs in
`requests` and state the exact matched or missing signature in `detail` and
`counterevidence`.
