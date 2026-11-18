# Version Disclosure Verification Criteria

Reference patterns and verdict rules for the `version-disclosure` active check and its
`verify_recipe` replay.

## 1. Version Banner Signatures

Flag headers when they disclose **both** a product/runtime identifier and a version or
build token:

- `Server`: e.g. `Apache/2.4.57 (Ubuntu)`, `nginx/1.18.0`, `Werkzeug/3.0.1 Python/3.11.6`
- `X-Powered-By`: e.g. `PHP/8.1.2`, `Express`, `ASP.NET`
- `X-AspNet-Version` / `X-AspNetMvc-Version` / `X-Generator`

Do not treat empty headers or stripped generic tokens (`Server: nginx`) as version leaks.

## 2. Stack Trace and Debug Page Signatures

Flag `4xx`/`5xx` error bodies containing any of:

- Language runtime tracebacks (`Traceback (most recent call last):`, `at java.lang.`,
  `System.NullReferenceException`, `Fatal error: ... in /var/www/`).
- Framework debug screens (Django `DEBUG = True` yellow page, Werkzeug interactive
  debugger, Rails `ActionController::RoutingError` with local paths).
- Absolute filesystem paths (`/home/`, `/var/www/`, `/app/`, `C:\inetpub\`).

## 3. Replay Verdict Rules

| Replay Outcome | Verdict | Finding Status Transition |
|---|---|---|
| Same header key + matching version regex, or matching stack-trace marker | `confirmed` | `reported` → `verified` |
| HTTP response received, header stripped / genericized or clean custom error page returned | `not_reproduced` | `reported` → `verification_failed` |
| Transport error, timeout, or `max_requests` budget exhausted | `inconclusive` | remains `reported` |

Every `Verification` record (`vf_*`) must cite the newly captured `ev_*` exchange IDs in
`requests` and state the exact matched or missing signature in `detail` and
`counterevidence`.
