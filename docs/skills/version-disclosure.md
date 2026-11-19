# Research: `version-disclosure` (`version-disclosure`)

- **Priority / Milestone:** P0 — Built-in active check + `verify_recipe` (M3 landed in `src/partex/checks/version_disclosure.py`; `PLAN.md` §10 & §13.4)
- **Skill Path:** `skills/version-disclosure/SKILL.md` (`reference/verification-criteria.md`)
- **Check ID & Protocol:** `version-disclosure` (`ActiveCheck` with single-request `verify_recipe`)
- **Standards & References:**
  - OWASP WSTG v4.2: `WSTG-INFO-02` (Fingerprint Web Server), `WSTG-INFO-08` (Fingerprint Web Application Framework), `WSTG-ERRH-01` (Improper Error Handling), `WSTG-ERRH-02` (Testing for Stack Traces)
  - IETF RFC 9110 §10.2.4 (`Server` header — advises against needlessly detailed product/version info) & §7.6.3 (`Via` header)
  - IETF RFC 9457 (Problem Details for HTTP APIs — §5 Security Considerations)
  - CWE-200 (Exposure of Sensitive Information), CWE-209 (Generation of Error Message Containing Sensitive Information), CWE-497 (Exposure of Sensitive System Information)

---

## 1. Threat Model & Signal Calibration

Information disclosure checks fail in two opposite ways in traditional scanners:
1. **Over-reporting benign product tokens:** Flagging `Server: cloudflare`, `Server: nginx`,
   or `Server: AmazonS3` with no version numbers creates low-value noise that operators
   ignore.
2. **Confusing structured API validation errors with unhandled debug leaks:** Modern REST
   APIs (FastAPI/Pydantic `422`, RFC 9457 `application/problem+json`, GraphQL `errors`
   arrays without stack traces) intentionally return machine-readable client error details.

`version-disclosure` separates findings into two calibrated classes:
- **Class A — Explicit Version Banner (`low` / `info`):** Response header or default server
  footer discloses a product identifier **paired with explicit version/release digits** (e.g.
  `nginx/1.24.0`, `Apache/2.4.57 (Ubuntu)`, `PHP/8.2.15`, `Werkzeug/3.0.1 Python/3.12.2`,
  `Microsoft-IIS/10.0`, `X-AspNet-Version: 4.0.30319`).
- **Class B — Verbose Error / Stack Trace / Debug Page (`medium`, or `high` if interactive debugger/env dump exposed):**
  Error response body exposes runtime stack frames, internal filesystem paths, SQL query
  fragments, environment/config dumps, or interactive developer debug consoles.

---

## 2. Response Header Taxonomy

Inspect headers case-insensitively across both already-captured baseline `HttpExchange`s and
the check's targeted active probes:

| Header | Example Leaky Value | Non-Leaky / Generic Value (Skip or Info-only) |
|---|---|---|
| `Server` | `Apache/2.4.58 (Debian)`, `nginx/1.25.3`, `Werkzeug/3.0.1 Python/3.12.1`, `gunicorn/21.2.0`, `Jetty(11.0.18)`, `Kestrel` (no digits → skip) | `nginx`, `cloudflare`, `envoy`, `AkamaiGHost` |
| `X-Powered-By` | `PHP/8.3.2`, `ASP.NET` (with `X-AspNet-Version`), `Servlet/5.0 JSP/3.0`, `Next.js 14.1.0`, `Phusion Passenger(R) 6.0.20` | `Express` (framework fingerprint without version — `info` at most unless paired with stack trace) |
| `X-AspNet-Version` / `X-AspNetMvc-Version` | `4.0.30319` / `5.2` | Always version-bearing when present |
| `X-Generator` | `Drupal 10 (https://www.drupal.org)`, `WordPress 6.4.3` | Generic CMS name without major/minor digits |
| `Via` | `1.1 varnish (Varnish/7.4)`, `1.1 squid/5.7` | `1.1 google`, `1.1 vegur`, `1.1 varnish` (protocol version `1.1` is the **HTTP** version per RFC 9110 §7.6.3 — **never** confuse `Via: 1.1 proxy` with proxy software v1.1!) |
| `X-Runtime` / `Server-Timing` | Rarely version-bearing, occasionally includes runtime/DB engine tags | Timing metrics (`db;dur=12.3`) are **not** version leaks |

> **False-positive guardrail (`Via` header):** In `Via: 1.1 varnish` or
> `Via: HTTP/1.1 edge-proxy`, `1.1` is the upstream HTTP protocol version, **not** software
> version `1.1`. Only flag `Via` when a parenthesized comment or product slash token carries
> an explicit software version (`Varnish/7.4`, `squid/5.7`).

---

## 3. Framework Stack Trace & Debug Page Signatures

Active probe #3 (`GET /partex-nonexistent-probe-<token>`) and captured `4xx`/`5xx` exchanges
should match high-precision signatures across major web stacks:

| Ecosystem / Framework | High-Confidence Body Signatures | Severity Escalation Note |
|---|---|---|
| **Python (stdlib / Flask / Werkzeug / FastAPI)** | `Traceback (most recent call last):`, `File "/..."`, `werkzeug.exceptions.`, `This is an interactive debug console` (Werkzeug debugger) | Interactive Werkzeug console (`__debugger__=yes`) is `high`/`critical` (potential RCE if PIN bypassed/absent) |
| **Python (Django `DEBUG=True`)** | `You're seeing this error because you have <code>DEBUG = True</code> in your Django settings file`, `Request information` + `SETTINGS_MODULE` | `medium`/`high` — leaks full URLconf or env/settings on 404/500 |
| **Java / JVM (Spring Boot, Tomcat, Jetty)** | `at java.lang.`, `at org.springframework.`, `javax.servlet.ServletException`, `jakarta.servlet.ServletException`, Apache Tomcat footer `<h3>Apache Tomcat/10.1.x</h3>` | Plain Spring `Whitelabel Error Page` *without* `trace` field or version footer is just a default 404/500 template (`info` at most); with `"trace": "java.lang..."` (`server.error.include-stacktrace=always`) it is `medium` |
| **Node.js (Express, Fastify, Next.js, Koa)** | `ReferenceError:` / `TypeError:` / `SyntaxError:` followed by `\n    at ... (/app/...:\d+:\d+)`, `webpack-internal:///`, `__NEXT_DATA__` containing `"err":{"name":...,"stack":...}` | `medium` |
| **PHP (Core, Laravel Ignition/Flare, Symfony)** | `Fatal error: Uncaught`, `Stack trace:\n#0 /var/www/`, `Illuminate\Routing\Exceptions\`, `window.ignite(` (Laravel Ignition `APP_DEBUG=true`), Symfony Profiler `sf-toolbar` | Laravel Ignition (`APP_DEBUG=true`) exposes env/context tabs (`high`) |
| **Ruby on Rails** | `ActionController::RoutingError`, `Rails.root:`, `Application Trace | Framework Trace | Full Trace` | Exposes full route table on 404 in development mode (`medium`) |
| **.NET / ASP.NET** | `Server Error in '/' Application`, `Stack Trace:`, `System.NullReferenceException`, `Version Information: Microsoft .NET Framework Version:` | Combines stack trace + exact CLR/ASP.NET build (`medium`) |
| **Go (`net/http`, Gin, Echo)** | `goroutine \d+ \[running\]:`, `runtime/debug.Stack`, `/go/pkg/mod/` source paths | `medium` |
| **SQL / Database Errors** | `SQLSTATE[`, `ORA-\d{5}:`, `PSQLException:`, `sqlite3.OperationalError:`, `You have an error in your SQL syntax` | `medium` (also signals potential injection surface for downstream review) |

### RFC 9457 (`application/problem+json`) Evaluation Rule

Per RFC 9457 §5, structured API errors returning `type`, `title`, `status`, `detail`, and
`instance` are **safe by design** when `detail` describes client-actionable conditions (e.g.
`"Your current balance is 30, but that costs 50"`).

- **Do NOT flag:** Clean RFC 9457 responses or FastAPI/Pydantic `422` validation arrays
  (`{"detail": [{"loc": ["query", "limit"], "msg": "Input should be a valid integer"}]}`).
- **DO flag:** RFC 9457 or JSON error bodies that embed stack traces (`"trace"`, `"stack"`,
  `"exception"`), absolute server paths (`/var/www/`, `/app/src/`, `C:\inetpub\`), or raw
  SQL/driver exceptions inside `detail` or extension fields.

---

## 4. Active Probing Strategy & Budget Discipline

Per `skills/version-disclosure/SKILL.md` and `PLAN.md` §10, `version-disclosure.probe()`
issues a **strictly bounded 3-request probe set** through `ScopedHttpClient`:

1. `GET /` — baseline origin and framework headers.
2. `GET /robots.txt` — static/metadata handler (often served directly by Nginx/Apache/CDN
   bypassing app middleware that strips `Server`, or conversely revealing distinct backend
   routing).
3. `GET /partex-nonexistent-probe-<run-deterministic-or-random-suffix>` (or with `Accept:
   text/html` vs `Accept: application/json`) — triggers the target's `404` handler to catch
   Django `DEBUG=True` route dumps, Rails `RoutingError`, Tomcat version footers, or
   unhandled error middleware.

**Scope & exclusion safety:**
- Before sending any probe, check `Scope` or handle `ScopeViolation` cleanly if an
  engagement scopes `path_prefixes` narrower than `/` (e.g. `/api/v1/` only — in that case,
  anchor probes under the first allowed `path_prefix`, e.g. `/api/v1/` and
  `/api/v1/partex-nonexistent-probe-...`!). This avoids burning refusals when an API
  engagement restricts `path_prefixes: ["/api"]`.
- Deduplicate findings by `(header_name, banner_value)` or `(signature_class, normalized_route)`
  across the 3 probes so `Server: nginx/1.24.0` appearing on all three responses emits
  **one** finding citing the primary `ev_*` (or sorted `ev_*` set) rather than three noisy
  duplicates.

---

## 5. Deterministic `verify_recipe` & Replay State Machine

`verify_recipe(finding)` returns a single-request `VerificationRecipe` replaying the exact
`(method, path, headers)` that triggered the finding:

| Replay Observation | Verdict | Finding Status Transition | `Verification` Record Notes |
|---|---|---|---|
| Replayed response status received **and** same version regex (`Server: nginx/1.24.0`) or stack-trace marker present | `confirmed` | `reported` → `verified` | Attach new `ev_*` ID; record matched token in `detail` |
| Replayed response received cleanly, banner removed/genericized (`Server: nginx`) or custom clean 404/500 body returned | `not_reproduced` | `reported` → `verification_failed` | Record observed header/status as `counterevidence`; original finding stays persisted (`PLAN.md` §13.4) |
| Network error, timeout, `429` / `503` gateway block, or `BudgetExhausted` | `inconclusive` | stays `reported` | Never mark `verification_failed` when origin did not answer |

---

## 6. Fixture Target App & Test Cases (`PLAN.md` §13.4)

1. **Vulnerable fixture app (`fixtures/target_app/`):**
   - Emits `Server: PartexFixture/0.1.0 Python/3.14` (or configurable version banner).
   - Unknown path `/partex-nonexistent-probe-*` or error route returns a verbose traceback
     body with internal file frame markers.
   - Live `test` → `verify` transitions both findings from `reported` to `verified`
     (`confirmed`).
2. **Hardened variant (`fixtures/target_app/` toggle):**
   - Strips version digits (`Server: PartexFixture`) and returns generic `{"error": "not found"}`.
   - Re-running `partex verify <run-id> <finding-id>` yields `not_reproduced` →
     `verification_failed` while preserving original `ev_*` and `fn_*` rows.
3. **Narrow `path_prefixes` engagement case:**
   - Engagement scoped only to `path_prefixes: ["/api"]` ensures probes stay inside `/api/...`
     without tripping avoidable root-path `ScopeViolation`s.
