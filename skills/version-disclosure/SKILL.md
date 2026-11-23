---
name: version-disclosure
description: >-
  Invoke during live engagements to probe for server or framework version banners and
  verbose error stack traces, and to verify findings via single-request replay.
modes:
  - active
checks:
  - version-disclosure
---

# Version and Error Disclosure Probing

Actively probe an authorized target through `ScopedHttpClient` for explicit software
version banners and unhandled exception details, then confirm each finding with a minimal
replayable `verify_recipe`.

**Standards:** OWASP WSTG v4.2 (`WSTG-INFO-02`, `WSTG-INFO-08`, `WSTG-ERRH-01`), RFC 9110
§10.2.4 (`Server`) & §7.6.3 (`Via`), RFC 9457 (`application/problem+json`), CWE-200,
CWE-209, CWE-497 (full citations and URLs in `docs/skills/version-disclosure.md`).

## Scope and Engagement Rules

- **Authorized live runs only.** All probes execute through the engagement-scoped target
  client (`--authorized` + valid `engagement.json` scope). Never bypass `Scope` host,
  path prefix, exclusion, or `max_rps` / `max_requests` limits.
- **Minimal probe set.** Do not fuzz or brute-force paths. Issue targeted baseline probes:
  1. `GET /` — inspect `Server`, `X-Powered-By`, `X-AspNet-Version`, and `X-Generator`
     headers on the root response.
  2. `GET /robots.txt` — check standard metadata responses for server/framework banners.
  3. `GET /partex-nonexistent-probe-0` — the check's fixed, deterministic token (stable
     paths keep evidence and finding IDs comparable across replays) — trigger a `404` or
     error handler to inspect default error pages for version strings, framework names, or
     stack traces.
- **Anchor under the engagement's scope (#80).** When the target sits deeper than the site
  root (e.g. `https://host/api/v1/`), probes anchor under the baseline capture's directory
  (`/api/v1/robots.txt`, `/api/v1/partex-nonexistent-probe-0`); a scope refusal falls back
  to the root path once and is then skipped cleanly — it never fails the run.
- **A clean error page is not the same as an untested one (#53).** The check records a coverage
  entry (`error-page-disclosure`, source `check_observed`) for the unknown-path probe: `reported`
  when the response exposed stack traces, `no_issue_found` when it reached a real error response
  without disclosure, and `not_applicable` when it did not exercise the error handler at all, either
  because the path returned `2xx` with the baseline's page (a catch-all / single-page-app route) or
  because the probe was refused by the engagement scope. Report `not_applicable` as "not tested", never
  as "clean"; a manual next step is an unknown path under an API prefix the app exposes.
- **One finding per banner.** The same `(header, banner value)` seen on several responses is
  one finding citing the primary evidence, not a finding per probe.

## Check Mapping (`version-disclosure`)

| Finding Class | Signal | Expected Severity |
|---|---|---|
| Product + version banner | Header (`Server`, `X-Powered-By`, etc.) includes explicit version digits (e.g. `nginx/1.24.0`, `Express`, `PHP/8.2.1`) | `low`; `X-Generator`-class CMS hints are `info` |
| Verbose error / stack trace | Error body exposes file paths, runtime stack frames, framework debug pages, or SQL fragments | `medium` |

- **Non-findings:** Generic product names without version numbers (e.g. `Server: cloudflare`
  or `Server: nginx` with no version) should be noted as `info` at most or omitted per
  policy; do not inflate severity without an explicit version or stack trace.

## Verification Protocol (`verify_recipe`)

Every `version-disclosure` finding must attach a single-request `verify_recipe` so
`partex verify <run-id> <finding-id>` can deterministically re-test the target:

1. Replay the exact `(method, path)` request that produced the banner or error page.
2. Compare the live `HttpExchange` against the original signature:
   - **`confirmed` (`verified`)**: the same header version token or stack-trace marker is
     observed in the replayed response.
   - **`not_reproduced` (`verification_failed`)**: the endpoint responds cleanly without
     the banner or stack trace (e.g. after server hardening).
   - **`inconclusive`**: the target is unreachable, rate-limited, or blocked by a gateway
     before the origin responds.
3. Never delete a finding on `verification_failed`; retain both the original `ev_*`
   capture and the `vf_*` verification record.

Consult [verification-criteria.md](reference/verification-criteria.md) for signature
patterns and verdict rules.
