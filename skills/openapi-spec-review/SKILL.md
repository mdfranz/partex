---
name: openapi-spec-review
description: >-
  Invoke whenever an OpenAPI 3.0/3.1 specification is captured or supplied in a bundle to review
  spec-level authentication gaps, weak security schemes, internal server URLs, credential query
  parameters, sensitive response schema properties, unauthenticated spec exposure, and SSRF or
  open-redirect parameter leads.
modes:
  - passive
checks:
  - openapi-spec-review
---

# OpenAPI Specification Security Review

Passive review of `format: openapi` `ConfigEvidence` (supplied in a bundle or automatically derived
from live `2xx` captures). Emits at most **one finding per `(spec, rule)`**, citing JSON Pointer
paths and `ev_*` IDs, never observed values. Sends no network traffic.

## When to run

- After capturing an OpenAPI/Swagger JSON or YAML document during a live session (`run_check('openapi-spec-review')`),
  or during offline bundle review (`partex review --all` or `--checks openapi-spec-review`).
- Complements `api-contract-conformance`: `api-contract-conformance` reconciles live traffic against
  the spec, whereas `openapi-spec-review` audits issues visible in the spec itself.

## Check Mapping (`openapi-spec-review`)

| Rule (`subject` suffix) | Trigger | Severity | Reference |
|---|---|---|---|
| `no-auth-declared` | Spec declares operations under `#/paths` with no `#/components/securitySchemes` and no global or per-operation `security` (one finding per spec, never per operation). | `medium` if any `POST`/`PUT`/`PATCH`/`DELETE` operation exists; else `low` | OWASP API2:2023 |
| `weak-security-scheme` | `http basic`, `apiKey` in `query`, OAuth2 flow URLs over `http://`, or OpenID Connect discovery URL over `http://`. | `medium` | CWE-522, OWASP API2:2023 |
| `internal-server-url` | `servers` entry pointing to `localhost`, loopback/private IP, internal TLD (`.internal`, `.local`, `.corp`), or non-production host label (`dev`, `staging`, `qa`, `uat`, `sandbox`, `preprod`). | `low` | CWE-200 |
| `credential-query-param` | Query parameter whose name looks like a credential, token, API key, or secret. | `medium` | CWE-598 |
| `sensitive-response-property` | `2xx`/`default` JSON response schema declares sensitive property names (password/secret/token/SSN/private key/role/admin). | `high` for high-signal secrets; `medium` otherwise | OWASP API3:2023, CWE-200 |
| `unauthenticated-spec-exposure` | Live-captured `2xx` spec fetched without `Authorization` or `Cookie` headers from a production-looking host. | `low` | CWE-200 |
| Coverage lead (`needs_follow_up`) | Query, path, or header parameters named `url`, `callback`, `webhook`, `redirect`, `next`, `return_to`, etc. Recorded in `coverage` (`ssrf-or-open-redirect`), **not** as findings. | `needs_follow_up` | CWE-918, CWE-601 |

## Output Discipline

- Always cite JSON Pointer paths (`#/components/securitySchemes/...`, `#/servers/0/url`, `#/paths/...`)
  and `ev_*` IDs; never paste raw credential or response values.
- Treat `no-auth-declared` as a spec-level signal — verify whether endpoints actually enforce
  authentication at runtime before escalating severity.
- Follow up `ssrf-or-open-redirect` coverage leads only under explicit operator direction and within
  engagement scope.
