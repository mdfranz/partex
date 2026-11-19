# Research: `api-inventory` (`api-contract-conformance`)

- **Priority / Slice:** P1.1 — First post-M6 integration slice (S1, `PARTX_SKILL_PLAN.md` §4)
- **Skill Path:** `skills/api-inventory/SKILL.md` (`reference/contract-matching.md`)
- **Check ID & Protocol:** `api-contract-conformance` (`PassiveCheck` over `HttpEvidence` + `ConfigEvidence` with `format: "openapi"`)
- **Engine Dependency Decision (`DEPS.md` §3.1):** Minimal in-package OpenAPI/JSON-Schema resolver (~300–500 lines of Python stdlib + `pyyaml`), zero new PyPI dependencies.
- **Standards & References:**
  - OpenAPI Specification (OAS) v3.0.3 & v3.1.0
  - JSON Schema Draft 2020-12 (`properties`, `additionalProperties`, `unevaluatedProperties`, `allOf`, `$ref`)
  - IETF RFC 6570 (URI Template) & OAS Path Templating rules
  - IETF RFC 8594 (`Sunset` header) & RFC 9745 (`Deprecation` header)
  - OWASP API Security Top 10 (2023): `API9:2023` (Improper Inventory Management) & `API3:2023` (Broken Object Property Level Authorization — read-side Excessive Data Exposure)
  - CWE-1059 (Insufficient Technical Documentation), CWE-213 (Exposure of Sensitive Information Due to Incompatible Policies)

---

## 1. Architectural Role in ParTEx

`api-inventory` is sequenced first in P1 (`PARTX_SKILL_PLAN.md` §4) because every downstream
API check (`authorization-testing` in S2, `auth-session-controls` in S3, `gateway-policy` in
S5) depends on **canonical operation keys** and **declared-vs-observed surface nodes**
(`surface_nodes` / `surface_edges` + `coverage_entries` in `PLAN.md` §7 & §12).

Inputs in a passive bundle or live capture store:
- **Declared surface:** One or more `ConfigEvidence` items with `config.format == "openapi"`
  (JSON or YAML parsed via `yaml.safe_load`) and `config.revision` (git SHA, semver, or spec
  revision).
- **Observed surface:** Captured `HttpEvidence` items (`ev_*`) from `ScopedHttpClient`,
  `partex import-har` (M3), or `partex browse` (M7).

---

## 2. OpenAPI 3.0 vs. 3.1 Divergences for the In-Package Resolver

Per `DEPS.md` §3.1, `partex` implements a focused ~300–500 line resolver rather than pulling
in `openapi-core` or `jsonschema`. Research on real-world OpenAPI specs highlights five
exact differences between OAS 3.0.x and OAS 3.1.x that the check code must handle:

| Feature | OpenAPI 3.0.x | OpenAPI 3.1.x (JSON Schema 2020-12) | Check Resolver Strategy |
|---|---|---|---|
| **Version field** | `openapi: "3.0.0"` .. `"3.0.4"` | `openapi: "3.1.0"` / `"3.1.1"` | Accept `3.0.*` and `3.1.*`; reject Swagger `2.0` or mark insufficient evidence with clear reason |
| **Nullable types** | `type: string`, `nullable: true` | `type: ["string", "null"]` or `anyOf: [{type: string}, {type: "null"}]` | Treat `null` JSON values on optional/nullable properties as conforming; never flag `null` as an undeclared field |
| **`$ref` siblings** | Siblings next to `$ref` ignored in 3.0 | `$ref` can coexist with sibling keywords (`description`, `unevaluatedProperties`, etc.) | Resolve local JSON Pointer `#/...` first, then merge outer sibling object keys over resolved target (cycle-guarded with a `visited: frozenset[str]` set!) |
| **Base URL / server prefix** | `servers: [{url: "/api/v2"}]` or full URL `https://api.example.com/v2` | Same, with `servers[].variables` | Strip matching server base path prefix (`/v2` or `/api/v2`) before matching `paths` keys, or normalize full path `/api/v2/users/{id}` consistently |
| **Strict object closure** | `additionalProperties: false` (breaks naively across `allOf` branches if evaluated per-branch!) | `unevaluatedProperties: false` **or** `additionalProperties: false` | Collect the **union** of declared `properties` across all `allOf` subschemas (and matching `oneOf`/`anyOf` branches) before checking whether an observed response key is undeclared |

### Handling `allOf` + `additionalProperties: false` / `unevaluatedProperties: false`

A classic OpenAPI bug:
```yaml
UserPublic:
  allOf:
    - $ref: '#/components/schemas/BaseEntity'   # defines {id, created_at}
    - type: object
      properties:
        username: { type: string }
  unevaluatedProperties: false                  # (or additionalProperties: false on wrapper)
```
If our check merges `properties` across all resolved `allOf` items (`{id, created_at,
username}`), it handles **both** OAS 3.0 composition patterns and OAS 3.1
`unevaluatedProperties: false` cleanly in ~40 lines of recursive dict traversal!

### External `$ref` & Circular `$ref` Safety

- **External `$ref`** (`$ref: "./common.yaml#/..."` or `https://...`): Passive checks forbid
  filesystem and network I/O (`PLAN.md` §2). Immediately mark schema conformance for that
  operation as **insufficient evidence** (`skills/api-inventory/reference/contract-matching.md`
  §1) while still recording path/method inventory.
- **Circular `$ref`** (`Node -> children[] -> $ref: '#/components/schemas/Node'`): Track
  active pointer stack `(pointer, json_path_depth)` during response walking so recursive
  tree responses never trigger `RecursionError`.
- **YAML Bomb / Alias Guard:** `yaml.safe_load` parses YAML anchors/aliases; cap maximum
  excerpt size or node count during load so pathological YAML aliases cannot exhaust memory.

---

## 3. Deterministic Path-Template Matching & Specificity Algorithm

Per OpenAPI Specification §4.8.9 ("Path Templating Matching") and `PLAN.md` §12:

1. **Pre-normalization:**
   - Parse request URL path; strip `?query` and `#fragment`.
   - Percent-decode unreserved RFC 3986 characters (`%7E` → `~`, etc.) **without** decoding
     `%2F` (`/`) before segment splitting, because `%2F` inside a single path parameter
     segment (`GET /files/dir%2Fdoc.pdf` matching `/files/{slug}`) is one segment, not two!
   - Normalize trailing slash consistently (if `/users` is declared and `/users/` is
     observed, match `/users` unless `/users/` is separately declared).
2. **Segment-by-segment specificity score:**
   Split candidate template `T` and concrete path `P` on `/`. Require `len(T_segs) == len(P_segs)`
   (OpenAPI 3.0/3.1 path parameters match single segments, not multi-segment globs).
   For each segment `i`:
   - Static literal segment (`users`, `me`): matches iff `T_segs[i] == P_segs[i]`; contributes
     bit `2` at position `i`.
   - Mixed literal + template segment (`v{version}`, `{id}.json`): regex-anchored match;
     contributes bit `1` at position `i`.
   - Pure template segment (`{id}`): matches any non-empty segment; contributes bit `0` at
     position `i`.
3. **Precedence tie-breaking:**
   Sort matching templates descending by tuple `(score_seg_0, score_seg_1, ..., template_str)`.
   - `/users/me` `(2, 2)` strictly beats `/users/{id}` `(2, 0)`.
   - `/books/{id}` `(2, 0)` strictly beats `/{entity}/me` `(0, 2)` on left-to-right literal
     priority (and tie-breaks deterministically via `template_str` if structural ambiguity
     exists in a malformed spec).
4. **Canonical Operation Key (`PLAN.md` §12):**
   Always emit `<UPPER_METHOD> <full_normalized_path_template>` (e.g.
   `GET /api/v1/users/{id}`). Never include concrete IDs (`42`, UUIDs) in `FindingDraft.title`
   so `fn_*` content-hash IDs remain identical across runs and users.

---

## 4. Finding Classes vs. Coverage Dispositions

### 4.1 Shadow & Zombie Operations (OWASP API9:2023)

| Scenario | Classification | Severity / Disposition |
|---|---|---|
| Observed `2xx`/`3xx`/`401`/`403`/`5xx` exchange matches **no** declared path template in OpenAPI (excluding plain `404 Not Found` probe noise!) | **Shadow / Undocumented Endpoint** | `medium` finding (`API9:2023`) — note: filter out pure `404` scanner probe misses so `GET /partex-nonexistent-probe-*` returning `404` is not misclassified as a live shadow API! |
| Observed path matches a declared path template, but the HTTP method (`DELETE`, `PATCH`, `PUT`) is undeclared and returns `2xx` (not `405 Method Not Allowed`) | **Undocumented HTTP Method** | `medium` / `high` finding (`API9:2023` + `needs_follow_up` for `authz-boundary`) |
| Observed `2xx` traffic hits an older version prefix (`/api/v1/users`) while OpenAPI only declares `/api/v2/users`, or operation is marked `deprecated: true` in OpenAPI / carries `Sunset` (RFC 8594) past current date | **Zombie / Deprecated Active Endpoint** | `medium` finding (`API9:2023`) |
| Declared operation in OpenAPI has **zero** matching `HttpExchange`s in bundle | **Unobserved Declared Operation** | **Not a finding** → `CoverageEntry(outcome='needs_follow_up', reason='unobserved in bundle')` |

> **Critical false-positive guardrail (`404` & `OPTIONS`):**
> - An observed `GET /random-probe` that returned `404 Not Found` is proof the route *does
>   not* exist (unless it leaks a stack trace, handled by `version-disclosure`), **not** a
>   shadow API! Require non-404 status (`2xx`, `401`, `403`, `400`, `405`, `422`, `5xx`) to
>   register an undocumented operation.
> - Browser CORS preflight `OPTIONS` requests automatically accompany cross-origin `fetch()`
>   calls even when `options:` is omitted from OpenAPI YAML; do not flag `OPTIONS` preflights
>   as undocumented endpoints.

### 4.2 Excessive Data Exposure / BOPLA Read-Side (OWASP API3:2023)

Two complementary detection signals on `2xx` `application/json` responses matched to an
OpenAPI operation:

1. **Strict contract violation:** Schema sets `additionalProperties: false` or
   `unevaluatedProperties: false` (or explicit DTO `properties`), and the observed response
   contains undeclared JSON property paths (e.g. `$.data.internal_notes`).
   - Base severity: `low`/`medium` (contract drift), escalated to `high` when the undeclared
     key matches sensitive property patterns.
2. **High-signal sensitive-field exposure (even when `additionalProperties` is omitted!):**
   Many OpenAPI specs omit `additionalProperties: false` by default (JSON Schema defaults
   `additionalProperties` to `true`). If a response returns a property **absent** from the
   declared `properties` schema whose key matches high-risk secret/credential/privilege
   indicators:
   - Auth/credential hashes: `password`, `password_hash`, `passwd`, `hashed_password`,
     `salt`, `totp_secret`, `mfa_secret`, `private_key`, `api_secret`, `client_secret`,
     `refresh_token`, `session_token`
   - Sensitive PII / internal privilege flags (when undeclared in schema): `ssn`,
     `tax_id`, `credit_card`, `cvv`, `is_superadmin`, `internal_role`
   Flag as `high` (`OWASP API3:2023` Excessive Data Exposure) while recording **only** the
   JSONPath (`$.user.password_hash`) and `ev_*` ID — **never** the field value!

### 4.3 Single-Endpoint Protocols (GraphQL / JSON-RPC / gRPC-Web)

Per `skills/api-inventory/SKILL.md`:
- Collapse `POST /graphql` (or `/rpc`) into one normalized operation key in v1 rather than
  inventing synthetic operation keys from GraphQL ASTs.
- Record `POST /graphql` once in `surface_nodes` / `coverage_entries` so the agent or
  future GraphQL-specific check knows a GraphQL surface is present.

---

## 5. Fixture Triad Design (`fixtures/skills/api-inventory/`)

1. **Clean bundle:**
   - OpenAPI 3.1 `ConfigExcerpt` (`revision: "2026.11.1"`) declaring `GET /api/v2/users/me`,
     `GET /api/v2/users/{id}`, and `POST /api/v2/orders` (using `allOf` + `type: ["string", "null"]`
     + `unevaluatedProperties: false`).
   - Matching `200` `HttpExchange`s (plus a CORS `OPTIONS` preflight and a `404` probe on an
     unknown path) → **zero findings**, conforming operations marked `no_issue_found`, any
     unobserved declared op marked `needs_follow_up`.
2. **Finding cases:**
   - **Shadow / zombie endpoint:** `GET /api/v1/admin/export` returning `200` JSON when only
     `/api/v2/...` is in the OpenAPI contract (`medium`, `API9:2023`).
   - **Excessive data exposure (BOPLA):** `GET /api/v2/users/42` returning undeclared
     `password_hash` and `mfa_secret` fields (`high`, `API3:2023`), asserting normalized key
     `GET /api/v2/users/{id}` in title and **zero** secret values in exported JSON.
3. **Insufficient-evidence cases:**
   - Bundle with `HttpExchange`s and **zero** `format: "openapi"` `ConfigExcerpt`s.
   - OpenAPI `ConfigExcerpt` containing an unresolvable external `$ref: "./external.yaml#/User"`.
