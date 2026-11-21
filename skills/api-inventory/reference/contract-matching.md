# OpenAPI Contract Matching and Inventory Rules

> Provenance: condensed from `strix/strix/skills/custom/api_spec_testing.md` (OpenAPI
> `$ref`/`allOf` traversal and implied-method checks) and
> `communitytools/skills/api-security/SKILL.md` (normalized operation templates). The
> declared-vs.-observed split originates in `PARTX_SKILL_PLAN.md` §4 (P1.1), not in
> third-party skill text.

## 1. Contract Ingestion and Schema Resolution (`ConfigExcerpt`)

- Load `ConfigEvidence` items where `config.format == "openapi"` (OpenAPI `3.0.x` and
  `3.1.x`, JSON or YAML). Unsupported versions (e.g. Swagger `2.0`) or malformed excerpts
  record `not_applicable` (`insufficient evidence`) rather than failing the run.
- Carry `config.revision` (falling back to `info.version` when unset) onto findings,
  coverage rows, and `surface_nodes` metadata.
- Resolve `servers[].url` path prefixes (substituting `servers[].variables.*.default` when
  declared) ahead of `paths` templates.
- Resolve local JSON Pointer `#/...` `$ref`s (including OpenAPI 3.1 `$ref` sibling keyword
  merging and cycle guards), `allOf` property unions, `oneOf`/`anyOf` variants, and
  nullable unions (`nullable: true` or `type: ["string", "null"]`).
- If an external or missing `$ref` cannot be resolved offline, mark that operation's
  schema check as `not_applicable` (`insufficient evidence: unresolvable $ref ...`) rather
  than failing or claiming conformance.

## 2. Path-Template Normalization

1. Strip query strings and fragments before path-template matching; record query parameter
   **names** (never values) on `surface_nodes` metadata.
2. Decode RFC 3986 unreserved percent-escapes while preserving `%2F` inside segments so an
   encoded slash inside a path parameter stays a single segment.
3. Match concrete captured paths (e.g. `GET /api/v2/users/42`) against the most specific
   OpenAPI path template using segment-by-segment precedence: exact static segment
   (`/users/me`) > mixed literal+parameter segment (`/files/{name}.json`) > pure parameter
   segment (`/users/{id}`).
4. On unmatched observed routes, collapse numeric, UUID, and long-hex segments to `{id}`
   while keeping static and single-endpoint paths (`POST /graphql`, `/rpc`) intact.
5. Emit the normalized operation key (`GET /api/v2/users/{id}`) in `surface_nodes.key`,
   `Finding.subject` (`op:<key>`), and finding titles (`fn_*` cites HTTP exchange `ev_*`
   IDs so finding IDs survive bundle revisions and OpenAPI route reordering).

## 3. Drift, Guardrails, and Excessive Data Exposure Rules

- **Method mismatch / shadow route (`OWASP API9:2023`, `medium`):** Flag when an observed
  `(method, path)` matches no declared operation in the loaded `openapi` excerpt
  (including legacy version prefixes such as `/api/v1/` when only `/api/v2/` is declared,
  or undeclared methods on a declared path template).
- **False-positive guardrails:** Ignore `404` probe misses, `405` rejections on declared
  path templates, `OPTIONS` CORS preflights, and `2xx`/`3xx` `GET`/`HEAD` HTML document
  navigations (`text/html`) outside API prefixes so browser page loads and scanner misses
  are not misreported as shadow API endpoints.
- **Undeclared or sensitive response fields (`OWASP API3:2023`, `medium` / `high`):**
  When a `2xx` JSON response schema sets `additionalProperties: false`,
  `unevaluatedProperties: false`, or an explicit `properties` map, flag undeclared
  property paths (`medium`), escalating credential, secret, PII, or privilege names
  (`password_hash`, `secret`, `token`, `api_key`, `is_admin`, `role`, `ssn`, etc.) to
  `high`. High-confidence credential/PII leaks (`password_hash`, `private_key`,
  `mfa_secret`, `ssn`, etc.) are flagged (`high`) even on open-map schemas.
- **Sensitive-value exclusion:** Report only JSON property paths (`$.user.password_hash`,
  `$[*].api_secret`) and `ev_*` IDs — never observed field values.

## 4. Coverage Matrix Linkage

- Unobserved declared operation → `outcome: needs_follow_up` (`source: check_observed`,
  `reason: "unobserved in bundle ..."`), feeding downstream active probing
  (`authorization-testing`, `auth-session-controls`).
- Observed operation with only non-`2xx` responses when a `2xx` schema is declared →
  `outcome: needs_follow_up` (`no 2xx response captured to verify response schema`).
- Missing OpenAPI contract or unresolvable `$ref` → `outcome: not_applicable`
  (`insufficient evidence: ...`).
- Never emit a vulnerability finding solely because a declared endpoint was not captured.
