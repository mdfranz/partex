# OpenAPI Contract Matching and Inventory Rules

> Provenance: condensed from `strix/strix/skills/custom/api_spec_testing.md` (OpenAPI
> `$ref`/`allOf` traversal and implied-method checks) and
> `communitytools/skills/api-security/SKILL.md` (normalized operation templates). The
> declared-vs.-observed split originates in `PARTX_SKILL_PLAN.md` §4 (P1.1), not in
> third-party skill text.

## 1. Contract Ingestion (`ConfigExcerpt`)

- Load `ConfigEvidence` items where `config.format == "openapi"`.
- Record `config.revision` (git SHA, semver, or spec version) on every finding and
  coverage row that cites the contract.
- Resolve local `$ref` and `allOf` compositions within the excerpt before comparing
  observed request/response shapes. If an external `$ref` cannot be resolved offline,
  mark that operation's schema check as insufficient evidence rather than failing.

## 2. Path-Template Normalization

1. Strip query strings before path-template matching; track query parameter names
   separately.
2. Match concrete captured paths (e.g. `GET /api/v1/users/42`) against the most specific
   OpenAPI path template (e.g. `GET /api/v1/users/{id}`).
3. Prefer exact static segments over parameterized segments (`/users/me` wins over
   `/users/{id}`).
4. Emit the normalized operation key (`GET /api/v1/users/{id}`) in `surface_nodes.key` and
   finding titles so `fn_*` hashes stay deterministic across runs.

## 3. Drift and Excessive Data Exposure Rules

- **Method mismatch / shadow route:** Flag when an observed `(method, path)` matches no
  declared operation in the loaded `openapi` excerpt (including legacy version prefixes
  such as `/api/v1/` when only `/api/v3/` is declared).
- **Undeclared or sensitive response fields:** When the contract specifies
  `additionalProperties: false` or an explicit `properties` list on a `2xx` JSON
  response, flag extra response keys — especially credential, secret, or internal-flag names
  (`password_hash`, `secret`, `token`, `is_admin`, `role`, `ssn`).
- **Sensitive-value exclusion:** Report only the schema path and property name; never
  embed observed field values in findings or exports.

## 4. Coverage Matrix Linkage

- Every declared operation with no matching `HttpExchange` in the bundle is recorded as
  `outcome: needs_follow_up` (`source: check_observed`, `reason: "unobserved in bundle"`)
  for downstream active testing (`authorization-testing`, `auth-session-controls`).
- Do not emit a vulnerability finding solely because a declared endpoint was not captured.
