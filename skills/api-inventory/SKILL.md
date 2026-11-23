---
name: api-inventory
description: >-
  Invoke when building a normalized API operation inventory from captured HTTP exchanges
  and checking contract conformance against OpenAPI config excerpts.
modes:
  - passive
checks:
  - api-contract-conformance
license: Apache-2.0
metadata:
  author: partex
  derived_from:
    - strix/strix/skills/custom/api_spec_testing.md (Apache-2.0)
    - communitytools/skills/api-security/SKILL.md (MIT)
---

# API Surface Inventory and Contract Conformance

Construct a stable, normalized API operation inventory from captured `HttpExchange`
records and reconcile observed traffic against declared OpenAPI contracts (`ConfigExcerpt`
with `format: openapi` and `revision`).

**Standards:** OpenAPI Specification (OAS) 3.0.3 & 3.1.0 (§4.8.9 Path Templating Matching),
JSON Schema Draft 2020-12, RFC 6570 (URI Template), RFC 8594 (`Sunset`) & RFC 9745
(`Deprecation`), OWASP API3:2023 (BOPLA — read-side Excessive Data Exposure), OWASP API9:2023
(Improper Inventory Management), CWE-213, CWE-1059 (full citations and URLs in
`docs/skills/api-inventory.md`).

## Workflow

1. **Bundle review (`partex review` / `partex chat`):** Run `--checks api-contract-conformance`
   (or `--all`). Always inspect `list_coverage` alongside `list_findings`: a zero-finding
   run is **not** clean when coverage shows `needs_follow_up` (unobserved declared routes
   or missing `2xx` captures) or `not_applicable` (`insufficient evidence`).
2. **Live session (`partex agent` / `partex test`):** Fetching an OpenAPI `3.0.x` / `3.1.x`
   document (`2xx` `http_request` or `download_asset` within the bundle content and node
   caps) automatically registers a derived `ConfigEvidence(format='openapi')` (`source`
   citing the originating `ev_*` ID and URL; `revision` from `info.version` or body
   `sha256`). Invoke `run_check('api-contract-conformance')` after capturing the spec and
   any API exchanges, then inspect `list_coverage` for `needs_follow_up` operations. A live
   session that has not yet captured an OpenAPI 3.0/3.1 spec records `not_applicable`
   (`no OpenAPI contract (format: openapi) in bundle`).

## Scope and Evidence Model

- **Passive only.** Operates strictly over registered `HttpEvidence` and `ConfigEvidence`
  records in the run. Do not issue live probes or crawl endpoints from this skill.
- **Single-endpoint protocols (GraphQL, RPC).** A GraphQL or RPC surface collapses to a
  single normalized operation key (e.g. `POST /graphql`) in v1; per-query/per-mutation
  decomposition into distinct operations is **out of scope**. Do not invent synthetic
  operation keys for individual queries — record the endpoint once as a coverage row.
  GraphQL-specific probing (query-harvested coverage rows, per-field authorization,
  introspection) is the [`skills/graphql/`](../graphql/SKILL.md) playbook.
- **Declared vs. observed provenance.** Keep two surfaces distinct in every inventory:
  - *Declared*: operations defined in a `ConfigExcerpt` (`format: openapi`, citing
    `revision`).
  - *Observed*: operations reconstructed from `HttpExchange` captures (`ev_*`).
- **Normalized operation keys (`PLAN.md` §12).** Identify every matched operation by
  `METHOD /normalized/path/{param}` (uppercase HTTP method + OpenAPI path template),
  never by raw observed path with concrete IDs, so `fn_*` finding IDs remain stable across
  bundle revisions and route reordering.

## Check Mapping (`api-contract-conformance`)

| Outcome / Finding Class | Condition | Expected Disposition |
|---|---|---|
| Conforming operation | Observed `2xx` `HttpExchange` matches declared path template, method, and allowed response fields | No finding; `no_issue_found` in `CoverageEntry` |
| Undocumented / shadow operation | Observed non-`404`/`405` API exchange has no matching path or method in the OpenAPI spec (`OPTIONS` preflights, non-API HTML navigations, and the `2xx` `GET`/`HEAD` spec fetch itself excluded) | `medium` finding (OWASP API9:2023 Improper Inventory Management) + `reported` in `CoverageEntry` |
| Disallowed / excessive response fields | `2xx` JSON response includes undeclared or sensitive properties beyond the contract DTO schema | `medium` / `high` finding (OWASP API3:2023 Broken Object Property Level Authorization) + `reported` in `CoverageEntry` |
| Unobserved declared operation (or non-`2xx` only) | Operation exists in `ConfigExcerpt` with zero matching captures, or no `2xx` response exercised a declared response schema | **Coverage gap** (`needs_follow_up`), never a vulnerability finding |
| Insufficient evidence | Zero `format: openapi` `ConfigExcerpt`s in bundle, unsupported Swagger `2.0`, or unresolvable external/missing `$ref` | **Insufficient evidence** (`not_applicable` in `CoverageEntry`); distinguish from conformance or drift |

## Secret and PII Redaction

- Never copy field values (tokens, passwords, emails, account numbers, or `secret_fields`)
  into finding `title`, `description`, or `CoverageEntry` records. Cite only JSON property
  **paths** (e.g. `$.user.password_hash`, `$[*].api_secret`) and `ev_*` IDs.

Consult [contract-matching.md](reference/contract-matching.md) for path-template matching,
OpenAPI 3.0/3.1 schema resolution, shadow-route guardrails, and coverage-matrix rules.
