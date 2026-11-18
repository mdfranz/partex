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

## Scope and Evidence Model

- **Passive only.** Operates strictly over registered `HttpEvidence` and `ConfigEvidence`
  records in the run. Do not issue live probes or crawl endpoints from this skill.
- **Single-endpoint protocols (GraphQL, RPC).** A GraphQL or RPC surface collapses to a
  single normalized operation key (e.g. `POST /graphql`) in v1; per-query/per-mutation
  decomposition into distinct operations is **out of scope**. Do not invent synthetic
  operation keys for individual queries — record the endpoint once as a coverage row.
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
| Conforming operation | Observed `HttpExchange` matches declared path template, method, status, and allowed response fields | No finding; mark `no_issue_found` in `CoverageEntry` |
| Undocumented / shadow operation | Observed `HttpExchange` has no matching path or method in the declared OpenAPI spec | `medium` finding (OWASP API9:2023 Improper Inventory Management) |
| Disallowed / excessive response fields | Response JSON includes sensitive or undeclared properties beyond the contract DTO schema | `medium` / `high` finding (OWASP API3:2023 Broken Object Property Level Authorization) |
| Unobserved declared operation | Operation exists in `ConfigExcerpt` (`format: openapi`) with zero matching `HttpExchange` captures | **Coverage gap** (`needs_follow_up`), not a vulnerability finding |
| No contract in bundle | Bundle contains `HttpExchange` records but zero `format: openapi` `ConfigExcerpt`s | **Insufficient evidence**; distinguish from conformance or drift |

## Secret and PII Redaction

- Never copy field values (tokens, passwords, emails, account numbers, or `secret_fields`)
  into finding `title`, `description`, or `CoverageEntry` records. Cite only JSON property
  **paths** (e.g. `$.user.password_hash`) and `ev_*` IDs.

Consult [contract-matching.md](reference/contract-matching.md) for path-template matching,
schema resolution, and coverage-matrix rules.
