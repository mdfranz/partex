# Research: `graphql` (GraphQL security playbook)

- **Priority / Slice:** Data-only playbook (issue #192); a deterministic check is a
  follow-up, not part of this slice.
- **Skill Path:** `skills/graphql/SKILL.md` (`reference/graphql-probing.md`)
- **Check ID & Protocol:** None yet (`checks: []`). The passive side is served today by
  `js-analysis` (query-literal harvesting) and `api-contract-conformance` (the single
  `POST /graphql` operation key); the active side by `authz-boundary` role-pair replay.
- **Standards & References:**
  - GraphQL specification — introspection system (`__schema`, `__Type`, `__typename`):
    the spec makes introspection a first-class feature; disabling it is a *policy*
    choice, which is why an exposed schema is an accepted-risk finding, not a flaw.
  - OWASP API Security Top 10 (2023): `API1:2023` (BOLA — per-resolver object level
    authorization), `API3:2023` (property-level authorization via selection sets),
    `API4:2023` (unlimited resource consumption — batching/aliases/depth).
  - OWASP WSTG-CONFIG (attack surface discovery: exposed schema) and the OWASP GraphQL
    Cheat Sheet (depth/complexity limits, introspection disablement, cost analysis).
  - Apollo persisted queries (APQ) and `__APOLLO_STATE__` hydration payloads as
    client-side query-mining sources.

---

## 1. Why a separate playbook (and what stays in the existing skills)

GraphQL breaks the per-route model the S1–S3 skills are built on: one HTTP route
(`POST /graphql`), one operation key, and authorization decided per *resolver field*.
The boundary decisions:

- `api-inventory` keeps the single `POST /graphql` operation key (v1 semantics
  unchanged). This playbook adds **query-harvested coverage rows** citing harvesting
  evidence — never synthetic operation keys per query/mutation.
- `authorization-testing` supplies the mandatory two-role rule, the
  `verify_recipe` protocol, and the `needs_follow_up` vocabulary; this skill applies
  them per query/mutation with selection-set widening as the GraphQL-specific probe
  class.
- `js-analysis` owns literal harvesting from bundles; this research doc records the
  false-positive rules for query literals (minified bundles, template fragments).
- `server-error` / `version-disclosure` keep error-message disclosure; GraphQL
  error arrays (`errors: [{path, extensions}]`) are a delivery mechanism for the same
  CWE-209 class.

## 2. The dominant flaw: per-field / per-mutation authorization

One endpoint, per-resolver authorization. The property-level attack (OWASP API3) is
unique to GraphQL's shape: the low-privilege client never requests the sensitive fields,
so route-level testing passes while `user(id: $other) { ssn }` resolves. Two probes:

1. **Cross-tenant argument replay** — identical request shape, substituted identifier
   (the BOLA pattern `authorization-testing/reference/role-pair-probing.md` §2 already
   defines, re-expressed in GraphQL variables).
2. **Selection-set widening** — add fields the public client shape never requests, under
   both roles. Disposition rules in `skills/graphql/reference/graphql-probing.md` §3:
   schema-level rejection (`Cannot query field`) is enforcement (`no_issue_found`);
   silent resolution for the low-privilege role is the finding.

## 3. Introspection: accepted risk, enforced by policy

An exposed `__schema` is reconnaissance input (info/low). Guardrails that keep the
signal honest:

- **Enforcement observed is a non-finding**: `403`/`404`, GraphQL Shield / plugin
  rejections, and persisted-queries-only endpoints that refuse free-form queries.
- **Non-production hosts do not escalate production verdicts** — staging introspection
  is a separate coverage row.
- **A named probe operation** (`PartexIntrospectionProbe`) lets a persisted-query
  gateway's refusal be distinguished from a transport error, and keeps evidence
  identifiable.

## 4. Resource consumption: observation, not DoS

API4-adjacent signals (alias batching, nesting depth, cost metadata) are measured with
single well-formed requests per depth class per role. The claim hierarchy:

| Evidence | Claim |
|---|---|
| A depth/cost limit message in a response | `no_issue_found` — a limit is present |
| No limit message on a moderately nested query | `info`/`low` observation: no per-request cost control evidenced |
| Aliased reply set exceeds a limit the un-aliased form trips | Corroborating evidence only; the bypass claim needs the documented limit (config excerpt) or an observed refusal |

Explicitly out of scope (per issue #192): volume/DoS testing, persisted-query ID
brute-forcing, websocket transport mutations.

## 5. Follow-up check sketch (not this issue)

A deterministic `graphql-config`-style `ActiveCheck` would own: the bounded introspection
probe (fixed query text, one per role), and a `PassiveCheck` side that consumes
`js-analysis`-harvested query literals into coverage rows. Role-pair replay of harvested
queries can ride the existing `authz-boundary` check once its operation-key model
understands harvested query names as replay targets. Until then this playbook's probes
run through the agent's scoped tools with this document as the wording contract.
