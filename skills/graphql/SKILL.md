---
name: graphql
description: >-
  Invoke when the target exposes a GraphQL endpoint: probe introspection,
  field suggestions, federation subgraphs, and CSRF protections; test
  per-field, nested-edge, and per-mutation authorization with role-pair
  replay; and observe array batching, aliases, and depth limits without
  volume testing.
modes:
  - passive
  - active
checks: []
license: Apache-2.0
metadata:
  author: partex
---

# GraphQL Security Playbook

GraphQL collapses an entire API surface into a single endpoint (commonly `POST /graphql`,
`/api/graphql`, `/v1/graphql`, `/gql`, or `/query`), which `api-inventory` records once as
a single operation key — never invent synthetic operation keys per query. Authorization
lives in per-field and nested-edge resolvers, and GraphQL-over-HTTP routinely returns
HTTP `200 OK` even when authorization fails, so evaluation must inspect the JSON `data` /
`errors` envelope rather than HTTP status codes alone.

This playbook works within the existing tools: passive bundle/traffic harvesting,
role-pair replay with selection-set widening and nested/fragment checks, bounded
introspection/suggestion/federation and CSRF probes, and **observation** of batching and
depth controls — never volume or DoS testing.

## Passive first: harvest before probing

1. **Client bundle harvesting (`js-analysis`).** Harvest GraphQL operations from captured
   JS and HTML assets as **coverage leads** (never findings or synthetic operation keys) —
   see [js-analysis reference/analysis-rules.md](../js-analysis/reference/analysis-rules.md)
   §3 for rules covering raw strings and anonymous shorthand (`{ user { id } }`), compiled
   `graphql-tag` `DocumentNode` ASTs (`kind: "Document"`), Relay `ConcreteRequest`
   artifacts, SSR hydration stores (`__APOLLO_STATE__`, `__NEXT_DATA__`, `__URQL_DATA__`,
   `__RELAY_STORE__`), and persisted-query manifests.
2. **Observed exchanges (`ev_*`).** Inspect captured GraphQL exchanges for real endpoint
   paths, operation names, variable shapes, selection sets per engagement role, auth
   transport (`Authorization: Bearer` vs. session cookies), and exposed GraphQL IDEs
   (`/graphiql`, `/playground`, `/altair`, `/voyager`, Apollo Sandbox).
3. **Error & engine disclosure.** Verbose GraphQL errors (`errors[].extensions.exception`,
   stack traces, `extensions.tracing`, internal SQL/ORM fragments, `x-hasura-*` metadata)
   follow `server-error` / `version-disclosure` semantics — cite those findings rather than
   duplicating the class here.

## Per-field, nested-edge, and per-mutation authorization (BOLA / BOPLA / BFLA)

The [authorization-testing](../authorization-testing/SKILL.md) two-role rule applies per
query, nested edge, and mutation, not per HTTP route:

- **Never claim an access-control finding from a single response or HTTP `200` alone.**
  Every boundary crossing compares two `engagement.roles` handles (with optional
  unauthenticated control) and attaches a two-request `verify_recipe` citing both `ev_*`
  IDs. Apply GraphQL envelope guardrails
  ([reference/graphql-probing.md](reference/graphql-probing.md) §2):
  - **GraphQL soft-403:** HTTP `200 OK` with `{"data": {"user": null}, "errors": [...]}`
    (e.g., `FORBIDDEN` / `UNAUTHENTICATED`) is enforcement (`no_issue_found`).
  - **Token re-hydration & empty lists:** Verify Role B's response contains **Role A's
    distinct resource attributes**, not Role B's own record hydrated from session context
    and not an empty list (`[]`).
  - **Validation vs. execution partial data:** `"Cannot query field"` is a validation-phase
    rejection that aborts execution before resolvers run (no `data` key or HTTP `400`).
    Execution-phase partial data (`data` populated alongside `errors[].path`) confirms
    per-field enforcement only for the nulled field; inspect whether sibling fields leaked.
- **Cross-tenant argument replay & Relay `node(id)`.** Keep a captured query's shape and
  substitute Role A's object ID in variables (`user(id: $role_a_id)`), or replay Relay
  global object lookups (`node(id: "<base64_gid>")`, `nodes(ids: [...])`), which frequently
  bypass type-specific root authorization.
- **Selection-set widening, nested traversal, and inline fragments (OWASP API3 / API1).**
  Query an object under both roles adding sensitive fields authorized for Role A (or
  discovered via introspection/bundles) that Role B's UI omits:
  - Direct field widening (`user(id: $id) { email ssn internalNotes }`).
  - **Nested edge traversal** from a public or shared parent
    (`post(id: $public_id) { author { email } }`, Relay `.nodes` alongside `.edges`).
  - **Polymorphic inline fragments** (`... on AdminUser { apiKey }`) on interfaces/unions
    and on **mutation return selection sets**.
  Confirm Role A resolves the fields first (so schema drift is not misreported), then flag
  any field resolving with Role A's non-null data under Role B.
- **Per-mutation BFLA & input-object mass assignment (OWASP API5 / API3).** Replay
  privileged mutations under Role B, and test privilege/ownership fields in mutation
  `Input` objects (`updateUser(input: { role: "ADMIN" })`) **strictly on test-owned
  records** and through the write approval gate (first pass prefers read-only queries).
- **Unprobed operations are coverage gaps:** record `needs_follow_up` for harvested
  queries/mutations not replayed under a second role.

## Introspection, field suggestions, and federation exposure

Send bounded probes from [reference/graphql-probing.md](reference/graphql-probing.md) §1
unauthenticated and once per engagement role:

- **Introspection probe:** One `POST` with named `PartexIntrospectionProbe` requesting
  `__schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind } }`.
  If blocked by a gateway/WAF (not native server policy), send at most **one** bounded
  check for naive regex filters (`__type(name: "Query")` or `__schema\n{`).
  - **Finding wording:** `info`/`low` — schema exposure is reconnaissance input, often an
    accepted risk; never phrase as an exploit.
  - **Guardrails:** `403`/`404` or native policy disablement (`"introspection is disabled"`,
    GraphQL Shield/plugin errors) is `no_issue_found`. Non-production hosts stay separate
    coverage rows and never escalate production verdicts.
  - **APQ vs. Trusted Documents:** `"PersistedQueryNotFound"` on a hash-only request is an
    **Automatic Persisted Queries (APQ) cache miss**, **not** an allowlist (APQ accepts
    and caches arbitrary full `"query"` bodies on retry). Record a persisted-queries-only
    constraint **only** when a request containing full `"query"` text is rejected as
    unregistered/disallowed (`PersistedQueryOnly`, `PersistedQueryNotSupported`, or
    allowlist error).
- **Field suggestions ("Did you mean...?").** When introspection is disabled, send **one**
  benign invalid-field query (`PartexSuggestionProbe`) to observe whether validation errors
  leak real field names (the Clairvoyance schema-reconstruction vector). Record as
  `info`/`low` if suggestions appear; **never** run wordlist/dictionary brute-forcing.
- **Apollo Federation subgraphs.** When federation indicators appear (or on directly
  reachable internal/API hosts), send **one** `{ _service { sdl } }` probe: subgraphs
  expose `_service { sdl }` (full SDL) and `_entities` (direct BOLA bypassing router authz)
  even when `__schema` introspection is disabled. Direct exposure of a subgraph's
  `_service { sdl }` or `_entities` is `medium`/`high` depending on data/entity access.

## GraphQL CSRF (cookie-authenticated endpoints)

When observed GraphQL traffic authenticates via cookies (not solely `Authorization: Bearer`),
run at most **two read-only `{ __typename }` probes** without custom preflight headers
(`Apollo-Require-Preflight`, `X-Apollo-Operation-Name`):

1. `GET /graphql?query=%7B__typename%7D` (tests GET query acceptance; mutations over GET
   violate GraphQL-over-HTTP and bypass CSRF controls).
2. `POST /graphql` with `Content-Type: application/x-www-form-urlencoded` and body
   `query={__typename}` (tests whether browser-simple form POSTs bypass CORS preflight).

If accepted (`200 OK` with `__typename` data) on a cookie-authenticated endpoint lacking
anti-CSRF tokens or `SameSite=Strict` protection, record a CSRF finding (`medium`/`high`,
citing cookie/CORS state from `header-review` without duplicating header findings).

## Batching (array & alias) and deep queries: observe, never volume-test

- **Explicit no-DoS boundary:** No request storms, no depth-increment sweeps, no large
  alias/array counts, no persisted-query hash brute-forcing, no field-suggestion
  wordlists, and no websocket transport mutations.
- **HTTP JSON array batching (1 probe):** Send **one** 2-element benign array
  `[{"query": "query PartexBatch1 { __typename }"}, {"query": "query PartexBatch2 { __typename }"}]`.
  Array batching (`allowBatchedHttpRequests`) lets attackers pack OTP/login/coupon attempts
  into a single HTTP request and can trigger batch state/2FA races. Rejection (`400` /
  `"batching is not allowed"`) is `no_issue_found`; acceptance is an `info`/`low`
  observation (note: disabling array batching does **not** disable alias batching).
- **Alias batching (1 probe per role):** One small aliased read (`a1`..`a3` on a benign
  field). An alias-count/cost error is `no_issue_found`. Claiming a **rate-limit bypass**
  requires a documented per-request limit (config excerpt) or an observed refusal of the
  un-aliased form.
- **Depth / complexity (at most 1 moderately nested query per role):** An explicit depth
  or complexity error (`"query is too nested"`, cost/complexity limit metadata) is
  `no_issue_found`; no limit message is an `info`/`low` observation only.

## Guardrails

- Every request flows through `ScopedHttpClient` under engagement scope, budgets
  (`max_requests`, `max_rps`), and the write approval gate (mutations and input-object
  mass-assignment probes require explicit write approval and test-owned objects only).
- Minimal bounded probe budget per endpoint/role: 1 introspection (+1 bypass check only on
  WAF block), 1 suggestion check if introspection is disabled, 1 federation check when
  applicable, 2 read-only CSRF probes on cookie-auth targets, 1 role-pair replay per
  harvested query, 1 2-element array batch probe, 1 small alias probe, and 1 depth probe.
- Keep `POST` bodies intact in evidence; redact `secret_fields` and PII values in findings
  and tool output (cite field paths and `ev_*` IDs only).
