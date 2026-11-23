# Research: `graphql` (GraphQL security playbook)

- **Priority / Slice:** Data-only playbook (issue #192); a deterministic `graphql-config`
  check is a follow-up, not part of this slice.
- **Skill Path:** `skills/graphql/SKILL.md` (`reference/graphql-probing.md`)
- **Check ID & Protocol:** None yet (`checks: []`). Passive discovery rides on
  `js-analysis` (query/AST/manifest harvesting) and `api-contract-conformance` (single
  `POST /graphql` operation key); active authorization replay builds on `authz-boundary`
  two-role semantics.
- **Standards & References:**
  - **GraphQL Specification** (introspection `__schema` / `__type` / `__typename`,
    validation vs. execution phases, aliases, fragments, input objects) &
    **GraphQL-over-HTTP Specification** (`application/graphql-response+json`, `200 OK`
    partial-data and error envelopes, GET vs. POST semantics).
  - **OWASP WSTG v4.2:** `WSTG-APIT-01` (Testing GraphQL), `WSTG-ATHZ-01..04`
    (Authorization), `WSTG-SESS-05` (CSRF), `WSTG-ERRH-01/02` (Error Handling).
  - **OWASP API Security Top 10 (2023):** `API1:2023` (BOLA — per-resolver & nested-edge
    object authorization), `API3:2023` (BOPLA — read-side selection-set over-fetching and
    write-side input-object mass assignment), `API4:2023` (Unrestricted Resource
    Consumption — array batching, aliases, depth, fragment expansion), `API5:2023` (BFLA —
    per-mutation / admin operation authorization).
  - **OWASP GraphQL Cheat Sheet** & **PortSwigger Web Security Academy (GraphQL API
    Vulnerabilities)**: introspection/suggestion hardening, array & alias batching, CSRF,
    Trusted Documents / persisted-query safelisting, resolver-level authorization.
  - **CWEs:** CWE-639 (User-Controlled Key / BOLA), CWE-285 (Improper Authorization),
    CWE-200 (Schema/Information Exposure), CWE-209 (Error Message Disclosure), CWE-352
    (CSRF), CWE-400 (Uncontrolled Resource Consumption), CWE-915 (Mass Assignment).
  - **Ecosystem specifications & tooling studied:** Apollo Server (`csrfPrevention` /
    `Apollo-Require-Preflight`, `allowBatchedHttpRequests`, APQ vs. GraphOS Persisted
    Queries), Apollo Federation (`_service { sdl }`, `_entities`), Apollo Router
    fragment/directive enforcement, Relay Global Object Identification (`node(id)`),
    InQL, Clairvoyance, and GraphQL Cop.

---

## 1. Why a Separate Playbook (and Clean Boundaries with Existing Skills)

GraphQL breaks the per-route assumption behind S1–S3: one HTTP path (e.g. `POST /graphql`,
`/api/graphql`, `/v1/graphql`, `/gql`, `/query`) multiplexes reads, writes, nested graph
traversals, and polymorphic types, with authorization enforced per *resolver*. Boundaries:

- **`api-inventory`** keeps the single normalized operation key (`POST /graphql`) in v1.
  This playbook records harvested operations as **coverage rows** citing harvesting
  evidence — never synthetic operation keys.
- **`authorization-testing`** owns the mandatory two-role rule, two-request
  `verify_recipe`, soft-403 / token re-hydration / empty-collection anti-FP rules, and
  `needs_follow_up` vocabulary; this playbook adapts them to GraphQL's `200 OK` envelope,
  nested edges, Relay `node(id)`, inline fragments, and mutation input objects.
- **`js-analysis`** owns passive extraction from bundles and SSR payloads; this research
  doc and `skills/js-analysis/reference/analysis-rules.md` §3 define extraction across raw
  strings, compiled `DocumentNode` ASTs, Relay artifacts, and hydration stores.
- **`header-review`** owns raw `Set-Cookie` (`SameSite`, `Secure`, `HttpOnly`) and CORS
  policy findings; GraphQL CSRF checks here cite cookie/CORS posture without double-filing
  header findings.
- **`server-error` / `version-disclosure`** own CWE-209 error disclosure; GraphQL
  `errors[].extensions` (stack traces, tracing, SQL fragments) are a delivery channel for
  the same class.
- **P3 injection boundary:** Unsanitized GraphQL filter/argument objects cause severe
  real-world SQLi/RCE (e.g. Hasura `CVE-2021-47748`, WPGraphQL `CVE-2026-40762`, Strapi
  `CVE-2026-22599`, Mozilla Taskcluster HackerOne `#3782701`). Active injection fuzzing
  stays deferred to P3; this playbook only notes passive error indicators when observed.

---

## 2. Protocol Semantics & Four Failure Modes Naive GraphQL Scanners Hit

Research into GraphQL-over-HTTP and real server implementations (`graphql-js`, Apollo
Server, Graphene, Strawberry, HotChocolate, `graphql-ruby`, Hasura) exposes four recurring
scanner mistakes that this playbook must prevent:

### 2.1 The GraphQL "Soft 403" (`200 OK` Error Envelope)
Unlike REST, GraphQL servers routinely return **HTTP `200 OK`** when a resolver rejects
access:
```json
{
  "data": { "user": null },
  "errors": [
    { "message": "Not authorized", "path": ["user"], "extensions": { "code": "FORBIDDEN" } }
  ]
}
```
Checking only HTTP `2xx` vs. `401`/`403`/`404` causes massive false positives. Any BOLA or
BFLA verdict must parse the JSON body and verify non-null Role A resource data in `data`.

### 2.2 Validation Errors vs. Execution-Phase Partial Data
Per the GraphQL spec, `"Cannot query field \"ssn\" on type \"User\"."` is a **validation**
error that aborts execution *before any resolver runs* — returning `errors` with **no**
`data` key (or HTTP `400` under `application/graphql-response+json`). That is *not* partial
data. True **partial data** occurs during **execution** when one field's resolver fails
while sibling fields succeed:
```json
{
  "data": { "user": { "id": "101", "ssn": null } },
  "errors": [{ "message": "Forbidden", "path": ["user", "ssn"] }]
}
```
*(With non-nullable GraphQL fields `String!`, a field error bubbles up and nulls the parent
object.)* Checks must treat a nulled field with matching `errors[].path` as per-field
enforcement for that field, while still checking whether sibling fields leaked Role A data.

### 2.3 Token Re-hydration & Empty Collections (`authorization-testing.md` §1.2–1.3)
A query `user(id: $role_a_id)` replayed by Role B may return `200 OK` containing **Role B's
own profile** (resolver ignored `$id` and hydrated from `context.currentUser`) or
`{"data": {"invoices": []}}` (scoped SQL filter returned empty). Confirmation requires
Role A's baseline to return `>= 1` non-empty entity and Role B's replay to contain Role A's
distinct identity/attribute markers.

### 2.4 APQ (`PersistedQueryNotFound`) vs. Trusted Documents (Allowlisting)
**Automatic Persisted Queries (APQ)** is a *bandwidth and CDN caching optimization*, **not**
a security control:
- Client sends only `extensions.persistedQuery.sha256Hash`.
- On a cache miss, the server replies `PersistedQueryNotFound`.
- The client retries with **both** the hash and the full arbitrary `"query"` string, which
  the server caches and executes — offering **zero** allowlist enforcement.

By contrast, **Trusted Documents / Persisted Query Safelisting** (Apollo GraphOS Persisted
Queries, Relay persisted queries, Envelop persisted operations) pre-registers approved
hashes at build time and rejects free-form `"query"` bodies even when supplied
(`PersistedQueryOnly`, `PersistedQueryNotSupported`, or allowlist `400`/`403`). Treating
`PersistedQueryNotFound` on a hash-only request as an allowlist produces false negatives.

---

## 3. Dominant Real-World Flaw: Per-Resolver, Nested, & Mutation Authorization

Real-world GraphQL authorization bugs cluster into four distinct patterns beyond flat REST
BOLA:

1. **Direct & nested-edge BOLA (`API1:2023`, CWE-639):**
   Developers often guard the top-level query resolver while leaving nested relationships
   unguarded (e.g. `publicPost(id) { author { email } }`, relational filters in headless
   CMSs/engines like Hasura `CVE-2026-54698`, GitLab notes widget `CVE-2026-16275`, Saleor
   `order()` IDOR `CVE-2026-24136`, or Relay migrations exposing auto-generated `.nodes`
   arrays alongside custom-filtered `.edges`).
2. **Relay Global Object Identification (`node(id: ID!)` / `nodes(ids: [ID!]!)`):**
   A universal `node()` root field accepts opaque/base64 global IDs (`gid://app/User/123`).
   When `node()` dispatches directly to model loaders without per-type authorization, it
   bypasses type-specific root resolvers — as seen in **HackerOne `#1618347`**, where
   supplying internal global IDs to `node()` exposed private bug bounty program metadata.
3. **Selection-set widening, polymorphic inline fragments, & mutation return over-fetching
   (`API3:2023` read-side):**
   Low-privilege UIs simply omit privileged fields (`ssn`, `internalNotes`, `apiKey`),
   while the backend returns whole ORM records. Adding fields via direct widening or
   polymorphic inline fragments (`... on AdminUser { ... }`) bypasses checks attached only
   to base interfaces/root types (also seen in Apollo Router directive-composition flaws on
   interfaces with `@authenticated` / `@requiresScopes` / `@policy`). Similarly, a benign
   mutation (`updatePreferences`) can leak restricted data through its returned object
   selection set when read-side resolver authz is missing.
   UI omission is only a discovery lead: confirmation also requires an expected entitlement
   boundary from engagement role definitions, policy/configuration, or object ownership.
4. **Per-mutation BFLA & input-object mass assignment (`API5:2023`, `API3:2023` write-side,
   CWE-285 / CWE-915):**
   Low-privilege callers invoke admin mutations (`WPGraphQL CVE-2026-88974` contributor
   calling `updatePost`; `Saleor CVE-2026-39851`/`CVE-2026-35407` on `requestEmailChange`;
   deprecated payload fields leaking accounts as in `WPGraphQL CVE-2026-54768`), or pass
   unintended privileged attributes inside GraphQL `Input` objects
   (`updateUser(input: { bio: "...", role: "ADMIN" })`) that bind directly to ORM updates.
   All mutation/mass-assignment probes go through the write approval gate on test-owned
   records only.

---

## 4. Introspection, Field Suggestions, Federation, & IDE Exposure

- **Introspection (`__schema` / `__type`):** First-class GraphQL feature; disabling it in
  production is a defense-in-depth policy choice (`info`/`low`, WSTG-APIT-01). Requesting
  `queryType`, `mutationType`, `subscriptionType`, and `types { name kind }` in a single
  named probe (`PartexIntrospectionProbe`) immediately reveals whether mutations exist.
- **WAF / regex bypasses:** Brittle WAF rules matching `__schema{` or `POST` JSON bodies
  are bypassed by GraphQL-legal whitespace/newlines (`__schema\n{`), `__type(name: "Query")`,
  aliases, or `GET /graphql?query=...`. At most one bounded bypass probe is warranted when
  a WAF block (not a native server policy error) is observed.
- **Field suggestion leaks ("Did you mean...?"):** Even when `__schema` and `__type` are
  disabled, `graphql-js`, Apollo, Graphene, and Sangria frequently emit typo suggestions
  in validation errors. Tools such as **Clairvoyance** automate dictionary brute-forcing to
  reconstruct the full schema. ParTEx **never** runs wordlist brute-forcing; **one** benign
  invalid-field probe is sufficient to observe whether suggestions are enabled (`info`/`low`).
- **Apollo Federation subgraph exposure (`_service { sdl }` & `_entities`):** Federated
  subgraphs expose `_service { sdl }` and, when the schema defines entities, may expose
  `_entities` as protocol fields — even when standard `__schema` introspection is disabled.
  If a subgraph is directly reachable without router mTLS/auth, `_service { sdl }` dumps
  the complete SDL and `_entities` creates a path that may bypass router-level resolver
  logic. Treat SDL exposure like introspection; confirm any `_entities` BOLA with two-role
  cross-tenant replay rather than inferring unauthorized access from field availability.
- **Non-standard paths & exposed IDEs:** Production endpoints frequently live at
  `/api/graphql`, `/v1/graphql`, `/gql`, `/query`, or expose interactive IDEs (`/graphiql`,
  `/playground`, `/altair`, `/voyager`, Apollo Sandbox). Non-production staging hosts stay
  separate coverage rows and never escalate production verdicts.
- **Note on untrusted introspection ingestion:** Tools or services that dynamically load
  external introspection JSON can themselves be vulnerable (e.g. `graphql-ruby`
  `CVE-2025-27407` RCE via `GraphQL::Schema.from_introspection`); ParTEx parses responses
  as inert JSON data only.

---

## 5. GraphQL CSRF (`GET`, Form-Encoded, Multipart, & `Apollo-Require-Preflight`)

GraphQL endpoints are commonly assumed CSRF-safe because clients normally send
`Content-Type: application/json` (which triggers a browser CORS preflight). Real-world
deployments break this assumption when cookie authentication is combined with:

- **`GET /graphql?query=...`** (especially servers permitting mutations over `GET`,
  violating GraphQL-over-HTTP), or
- **`POST` with browser-simple content types** (`application/x-www-form-urlencoded`,
  `text/plain`, or `multipart/form-data` used by `graphql-upload`) without enforcing a
  non-simple custom header.

This class drove **Apollo Server's `csrfPrevention: true`** feature (`CVE-2022-37734` for
multipart/GET CSRF and XS-Search, requiring `Apollo-Require-Preflight: true` or
`X-Apollo-Operation-Name`) and PortSwigger's GraphQL CSRF exploit pattern. ParTEx tests
this safely on cookie-authenticated endpoints using at most two read-only `{ __typename }`
probes (`GET` and `application/x-www-form-urlencoded` `POST` without custom headers).
Acceptance proves simple-request reachability only and records `needs_follow_up`; a finding
requires an approved reversible mutation on a test-owned object or concrete sensitive-read
/ XS-Search impact. Cookie delivery is evaluated per method (`SameSite=Lax` normally blocks
cross-site form POST cookies but can allow top-level safe-method navigation).

---

## 6. Batching & Resource Consumption: Observation Only (No DoS)

API4 vulnerabilities in real GraphQL servers take four distinct forms:

1. **HTTP JSON array batching** (`[{"query": ...}, {"query": ...}]`): Enabled via options
   such as Apollo Server's `allowBatchedHttpRequests` (and default in several Python/PHP
   frameworks; e.g. `Saleor CVE-2026-35401`). Lets attackers pack hundreds of login, 2FA/OTP,
   or coupon guesses into **one** HTTP request, and can cause **logical 2FA race/state
   bypasses** when login + sensitive queries execute within the same batch.
2. **Document-level alias batching** (`query { a1: login(...), a2: login(...) }`): Uses
   core GraphQL syntax, so **disabling `allowBatchedHttpRequests` does not block it**
   (PortSwigger *Bypassing GraphQL brute force protections*). Mitigations require
   resolver-level rate limiting, alias-count caps, or cost analysis.
3. **Recursive nesting depth & cyclic graphs** (`user { friends { friends { ... } } }`).
4. **Named fragment expansion & limiter bugs:** Depth caps alone do not prevent exponential
   named-fragment expansion (`Apollo Router CVE-2025-32034` / `CVE-2025-32031`) or
   cost-counter overflows (`CVE-2025-32033`), which require query-cost / AST-node budgets.

ParTEx observes controls strictly **without DoS or volume testing**:

| Bounded Observation | Evidence | Claim |
|---|---|---|
| 2-element benign array batch (`__typename`) | `400`/`403` / batching-disabled error | `no_issue_found` (array batching off; aliases still separate) |
| 2-element benign array batch (`__typename`) | `200 OK` 2-element array | Capability/coverage observation: HTTP array batching enabled; not a finding without a sensitive-control bypass |
| Small-N alias batch (3–5 benign aliases) | Alias/cost limit error | `no_issue_found` — per-alias/cost limit present |
| Small-N alias batch (3–5 benign aliases) | Resolves exceeding documented/observed single-request limit | Corroborating API4 evidence; bypass claim requires documented limit (`ConfigExcerpt`) or observed refusal of un-aliased form |
| Single moderately nested query (depth 5–6) | Depth/cost limit error | `no_issue_found` — depth/cost control present |
| Single moderately nested query (depth 5–6) | Accepted | Coverage observation only: this low-cost query was accepted; no inference about higher thresholds |

Explicitly out of scope (per issue #192): volume/DoS sweeps, large alias/array counts,
fragment-expansion bombs, persisted-query hash brute-forcing, suggestion wordlists, and
websocket transport mutations.

---

## 7. Client Bundle & Passive Harvesting Reality (`js-analysis`)

Modern GraphQL frontends rarely ship only neat `"query GetUser { ... }"` strings:

- **Compiled `DocumentNode` ASTs:** `graphql-tag/loader`, `babel-plugin-graphql-tag`, and
  `graphql-codegen` compile `gql` tagged templates at build time into JS object literals
  (`{ kind: "Document", definitions: [{ kind: "OperationDefinition", operation: "query",
  name: { kind: "Name", value: "GetUser" }, selectionSet: ... }] }`). Scanning only for
  `"query "` string literals misses most production React/Apollo webpack/Vite bundles.
- **Relay compiled artifacts:** Relay Compiler emits `ConcreteRequest` objects containing
  `params: { id, name, operationKind, text }` (with `text: null` when persisted queries are
  enabled).
- **Anonymous shorthand queries:** `{ user { id } }` (without the `query` keyword) is
  spec-valid GraphQL and common in lightweight clients.
- **SSR hydration caches:** `__APOLLO_STATE__`, `__NEXT_DATA__`, `__URQL_DATA__`, and
  `__RELAY_STORE__` reveal object types (`__typename`), field names, and IDs passively.
- **Engine fingerprinting via responses:** `extensions.code`, `extensions.exception.stacktrace`
  (Apollo dev mode), `extensions.tracing`, and `x-hasura-*` headers identify the backend
  stack and feed `server-error`/`version-disclosure` without extra requests.

---

## 8. Follow-Up Deterministic Check & Fixture-Triad Blueprint (Not This Issue)

A follow-up `graphql-config` check pair can implement:
- **PassiveCheck:** Consume `js-analysis`-harvested queries, compiled `DocumentNode`
  operations, Relay `ConcreteRequest` entries, and captured `POST /graphql` exchanges into
  coverage rows; flag `extensions.exception.stacktrace` / `extensions.tracing` leaks (or
  defer cleanly to `server-error`).
- **ActiveCheck (with `verify_recipe`):** Bounded probes for introspection (`__schema` +
  single WAF-fallback `__type`), field suggestions (1 probe when disabled), federation
  `_service { sdl }`, 2-element array batching, small-N alias observation, and read-only
  `GET` / `form-urlencoded` CSRF checks on cookie-authenticated endpoints. Role-pair replay
  of harvested queries/mutations can extend `authz-boundary` with GraphQL `200 OK` envelope
  parsing (§2).
- **Fixture triad (`fixtures/skills/graphql/`):**
  1. *Clean:* Introspection disabled, suggestions suppressed, Trusted Documents allowlist
     enforced, `csrfPrevention` rejecting `GET`/form-urlencoded, array batching disabled,
     and `200 OK` soft-403 (`data: { user: null }, errors: [FORBIDDEN]`) + token
     re-hydration returning Role B's own record → **zero findings**.
  2. *Vulnerable:* Introspection + field suggestions enabled; exposed `_service { sdl }`,
     simple-request execution, and array batching recorded as observations; an approved
     test-owned mutation confirms CSRF; and `_entities` / selection-set cross-tenant BOLA
     is confirmed via two-request `verify_recipe` (with `secret_fields` redacted).
  3. *Insufficient evidence:* Target with no GraphQL exchanges/bundles (`not_applicable`),
     or Trusted Documents endpoint with `< 2` roles (`needs_follow_up`).
