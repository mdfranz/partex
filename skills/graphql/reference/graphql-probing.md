# GraphQL Probing Reference

Reference for `skills/graphql/SKILL.md`: exact bounded probe bodies, GraphQL-over-HTTP
response evaluation rules, and false-positive dispositions. Unless stated otherwise,
requests are `POST` with `Content-Type: application/json` to the discovered GraphQL path
(e.g. `/graphql`, `/api/graphql`, `/v1/graphql`, `/gql`, `/query`) through
`ScopedHttpClient`. Each example below is the **entire** request sent — counted against
`max_requests`.

## 1. Introspection, field suggestions, and federation probes

### 1.1 Primary introspection probe (one per role + unauthenticated)

```json
{"query": "query PartexIntrospectionProbe { __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind } } }"}
```

If blocked by a reverse-proxy/WAF pattern (e.g. `403` HTML WAF page or generic block, not
a GraphQL server policy error), send at most **one** bounded bypass check:

```json
{"query": "query PartexTypeProbe { __type(name: \"Query\") { name fields { name } } }"}
```
*(Or newline-separated `__schema\n{ queryType { name } }` if regex filtering of `__schema{`
is suspected.)*

### 1.2 Field suggestion probe (one benign request when introspection is disabled)

```json
{"query": "query PartexSuggestionProbe { __typename partexNonexistentFieldProbe }"}
```
*(If the server returns no suggestion on a long random name, one short common prefix such
as `use` observes whether `"Did you mean ...?"` is active. **Never** run dictionary or
Clairvoyance-style brute-forcing.)*

### 1.3 Apollo Federation subgraph probe (one request when federation is suspected)

```json
{"query": "query PartexFederationProbe { _service { sdl } }"}
```

### 1.4 Dispositions

| Observed Response | Disposition |
|---|---|
| `2xx` with `__schema` or `__type` data | `info`/`low` finding: schema exposed `<unauthenticated / to role>`; reconnaissance input, often accepted risk — never phrase as an exploit |
| `403`/`404` or GraphQL policy error (`"introspection is disabled"`, GraphQL Shield/plugin rejection) | `no_issue_found`: enforcement observed (follow with §1.2 suggestion check) |
| Validation error containing `"Did you mean ...?"` while introspection is disabled | `info`/`low` finding: field suggestions leak schema names (Clairvoyance reconstruction vector; WSTG-APIT-01) |
| `2xx` returning `_service.sdl` on a directly reachable endpoint | `info`/`low`, like introspection, plus a configuration/coverage note that the subgraph is directly reachable; `_entities` becomes `medium`/`high` only after two-role cross-tenant replay confirms unauthorized entity data |
| `"PersistedQueryNotFound"` in response to a **hash-only** request | **Not** an allowlist! This is an **APQ cache miss**; send the full `"query"` text before concluding free-form queries are blocked |
| Rejection of a request containing **full `"query"` text** (`"PersistedQueryOnly"`, `"PersistedQueryNotSupported"`, allowlist/safelist error) | `no_issue_found` + coverage note: Trusted Documents / persisted-query allowlist enforced; playbook is constrained to harvested operation hashes/names |
| Non-production host answers, production host refuses | Two separate coverage rows; never escalate the production verdict from staging |

A named operation (`PartexIntrospectionProbe`) keeps evidence attributable and distinguishes
GraphQL policy/allowlist responses from transport failures.

---

## 2. GraphQL-over-HTTP response evaluation rules (anti-FP guardrails)

GraphQL servers routinely return **HTTP `200 OK`** for both successes and authorization
failures. Evaluate the parsed JSON envelope before emitting any authorization finding:

| Response Envelope | Meaning | Disposition |
|---|---|---|
| `{"data": {"user": null}, "errors": [{"message": "Forbidden", "extensions": {"code": "FORBIDDEN"}}]}` (`200 OK`) | **GraphQL soft-403** (resolver denied access) | `no_issue_found` citing both `ev_*` IDs |
| `{"errors": [{"message": "Cannot query field \"ssn\" on type \"User\"."}]}` (no `data` key, or `400` under `application/graphql-response+json`) | **Validation-phase error** (aborted before execution; field absent from schema or hidden schema view) | `no_issue_found` (schema drift if Role A also fails) |
| `{"data": {"user": {"id": "1", "ssn": null}}, "errors": [{"path": ["user", "ssn"], "message": "Unauthorized"}]}` (`200 OK`) | **Execution-phase partial data** (per-field denial on `ssn`, sibling `id` resolved) | `no_issue_found` for `ssn`; verify whether resolved sibling fields belong to Role A |
| `{"data": {"user": {"id": "<role_b_id>", "email": "<role_b_email>"}}}` (`200 OK`) | **Token re-hydration** (server ignored `$id` and hydrated from Role B's session) | `no_issue_found` — Role B saw only its own object |
| `{"data": {"orders": []}}` (`200 OK`) | **Empty filtered collection** | `no_issue_found` (require Role A baseline to return `>= 1` entity) |
| `{"data": {"user": {"id": "<role_a_id>", "email": "<role_a_email>"}}}` (`200 OK`) | **Verified boundary crossing** (Role A's distinct resource markers returned to Role B) | `high`/`critical` finding + two-request `verify_recipe` citing both `ev_*` IDs |

---

## 3. Cross-tenant argument replay & Relay `node(id)` (BOLA)

### 3.1 Direct argument replay

Keep the captured query shape; substitute only Role A's object identifier:

```json
{"query": "query GetUser($id: ID!) { user(id: $id) { id name email } }",
 "variables": {"id": "<role_a_object_id>"}}
```

### 3.2 Relay Global Object Identification (`node` / `nodes`)

When Relay global IDs (base64 strings such as `gid://app/Order/101` or `VXNlcjoxMDE=`) are
observed, replay Role A's global ID through `node(id: ID!)` under Role B:

```json
{"query": "query PartexRelayNodeCheck($id: ID!) { node(id: $id) { id ... on User { email } ... on Order { total } } }",
 "variables": {"id": "<role_a_global_id>"}}
```

- Baseline: Role A resolves its own object (`ev_*` #1). Replay: Role B sends the identical
  body (`ev_*` #2). Apply the §2 evaluation table (and optional unauthenticated control).
- HTTP `401`/`403`/`404` or GraphQL soft-403 → `no_issue_found` citing both exchanges.
  Object-existence differences in error messages (`"Not found"` vs. `"Forbidden"`) are a
  weaker enumeration signal — note in coverage, do not escalate to BOLA alone.

---

## 4. Selection-set widening, nested edges, fragments, & mass assignment

### 4.1 Direct widening, nested traversal, and polymorphic fragments (OWASP API3 / API1)

Low-privilege UIs often omit sensitive fields that the schema still exposes on the object
or on related edges:

```json
{"query": "query GetUser($id: ID!) { user(id: $id) { id email ssn internalNotes } }",
 "variables": {"id": "<role_a_object_id>"}}
```

Nested-edge traversal (shared/public parent → private child edge, or Relay `.nodes`
bypassing `.edges` filters) and inline fragments (`... on AdminUser`):

```json
{"query": "query PartexNestedCheck($postId: ID!) { post(id: $postId) { id author { id ... on AdminUser { email apiKey } } } }",
 "variables": {"postId": "<public_or_shared_post_id>"}}
```

- Always send the widened/nested query under **Role A** first (confirming the fields exist
  and resolve for the authorized role — a field that fails validation for Role A is schema
  drift, not a finding), then under **Role B**.
- Treat absence from Role B's UI only as a discovery lead. Establish the expected boundary
  from engagement role definitions, product policy, configuration, or object ownership;
  UI omission alone does not prove that Role B is unauthorized.
- Any field resolving with **Role A's non-null data** for Role B that Role B is not
  entitled to read is confirmed
  property-level evidence: cite the field path (`$.data.user.ssn`), both roles, and both
  `ev_*` IDs (never echo sensitive values).
- Also check **mutation return selection sets**: a benign mutation Role B may call (e.g.
  `updatePreferences`) can leak restricted fields if its returned object graph omits
  read-side field authz.
- Only widen with fields harvested from introspection, bundles, or Role A traffic — never
  blindly fuzz field names.

### 4.2 Per-mutation BFLA & input-object mass assignment (write-gate required)

- **Write approval gate:** Mutations are state-changing. Obtain explicit write approval and
  operate **only** on test-owned objects.
- **BFLA:** Replay a privileged/admin mutation under Role B (e.g. `publishPost`,
  `updateFeatureFlag`) and confirm whether state changed (not merely a soft-403 `200 OK`).
- **Input-object mass assignment (CWE-915):** On a self-service mutation Role B is allowed
  to call (`updateProfile(input: { bio: "...", role: "ADMIN" })`), confirm **only** if a
  follow-up read or the returned object shows the privileged field actually persisted, then
  revert on the test account.

---

## 5. GraphQL CSRF probes (cookie-authenticated endpoints only)

Skip if the endpoint authenticates exclusively via `Authorization: Bearer` headers (not
cookies). Send at most two read-only `{ __typename }` requests **without**
`Apollo-Require-Preflight` or `X-Apollo-Operation-Name`:

1. **GET query probe:**
   ```http
   GET /graphql?query=%7B__typename%7D HTTP/1.1
   Cookie: <engagement_role_cookie>
   ```
2. **Form-urlencoded POST probe (simple request — no CORS preflight):**
   ```http
   POST /graphql HTTP/1.1
   Content-Type: application/x-www-form-urlencoded
   Cookie: <engagement_role_cookie>

   query=%7B__typename%7D
   ```

| Observed Response | Disposition |
|---|---|
| `400`/`403`/`405`/`415` or Apollo `csrfPrevention` error (`"blocked as a potential Cross-Site Request Forgery"`) | `no_issue_found`: transport/preflight CSRF protection observed |
| `200 OK` with `{"data": {"__typename": ...}}` on form-urlencoded POST or GET | `needs_follow_up`: simple-request execution is reachable, but this harmless query does not prove CSRF impact; cite `header-review` cookie evidence and evaluate whether the browser sends the cookie for this method/context |

Confirm CSRF only with an approved, reversible mutation against a test-owned object, or
with concrete sensitive-read / XS-Search impact. `SameSite=Lax` ordinarily blocks cookies
on cross-site form POSTs but can allow them on top-level safe-method navigation, so assess
GET and POST separately rather than requiring `SameSite=Strict` for every deployment.

---

## 6. Batching (array & alias) and depth observation (at most 1 probe per class)

### 6.1 HTTP JSON array batching (1 probe)

```json
[
  {"query": "query PartexBatch1 { __typename }"},
  {"query": "query PartexBatch2 { __typename }"}
]
```

- `400`/`403` or `"batching is not allowed"` → `no_issue_found` (array batching disabled;
  note this does **not** disable alias batching).
- `200 OK` returning a 2-element JSON array `[{"data": ...}, {"data": ...}]` → capability
  / coverage observation that HTTP array batching is enabled, not a finding. Emit a finding
  only when a sensitive operation bypasses an established per-operation control.

### 6.2 Alias batching (1 small-N probe per role)

```json
{"query": "query PartexAliasProbe { a1: __typename a2: __typename a3: __typename }"}
```
*(Or 3–5 aliases of a benign read field harvested from the target.)*

- Explicit alias/complexity limit error → `no_issue_found`.
- Acceptance → capability/coverage observation only. A **rate-limit-bypass claim** requires a
  documented per-request limit (`ConfigExcerpt`) or an observed refusal of the equivalent
  un-aliased form.

### 6.3 Nesting depth (at most 1 moderately nested query per role)

- Use a single moderately nested query derived from an observed cyclic relationship (e.g.
  depth 5–6, never deep sweeps).
- Depth/complexity error (`"query is too nested"`, cost/complexity `maximum` metadata) →
  `no_issue_found` for the selected query. Acceptance means only that this depth-5/6 query
  was accepted; record coverage without claiming that no higher limit or cost control exists.

### 6.4 Explicit DoS / out-of-scope boundary

- **Never:** repeated depth-increment sweeps, alias or array batches in the dozens or
  hundreds, recursive fragment-expansion payloads, automatic persisted-query hash
  brute-forcing, Clairvoyance field-suggestion wordlists, or websocket transport
  mutations. These are DoS or brute-force attacks and are out of scope for every partex
  skill.
