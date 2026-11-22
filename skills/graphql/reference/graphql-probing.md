# GraphQL Probing Reference

Reference for `skills/graphql/SKILL.md`: the concrete probe shapes, evidence wording, and
false-positive rules. All requests are `POST /graphql` with `application/json` through the
engagement-scoped client; every example below is the *whole* request body sent — one
request, counted against the engagement budget.

## 1. Introspection probe (one per role)

```json
{"query": "query PartexIntrospectionProbe { __schema { types { name } } }"}
```

| Response | Disposition |
|---|---|
| `2xx` with `__schema` data | `info`/`low` finding: schema exposed <unauthenticated / to role>; reconnaissance input, often an accepted risk — never phrase as an exploit |
| `403`/`404` or error `"introspection is disabled"` (GraphQL Shield, plugin rejections) | `no_issue_found`: enforcement observed |
| Persisted-queries-only rejection of free-form queries (`"PersistedQueryNotFound"`, allowlist errors) | Not a finding; record a coverage note: the whole playbook is constrained to harvested operation names |
| Non-production host answers, production host refuses | Two separate coverage rows; do **not** escalate the production verdict from the staging result |

A named operation (`PartexIntrospectionProbe`) keeps the probe identifiable in evidence
and lets a persisted-query gateway's refusal distinguish itself from transport errors.

## 2. Cross-tenant argument replay (per harvested/captured query)

Keep the request shape a captured exchange already used; substitute only the identifier:

```json
{"query": "query GetUser($id: ID!) { user(id: $id) { id name email } }",
 "variables": {"id": "<role_a_object_id>"}}
```

- Baseline: Role A requests its own object (`ev_*` #1). Replay: Role B sends the identical
  body with Role A's identifier (`ev_*` #2).
- `2xx` returning Role A's fields to Role B → boundary crossing; the two-request
  `verify_recipe` cites both `ev_*` IDs.
- `401`/`403`/`404` → `no_issue_found` citing both exchanges (a `404` that leaks object
  existence through timing or error shape is a separate, weaker signal — record it in
  the coverage reason, do not escalate on it alone).

## 3. Selection-set widening (per object, both roles)

The high-privilege client's captured query shows the *public shape*; per-field
authorization hides in the fields it never requests:

```json
{"query": "query GetUser($id: ID!) { user(id: $id) { email ssn internalNotes } }"}
```

- Send the widened set under Role A (expect the resolver to work — a field that fails
  for the owning role is a schema-drift problem, not a finding) and under Role B.
- A field resolving for Role B that is absent from every Role-A/public client shape is
  the property-level evidence (OWASP API3): finding names the field, both roles, and
  both `ev_*` IDs.
- A partial-data response (`"Cannot query field"`) under Role B is `no_issue_found` for
  that field: the schema itself enforces visibility.
- Widening adds fields one probe per role per object — never free-form fuzzing of field
  names; unknown fields are harvested from introspection data or bundles, not guessed.

## 4. Alias / depth observation (at most one request per class per role)

- **Aliased batch (small N):** `"query { a: field b: field c: field … }"` — a handful of
  aliases, sent once. If the reply set exceeds a per-request limit that an equivalent
  un-aliased request trips, that is corroborating evidence for an API4 observation; the
  *bypass claim* still needs the documented limit (config excerpt) or an observed
  refusal of the un-aliased form.
- **Depth:** one moderately nested query per role. A limit message (`"query is too
  nested"`, cost/complexity errors with `maximum`-style fields) is `no_issue_found`
  coverage; no limit message is an `info` observation only.
- **Never:** repeated requests at increasing depth, alias counts in the hundreds,
  automatic persisted-query hash brute-forcing, or mutations over websocket transports.
  These are DoS testing and are out of scope for every partex skill.
