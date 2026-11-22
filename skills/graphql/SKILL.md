---
name: graphql
description: >-
  Invoke when the target exposes a GraphQL endpoint: probe introspection,
  test per-field and per-mutation authorization with role-pair replay of
  harvested queries, and observe deep-query and alias behavior without
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

GraphQL collapses an entire API surface into a single `POST /graphql` operation key
(`api-inventory` records it once; never invent synthetic operation keys per query). All
authorization logic lives in per-field resolvers, so the attack surface is the *selection
set*, not the route. This playbook works entirely within the existing tools:
role-pair replay of harvested queries, selection-set widening, a single bounded
introspection probe, and **observation** of depth/alias limits — never volume testing.

## Passive first: harvest before probing

1. **Query mining in JS bundles.** Clients ship queries as string literals. `js-analysis`
   harvests GraphQL query/mutation literals, `__APOLLO_STATE__` payloads, and
   persisted-query (APQ) manifests from captured assets — see the harvesting note in
   [js-analysis reference/analysis-rules.md](../js-analysis/reference/analysis-rules.md)
   for the false-positive rules. Harvested queries are *leads*: record each as a coverage
   row citing the harvesting evidence, never as a finding.
2. **Observed exchanges.** Captured `POST /graphql` exchanges (`ev_*`) yield the real
   request shapes: operation names, variables, and which selection sets each engagement
   role actually sends.
3. **Error-message disclosure.** Verbose GraphQL errors in captured responses (resolver
   paths, stack frames, internal codes) follow `server-error` / `version-disclosure`
   semantics — cite those checks' findings rather than duplicating the class here.

## Per-field and per-mutation authorization (BOLA / BFLA via GraphQL)

The [authorization-testing](../authorization-testing/SKILL.md) two-role rule applies per
query/mutation, not per route:

- **Never claim an access-control finding from a single response.** Every boundary
  crossing compares two `engagement.roles` handles, and carries a two-request
  `verify_recipe` (baseline under the owning role, replay under the second role —
  see the examples in [reference/graphql-probing.md](reference/graphql-probing.md)).
- **Cross-tenant argument replay.** Take a harvested or captured query, keep the
  request shape, and substitute Role B's variables with an object identifier owned by
  Role A (`user(id: <role_a_id>)`). A `2xx` returning Role A's data is the finding;
  `401`/`403`/`404` records `no_issue_found` citing both exchanges.
- **Selection-set widening.** Query the *same* object under both roles with a wider
  selection set (`user(id) { email ssn internalNotes }`): per-field authorization only
  shows up when the low-privilege role asks for fields the high-privilege client never
  requests. A field that resolves for Role B but not for Role A's public shape is the
  property-level evidence (OWASP API3).
- **Per-mutation BFLA.** Replay harvested mutations under the lower-privilege role —
  but mutations are state-changing requests: they go through the write approval gate
  like any other write, and the first pass prefers read-only queries.
- **Unprobed queries are coverage gaps, not findings:** a harvested query never replayed
  under the second role records `needs_follow_up`.

## Introspection exposure

A single, deterministic probe (the exact query text is in
[reference/graphql-probing.md](reference/graphql-probing.md)): one `POST /graphql` with
`__schema { types { name } }`, sent unauthenticated and once per engagement role — no
brute-forcing of disabled endpoints.

- **Finding wording.** `info`/`low`: an exposed schema is reconnaissance input, not an
  exploit; production endpoints frequently expose it as an accepted risk.
- **False-positive guardrails.** A `403`/`404` or a policy error
  (`"introspection is disabled"`, GraphQL Shield / plugin rejections) is
  `no_issue_found` — enforcement observed, not a finding. A non-production endpoint
  (staging host in scope) answering introspection does **not** escalate the production
  finding; record it as a separate coverage row. A persisted-queries-only endpoint that
  rejects free-form queries is likewise not an introspection finding; note it as a
  *reconnaissance constraint* on the whole playbook.

## Deep queries and aliases: observe, never volume-test

- **The boundary is explicit: no volume or DoS testing.** No request storms, no
  depth-increment sweeps, no automatic persisted-query ID brute-forcing, no websocket
  transport mutations. Deep-query behavior is measured with at most a *single*
  well-formed request per depth class per role.
- **Observation, not escalation.** A response that reports a depth/complexity limit
  (`"query is too nested"`, `422` with cost metadata) is `no_issue_found` coverage:
  a limit is present. Absence of any limit message is an `info`/`low` *observation*
  (OWASP API4-adjacent) that per-request cost controls were not evidenced — it is not,
  by itself, a rate-limit-bypass finding.
- **Aliases.** One small aliased batch (a handful of fields, not hundreds) can observe
  whether batching is counted per request or per alias: an aliased reply set larger
  than the documented per-request limit is corroborating evidence; the *bypass claim*
  needs the gateway's documented limit (a config excerpt) or an observed refusal of the
  un-aliased equivalent. Never send the aliased request more than once per role.

## Guardrails

- Every GraphQL request goes through the engagement-scoped client under the run's
  scope, budgets (`max_requests`, `max_rps`), and write approval gate; the minimal probe
  set is: one introspection request per role, one replay per harvested query per role,
  and at most one alias observation. `POST /graphql` bodies stay as sent in evidence;
  redact `secret_fields` in findings and tool output.
