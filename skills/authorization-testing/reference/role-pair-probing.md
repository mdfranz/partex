# Role-Pair Probing Reference

> Provenance: condensed from the `api-security` playbook of
> [zhaoxuya520/reverse-skill](https://github.com/zhaoxuya520/reverse-skill) (MIT; Phase 3
> BOLA/BFLA and second-account rule), `communitytools/skills/api-security/SKILL.md`
> (per-role replay matrix), and `communitytools/skills/web-app-logic/SKILL.md`
> (multi-step workflow boundaries).

## 1. Engagement Roles Setup (`PLAN.md` §4.1 D2)

- Each role in `engagement.roles` resolves to an environment variable (`PARTEX_CRED_*`)
  and binds its own `ScopedHttpClient` handle through the same scope gate.
- Never inline tokens in `engagement.json`, findings, or `CoverageEntry` records.

## 2. Object-Level (BOLA / IDOR) Patterns

1. **Identifier harvest:** Capture a valid object identifier (`id`, `uuid`, `order_id`,
   `tenant_id`) created or read by Role A (`ev_*` baseline).
2. **Cross-role replay:** Replay the same `METHOD /path/{id}` (or JSON body reference)
   using Role B's client handle.
3. **Boundary check:**
   - `401` / `403` / `404` (without leaking object existence) → record `no_issue_found`
     citing both exchanges.
   - `2xx` returning Role A's object fields → emit `authz-boundary` draft citing both
     `ev_*` IDs.

## 3. Function-Level (BFLA) Patterns

- Replay administrative or staff operations (`GET`/`POST`/`PUT`/`PATCH`/`DELETE`) with a
  standard or read-only role token.
- Test implied sibling methods on resource paths (e.g. `DELETE /api/users/{id}` when
  only `GET` is intended for non-admins) and legacy version prefixes (`/v1/admin/...`).
- **Mass assignment:** Append privilege-bearing properties (`"is_admin": true`,
  `"role": "admin"`) to request bodies the lower-privilege role is allowed to send;
  flag if the property sticks in the response or changes the account's effective role.
- **Batch-operation injection:** Append another account's object id to bulk-body
  arrays (`{"ids": [<own_id>, <role_a_id>]}`) the lower-privilege role can call.

## 4. Guardrails

- Do not exfiltrate real user data to prove a boundary. One record the engagement is
  authorized to touch, or the second engagement role's own object, is sufficient
  evidence; stop at the `2xx` and record the boundary — do not page through or dump
  other users' data.
- Restrict state-mutating probes (`POST`/`PUT`/`PATCH`/`DELETE`) to test-owned records
  created within the engagement; never delete or corrupt real user data.
- Respect `scope.exclusions` (such as `/admin/shutdown` or `/logout`) enforced by
  `ScopedHttpClient`.
