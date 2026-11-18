# Role-Pair Probing Reference

> Provenance: condensed from `BaaRai/ARTEX/skills/api-security/SKILL.md` (Phase 3
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

## 4. Guardrails

- Restrict state-mutating probes (`POST`/`PUT`/`PATCH`/`DELETE`) to test-owned records
  created within the engagement; never delete or corrupt real user data.
- Respect `scope.exclusions` (such as `/admin/shutdown` or `/logout`) enforced by
  `ScopedHttpClient`.
