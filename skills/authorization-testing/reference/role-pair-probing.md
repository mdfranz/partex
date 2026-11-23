# Role-Pair Probing Reference

> Provenance & Standards: OWASP API1:2023 (BOLA), API3:2023 (BOPLA / Mass Assignment),
> API5:2023 (BFLA), OWASP WSTG v4.2 (`WSTG-ATHZ-02`, `WSTG-ATHZ-03`, `WSTG-ATHZ-04`,
> `WSTG-CONF-06`, `WSTG-INPV-04`), OWASP Authorization Testing Automation Cheat Sheet,
> and ParTEx differential response methodology (`docs/skills/authorization-testing.md`).
> Lineage: condensed from [zhaoxuya520/reverse-skill](https://github.com/zhaoxuya520/reverse-skill)
> (MIT), `communitytools/skills/api-security/SKILL.md`, and
> `communitytools/skills/web-app-logic/SKILL.md`.

## 1. Engagement Roles Setup (`PLAN.md` §4.1 D2)

- Each role in `engagement.roles` resolves to an environment variable (`PARTEX_CRED_*`)
  and binds its own `ScopedHttpClient` handle through the same scope gate.
- Never inline tokens in `engagement.json`, findings, or `CoverageEntry` records.

## 2. False-Positive Defenses & Decision Matrix (ParTEx Methodology)

Naive status-code comparison (`200 OK` == vulnerable) false-positives heavily. Apply these
four semantic checks before emitting any finding (`docs/skills/authorization-testing.md` §1):

1. **Soft-403 (`200 OK` Error Wrapper):** Reject `2xx` responses whose payload shifts from
   resource attributes to an application-level denial envelope (`{"ok": false, "error": "Forbidden"}`,
   `{"errors": [...]}`, or an HTML login/access-denied page).
2. **Token Re-hydration (Implicit Session Override):** On endpoints like
   `GET /api/v1/profile?user_id=101`, backends often ignore `user_id` and hydrate from Role B's
   own session token (`200 OK`, identical JSON schema and similar byte length, but returning
   `{"id": 202, "email": "bob@..."}`). Verify that Role B's response contains **Role A's
   distinct resource identifiers/attributes**, not Role B's own record.
3. **Empty Collection Filtering (`200 OK` with `[]`):** Scoped queries often return
   `{"items": [], "total": 0}` instead of `403`. Require Role A's baseline to return `>= 1`
   entity and Role B's replay to contain Role A's entity IDs.
4. **3-Way Baseline Matrix (`Role A` vs. `Role B` vs. `Unauthenticated`):** If an
   unauthenticated request also receives the identical `200 OK` payload and the route is public
   catalog metadata (`security: []`), classify as public (`no_issue_found`) — unless the
   contract requires authentication or the path is `/admin/*` (unauthenticated BFLA/BOLA).

| Role A Baseline | Role B Replay (targeting Role A's ID) | Observed Semantics | Disposition |
|---|---|---|---|
| `2xx` (Role A data) | `401` / `403` / `404` | Explicit access denial | `no_issue_found` (cite both `ev_*`) |
| `2xx` (Role A data) | `2xx` (`{"error": "forbidden"}` or login HTML) | **Soft-403** denial wrapper | `no_issue_found` |
| `2xx` (Role A data) | `2xx` (contains Role B's own ID/profile) | **Token re-hydration** (parameter ignored) | `no_issue_found` |
| `2xx` (`>= 1` item) | `2xx` (`items: []` / empty list) | **Empty filtered collection** | `no_issue_found` |
| `2xx` (public data) | `2xx` (same public data; unauth also `2xx` on public route) | Public catalog endpoint | `no_issue_found` |
| `2xx` (Role A data) | `2xx` (contains Role A's distinct ID / private fields) | **Confirmed boundary crossing** | `high` / `critical` finding + two-request `verify_recipe` |
| Missing / `< 2` roles | Not probed or write-gated (#65) | Unexercised boundary | `needs_follow_up` in `CoverageEntry` |

## 3. Object-Level (BOLA / IDOR) Patterns (`OWASP API1:2023`, `WSTG-ATHZ-04`, CWE-639)

1. **Identifier harvest:** Capture a valid object identifier (`id`, `uuid`, `order_id`,
   `tenant_id`) created or read by Role A (`ev_*` baseline). UUIDs do not mitigate BOLA.
2. **Cross-role replay across all ID carriers:**
   - **Path & query parameters:** `GET /api/v2/accounts/{accountId}`, `?report_id=...`.
   - **Filter, sort, and expansion parameters:** `?account_id=eq.<role_a_id>`,
     `?filter[tenant_id]=<role_a_id>`, or nested relation expansion (`?expand=account.invoices`,
     `?include=owner`).
   - **Header-based tenancy:** `X-Tenant-Id`, `X-Org-Id`, or `X-Account-Id` mismatched against
     Role B's bearer token / session cookie.
   - **Batch / bulk array injection:** Append Role A's ID to a multi-ID request Role B is
     allowed to call (`{"ids": ["<role_b_id>", "<role_a_id>"]}`) to test whether ownership is
     checked only on `ids[0]`.

## 4. Function-Level (BFLA), Mass Assignment, & Bypass Vectors (`API5:2023`, `API3:2023`)

- **Administrative & sibling verb replay (`API5:2023`, CWE-285):** Replay Role A admin routes
  (`/admin/*`, `/internal/*`, `/staff/*`) under Role B; test implied sibling HTTP methods on
  shared paths (`PUT`/`PATCH`/`DELETE` when only `GET` is authorized) and legacy API version
  prefixes (`/api/v1/admin/...` when `/api/v2/admin/...` is hardened).
- **Mass assignment / BOPLA write-side (`API3:2023`, CWE-915):** On write endpoints Role B may
  call on its **own** test record (`PATCH /api/v2/users/me`), test undeclared privilege/tenancy
  fields (`role`, `roles`, `is_admin`, `permissions`, `tenant_id`, `plan`). A `200 OK` that
  ignores extra keys is **not** vulnerable — confirm only when a read-back or representation
  proves the attribute persisted (and revert on the test account).
- **Standard authorization bypass vectors (when direct replay returns `403`/`405`):**
  - **HTTP Parameter Pollution (`WSTG-INPV-04`):** Duplicate object/tenant keys
    (`?user_id=<role_b_id>&user_id=<role_a_id>`) or mix query vs. JSON body IDs when middleware
    validates the first parameter and the handler consumes the last.
  - **Method-override headers (`WSTG-CONF-06`):** On test-owned resources (with write approval),
    test `POST` with `X-HTTP-Method-Override: PUT`, `X-Method-Override: DELETE`, or `?_method=PATCH`.
  - **Rewrite headers & path normalization differentials (PortSwigger Access Control; Orange Tsai):**
    Test whether edge proxies and backend routers disagree on `X-Original-URL` / `X-Rewrite-URL`
    or path parameters (`/api/v2/users/<role_b_id>/../<role_a_id>`, `/admin;v=1/users`) —
    **strictly for in-scope, non-excluded paths** (never place `scope.exclusions` paths inside
    rewrite headers).

## 5. Guardrails

- Do not exfiltrate real user data to prove a boundary. Confirming 1 authorized test record
  (or Role A's own engagement object) is sufficient; stop at the `2xx` and record the boundary —
  never paginate (`?page=2..N`) or dump other users' records.
- Restrict state-mutating probes (`POST`/`PUT`/`PATCH`/`DELETE`) to test-owned records under
  the operator write-approval gate (#65, #223); never delete or corrupt real user data.
- Respect `scope.exclusions` (such as `/admin/shutdown` or `/logout`) enforced by
  `ScopedHttpClient`.
