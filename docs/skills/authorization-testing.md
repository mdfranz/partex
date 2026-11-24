# Research: `authorization-testing` (`authz-boundary`)

- **Priority / Slice:** P1.2 — Second post-M6 integration slice (S2, `docs/skills/PLAN.md` §4)
- **Skill Path:** `skills/authorization-testing/SKILL.md` (`reference/role-pair-probing.md`)
- **Check ID & Protocol:** `authz-boundary` (`ActiveCheck` with two-request `verify_recipe` + passive pre-review prioritization)
- **Engagement Requirement (`PLAN.md` §4.1 D2):** `engagement.roles` mapping at least two distinct scoped role handles (e.g. `owner` + `guest`, or `tenant_a` + `tenant_b`), resolved from `PARTEX_CRED_*` env vars.
- **Standards & References:**
  - OWASP API Security Top 10 (2023):
    - [API1:2023 — Broken Object Level Authorization (BOLA / IDOR)](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
    - [API3:2023 — Broken Object Property Level Authorization (BOPLA — write-side Mass Assignment)](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/)
    - [API5:2023 — Broken Function Level Authorization (BFLA)](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/)
  - OWASP Web Security Testing Guide (WSTG) v4.2:
    - [WSTG-ATHZ-02 — Testing for Bypassing Authorization Schema](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema)
    - [WSTG-ATHZ-03 — Testing for Privilege Escalation](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/03-Testing_for_Privilege_Escalation)
    - [WSTG-ATHZ-04 — Testing for Insecure Direct Object References](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)
    - [WSTG-CONF-06 — Test HTTP Methods (`X-HTTP-Method-Override`)](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods)
    - [WSTG-INPV-04 — Testing for HTTP Parameter Pollution](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution)
  - OWASP Cheat Sheets:
    - [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
    - [OWASP Authorization Testing Automation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Testing_Automation_Cheat_Sheet.html)
    - [OWASP Insecure Direct Object Reference Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)
    - [OWASP Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
  - [PortSwigger Web Security Academy — Access Control Vulnerabilities (`X-Original-URL` / `X-Rewrite-URL`)](https://portswigger.net/web-security/access-control) & [Orange Tsai (Black Hat USA 2018) — *Breaking Parser Logic! Take Your Path Normalization Off and Pop 0days Out* (`..;` / proxy-backend path differentials)](https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf)
  - Tooling lineage studied: Burp Autorize & AuthMatrix false-positive failure modes and ParTEx semantic differential response analysis (Soft-403, Token Re-hydration, Empty Collection, 3-Way Baseline Matrix)
  - CWEs: [CWE-639](https://cwe.mitre.org/data/definitions/639.html) (Authorization Bypass Through User-Controlled Key), [CWE-285](https://cwe.mitre.org/data/definitions/285.html) (Improper Authorization), [CWE-862](https://cwe.mitre.org/data/definitions/862.html) (Missing Authorization), [CWE-863](https://cwe.mitre.org/data/definitions/863.html) (Incorrect Authorization), [CWE-915](https://cwe.mitre.org/data/definitions/915.html) (Improperly Controlled Modification of Dynamically-Determined Object Attributes / Mass Assignment)

---

## 1. Why Naive Automated Authz Scanners Fail (and How `authz-boundary` Solves It)

Industry tooling (Autorize, AuthMatrix, naive HTTP replay scripts) suffers from notorious
false-positive rates when testing BOLA/BFLA at scale. Research identifies **four primary
false-positive failure modes** that `authz-boundary` must defeat deterministically:

### 1.1 The "Soft 403" (`200 OK` Error Wrapper)
Many web frameworks, GraphQL servers, and legacy RPC APIs return HTTP `200 OK` with an
application-level denial payload:
- JSON: `{"ok": false, "error": "Forbidden", "code": "PERMISSION_DENIED"}` or GraphQL
  `{"data": {"invoice": null}, "errors": [{"message": "Not authorized"}]}`.
- HTML: `200 OK` rendering a login form or `"Access Denied"` banner after an internal rewrite.

**Mitigation:** Parse JSON/HTML structure before comparing. Reject `2xx` responses whose
top-level schema shifts from resource keys (`id`, `owner_id`, `items`, `email`) to error
envelopes (`error`, `errors` with `data == null`, `login_required`), or whose body matches
negative assertion markers while missing baseline resource fields.

### 1.2 The "Token Re-hydration" Trap (Implicit Session Override)
Suppose Role A requests `GET /api/v1/profile?user_id=101` (or `GET /api/v1/users/101/settings`),
receiving Role A's profile (`{"id": 101, "email": "alice@example.test"}`). When replayed
with Role B's token (`GET /api/v1/profile?user_id=101`), some backends **ignore `user_id`
entirely** and resolve the user from Role B's session token, returning `200 OK` with
`{"id": 202, "email": "bob@example.test"}`!

- Status code: `200 OK` (matches baseline!).
- JSON key schema: `["id", "email"]` (100% schema similarity!).
- Byte length: nearly identical (`46` vs `44` bytes)!
- **Actual security status:** **Not vulnerable** — Role B only saw Role B's own record.

**Mitigation (Canary / Attribute Ownership Diffing):**
Extract **Role A-specific identifier/attribute values** from Role A's baseline response
(e.g. `"id": 101`, `"uuid": "a1b2..."`, or field values absent from Role B's own baseline
profile) and verify that Role B's cross-role response contains **Role A's resource identity**,
not Role B's!

### 1.3 Empty Collection Filtering (`200 OK` with `[]`)
On collection endpoints (`GET /api/v1/tenants/tenant-a/invoices` or `GET /api/v1/orders?org=A`),
scoped SQL queries (`WHERE org_id = :param AND member_id = :current_user`) often return
`200 OK` with `{"items": [], "total": 0}` instead of `403 Forbidden`.

**Mitigation:** Require Role A's baseline exchange to return **at least one non-empty
entity** (`len(items) >= 1`), and require Role B's replay to return one or more of Role A's
entities (`len(items) >= 1` with matching entity IDs).

### 1.4 Public / Shared Catalog Endpoints
Endpoints like `GET /api/v1/products/99`, `GET /api/v1/countries`, or `GET /health`
intentionally return identical `200 OK` payloads to Role A, Role B, **and** unauthenticated
requests.

**Mitigation (3-Way Baseline Matrix):**
Perform a 3-way check (`Role A [Owner/Admin]` vs. `Role B [Other User/Guest]` vs.
`Unauthenticated`):
- If `Unauthenticated` also receives the identical `200 OK` payload **and** the OpenAPI
  contract marks `security: []` (or path is public catalog metadata without user/tenant
  identifiers), classify as a public resource rather than BOLA — *unless* the OpenAPI
  contract explicitly declares `security: [{bearerAuth: []}]` or the path is `/admin/*`
  (in which case unauthenticated `200 OK` is an **Unauthenticated BFLA / Missing Auth**
  finding!).

---

## 2. Vulnerability Classes & Probe Patterns

### 2.1 Broken Object Level Authorization — BOLA / IDOR (`API1:2023`)

Where object identifiers live in real traffic (prioritized from `api-inventory`):

1. **Path parameters:** `GET /api/v2/accounts/{accountId}/statements/{statementId}`
   - Numeric sequential IDs (`101`), UUIDv1/v4/v7, ULIDs, slugs. Note: **UUIDs do not
     mitigate BOLA** (CWE-639) — UUIDs leak via logs, `Referer`, shared links, or collaborative
     views. Pairing Role A + Role B eliminates the need to guess UUIDs because Role A's own
     capture supplies the exact valid UUID!
2. **Query parameters:** `GET /api/v2/export?report_id=rep_8891`
3. **JSON / form request bodies:** `POST /api/v2/documents/view` with `{"document_id": "doc_a1"}`
4. **Batch / bulk array injection:** `POST /api/v2/messages/read` with
   `{"ids": ["<role_b_own_id>", "<role_a_target_id>"]}` — many backends check ownership only
   on `ids[0]` (`all()` vs `any()` bug) and return all requested objects!

### 2.2 Broken Function Level Authorization — BFLA (`API5:2023`)

1. **Direct administrative route replay:**
   Replay Role A (`admin` / `staff`) captures on `/admin/*`, `/internal/*`, `/staff/*`,
   `/api/v2/users` (list all users), `/api/v2/audit-logs` using Role B (`guest` / `member`).
2. **Implied HTTP verb / sibling method probing:**
   When `GET /api/v2/announcements/{id}` is public/member-readable, test whether privileged
   write verbs (`PUT`, `PATCH`, `DELETE`) on test-owned objects enforce role checks.
3. **Method-override headers (safe read/idempotent check or test-owned object):**
   Test `POST` with `X-HTTP-Method-Override: PUT` / `X-Method-Override: PATCH` on a
   **test-owned** resource when direct `PUT`/`PATCH` returns `403`/`405`.
4. **API version downgrade (`API9` × `API5` intersection):**
   If `/api/v2/admin/stats` returns `403` to Role B, test `/api/v1/admin/stats` (within
   `scope.path_prefixes`) where legacy middleware often lacked RBAC decorators.

> **Scope Gate Interaction Note (`X-Original-URL` & Dot-Segments):**
> While external testers sometimes probe `X-Original-URL: /admin/shutdown` or `/public/../admin`,
> in ParTEx **every** probe must honor `engagement.scope.exclusions`! Never place an excluded
> path (`/admin/shutdown`, `/logout`) inside `X-Original-URL` or `X-Rewrite-URL` headers, and
> rely on `scope.py` canonicalization so excluded paths are never reached indirectly.

### 2.3 Mass Assignment / BOPLA Write-Side (`API3:2023`)

On `POST` / `PUT` / `PATCH` endpoints that Role B **is** authorized to call on Role B's
**own** profile/object (e.g. `PATCH /api/v2/users/me`), test whether undeclared privilege or
ownership fields bind to the model:
- Candidate fields (inferred from Role A's admin schema or standard privilege keys):
  `role`, `roles`, `is_admin`, `admin`, `permissions`, `plan`, `tier`, `tenant_id`,
  `org_id`, `verified`.
- **Confirmation criterion:** A `200 OK` that silently ignores extra JSON keys is **not**
  mass assignment! Confirm **only** if a subsequent `GET` (or the `200` representation) shows
  the privilege attribute persisted/changed on Role B's resource (and immediately revert or
  confine strictly to disposable fixture/test accounts).

---

## 3. Differential Evaluation Algorithm (Check Blueprint)

For each candidate operation `(method, normalized_path)` with Role A exchange `ev_a`:

1. **Pre-filter:**
   - Skip if `ev_a.http.response.status` is not `2xx`.
   - Skip state-destructive methods (`DELETE`, or `POST`/`PUT`/`PATCH` on shared/non-test
     records) unless explicitly tagged as safe/idempotent or targeting an engagement-created
     canary object.
   - Check `scope.exclusions` and remaining `max_requests` budget; if budget is insufficient
     or `< 2` roles are configured in `engagement.roles`, record
     `CoverageEntry(outcome='needs_follow_up', reason='missing second role or budget')`.
2. **Execute Role B Replay (`ev_b`):**
   - Substitute Role B's `ScopedHttpClient` credentials (replacing `Authorization` / `Cookie`
     and any CSRF header bound to Role B's session) while keeping Role A's target object ID.
3. **Evaluate Verdict:**
   - `ev_b.status in {401, 403, 404}` → `no_issue_found` (cite `[ev_a.id, ev_b.id]`).
   - `ev_b.status in 200..299`:
     1. Check soft-403 heuristics (error-only JSON keys, login redirect HTML). If soft-403 →
        `no_issue_found`.
     2. Extract Role A identity markers from `ev_a` (object ID, owner email/UUID, non-empty
        records). Verify at least one Role A marker is present in `ev_b` **and** differs from
        Role B's self-identity (defeating token re-hydration).
     3. Optional unauthenticated check (`ev_anon`): if `ev_anon` returns `401`/`403` while
        `ev_b` returns Role A's private data → **high-confidence cross-role BOLA** (`high` /
        `critical`). If `ev_anon` also returns Role A's private data on an authenticated
        endpoint → **unauthenticated BOLA/BFLA** (`critical`).

---

## 4. Two-Request `verify_recipe` & Redaction Discipline

Per `skills/authorization-testing/SKILL.md`:
- `verify_recipe(finding)` replays the ordered pair:
  1. Role A baseline request (`role="owner"` or primary role) — confirms the target object
     still exists and returns `2xx` (preventing false `not_reproduced` verdicts when a test
     record was merely deleted!).
  2. Role B boundary-crossing request (`role="guest"` or secondary role) — confirms the
     cross-role `2xx` with Role A's resource markers still reproduces.
- Verdict transitions:
  - Role A `2xx` + Role B `2xx` (with Role A data) → `confirmed` (`verified`).
  - Role A `2xx` + Role B `401`/`403`/`404` (or soft-403) → `not_reproduced`
    (`verification_failed` — access control fix verified!).
  - Role A `404`/`401`/`5xx` (test object gone or Role A token expired) → `inconclusive`
    (stays `reported` — cannot prove fix if baseline object disappeared!).
- **Strict no-exfiltration & secret redaction:** Stop after confirming 1 record; never
  paginate (`?page=2..N`); redact all `Authorization` / `Cookie` headers via `secret_fields`
  and cite only normalized operation keys + JSON field names + `[ev_a, ev_b]` IDs.

---

## 5. Fixture Triad Design (`fixtures/skills/authorization-testing/`)

1. **Clean + false-positive-resistant target cases:**
   - Properly enforced `GET /api/v2/orders/{id}` returning `403` to `guest`.
   - **Soft-403 trap:** `GET /api/v2/admin/billing` returning `200 OK` with
     `{"error": "insufficient_role"}` to `guest` → **zero findings**.
   - **Token re-hydration trap:** `GET /api/v2/profile?id=owner` returning `200 OK` with
     `guest`'s own profile (`{"id": "guest"}`) → **zero findings**.
   - **Empty filtered list:** `GET /api/v2/invoices?tenant=owner` returning `200 OK` with
     `{"items": []}` to `guest` → **zero findings**.
2. **Vulnerable cases (verified via `verify_recipe`):**
   - **BOLA (`API1:2023`):** `GET /api/v2/invoices/inv_owner_1` returning `owner`'s invoice
     to `guest` (`high`), `verify_recipe` confirms both exchanges, patched variant transitions
     to `verification_failed`.
   - **BFLA (`API5:2023`):** `POST /api/v2/admin/feature-flags` succeeding under `guest`
     (`high`).
3. **Insufficient-evidence / coverage-gap case:**
   - Engagement with only 1 role (`credentials` set, `roles` has `< 2` entries) or
     `max_requests` exhausted mid-inventory → emits `CoverageEntry(outcome='needs_follow_up')`,
     **zero** unverified access-control findings.
