---
name: authorization-testing
description: >-
  Invoke when testing API operations or web workflows for BOLA, IDOR, BFLA, or
  cross-tenant authorization flaws using paired engagement roles.
modes:
  - active
  - passive
checks:
  - authz-boundary
license: Apache-2.0
metadata:
  author: partex
  derived_from:
    - zhaoxuya520/reverse-skill api-security playbook (MIT)
    - communitytools/skills/api-security/SKILL.md (MIT)
    - communitytools/skills/web-app-logic/SKILL.md (MIT)
---

# Authorization Boundary Testing (BOLA / IDOR / BFLA)

Test operations from the `api-inventory` surface for broken object-level (BOLA/IDOR) and
function-level (BFLA) authorization by replaying the same normalized operation across two
distinct `engagement.roles` handles.

## Mandatory Two-Role Rule

- **Never claim an access-control finding from a single response.** A boundary crossing
  requires comparing two scoped identities from `engagement.roles` (e.g. `owner` vs.
  `guest`, or `user_a` vs. `user_b`) through `ScopedHttpClient`, or proving an
  authenticated-only endpoint succeeds without credentials.
- **Passive pre-review (`passive`):** Inspect captured `HttpExchange` pairs and
  `ConfigExcerpt` (`format: openapi`) security requirements to prioritize object-scoped
  paths (`{id}`, `{accountId}`, `{tenantId}`) and privileged routes (`/admin`, `PUT`,
  `PATCH`, `DELETE`), flagging unprobed operations as `needs_follow_up` in
  `CoverageEntry`.
- **Active probing (`active`):** Replay each candidate operation under the lower-privilege
  or cross-tenant role within `max_rps` / `max_requests` budgets.

## Check Mapping (`authz-boundary`)

| Finding / Outcome Class | Condition | Expected Disposition |
|---|---|---|
| Verified BOLA / IDOR | Role B accesses or mutates an object owned by Role A (`2xx` with Role A resource data) | `high` / `critical` finding + `verify_recipe` citing both `ev_*` IDs |
| Verified BFLA / method bypass | Lower-privilege role invokes an admin operation or privileged HTTP method (`PUT`/`DELETE`/`PATCH`) | `high` finding + `verify_recipe` citing both `ev_*` IDs |
| Unprobed operation | Operation in inventory lacks a second role in `engagement.roles` or hit `max_requests` | **Coverage gap** (`needs_follow_up`), not a finding |
| Missing evidence | Neither baseline exchange nor role-pair capture exists for the operation | **Insufficient evidence**; do not infer enforcement |

## Verification Protocol (`verify_recipe`)

- Every `authz-boundary` finding must attach a replayable two-request `verify_recipe`:
  1. Baseline request under the authorized role (`ev_*` #1).
  2. Cross-role or unprivileged replay under the second role (`ev_*` #2).
- Finding `title` and `description` must name the normalized operation key, the violated
  role/tenant policy, and both `ev_*` IDs while keeping `secret_fields` (`<redacted>`)
  out of text.

Consult [role-pair-probing.md](reference/role-pair-probing.md) for object-ID substitution,
BFLA method-swap patterns, and destructive-action guardrails.
