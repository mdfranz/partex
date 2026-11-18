# Session and Token Verification Reference

> Provenance: condensed from `communitytools/skills/authentication/SKILL.md`,
> `communitytools/skills/client-side/SKILL.md`, and
> `BaaRai/ARTEX/skills/api-security/SKILL.md` (Phase 2 JWT/OAuth checks).

## 1. Evidence Distinction

| Evidence Type | Check | What It Proves |
|---|---|---|
| Response-visible (`Set-Cookie` flags) | `session-cookie-config` (passive) | Browser-enforced transport, script-access, and cross-site cookie protections |
| Probe-verified (replay response) | `token-weakness` (active) | Server-side token expiry, signature validation, and session revocation |
| Absent auth exchanges | Either | Insufficient evidence — do not report as compliant |

## 2. Active Probe Recipes (`token-weakness`)

1. **Expired token:** Send `GET <protected_path>` with an expired JWT or session token.
   - Expected: `401` / `403` (`no_issue_found`).
   - Failing: `2xx` returning protected resource (`high` finding + `verify_recipe`
     replaying the single request).
2. **`alg: none` JWT:** Replace the JWT header `alg` with `"none"` and strip the
   signature segment (keeping trailing `.`).
   - Expected: `401` / `403`.
   - Failing: `2xx` (`critical` / `high` finding + `verify_recipe`).
3. **Post-logout replay:** Only run when logout is in scope and not listed in
   `scope.exclusions`. Replay the pre-logout token after logout returns `2xx`/`3xx`;
   flag if the protected endpoint still returns `2xx`.

## 3. Redaction and Budget Rules

- Mark all credential headers/cookies in `secret_fields`; findings must never print raw
  JWTs, bearer strings, or `Set-Cookie` values.
- Do not run wordlist brute-forcing against HMAC secrets (`jwt_tool -C`) under `v1`
  verification depth.
