# Session and Token Verification Reference

> Provenance: condensed from `communitytools/skills/authentication/SKILL.md`,
> `communitytools/skills/client-side/SKILL.md`, and the `api-security` playbook of
> [zhaoxuya520/reverse-skill](https://github.com/zhaoxuya520/reverse-skill) (MIT; JWT
> algorithm-confusion and claim-tampering checks).

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
3. **Key confusion (RS256 → HS256):** Re-sign a token with the target's public key
   (e.g. from `/.well-known/jwks.json`, if captured in the bundle) used as the HMAC
   secret, keeping the original claims.
   - Expected: `401` / `403`.
   - Failing: `2xx` (`high` / `critical` finding + `verify_recipe`).
4. **Post-logout replay:** Only run when logout is in scope and not listed in
   `scope.exclusions`. Replay the pre-logout token after logout returns `2xx`/`3xx`;
   flag if the protected endpoint still returns `2xx`.

## 3. Redaction and Budget Rules

- Mark all credential headers/cookies in `secret_fields`; findings must never print raw
  JWTs, bearer strings, or `Set-Cookie` values.
- Do not run wordlist or dictionary attacks against token secrets under the §17.2
  verification depth — token probing stops at minimal confirmation (accept / reject
  of crafted tokens), never secret recovery.
