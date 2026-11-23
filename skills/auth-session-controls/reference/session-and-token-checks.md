# Session and Token Verification Reference

> Provenance & Standards: IETF RFC 8725 (JWT BCP), RFC 7515–7519 (JWS/JWK/JWA/JWT),
> RFC 6749 §5.1 (OAuth 2.0 `Cache-Control: no-store`), `draft-ietf-httpbis-rfc6265bis`,
> OWASP API2:2023 (Broken Authentication), OWASP WSTG v4.2 (`WSTG-SESS-02`, `WSTG-SESS-04`,
> `WSTG-SESS-06`, `WSTG-SESS-10`), PortSwigger JWT Attacks methodology, and ParTEx
> stdlib-only token verification research (`docs/skills/auth-session-controls.md`).
> Lineage: condensed from `communitytools/skills/authentication/SKILL.md`,
> `communitytools/skills/client-side/SKILL.md`, and
> [zhaoxuya520/reverse-skill](https://github.com/zhaoxuya520/reverse-skill) (MIT).

## 1. Evidence Distinction & Passive Checklist (`session-cookie-config`)

| Evidence Type | Check | What It Proves |
|---|---|---|
| Response-visible (`Set-Cookie`, URL query/`Referer`, `Cache-Control`) | `session-cookie-config` (passive) | Session transport hygiene: tokens leaked in URLs/`Referer` (`WSTG-SESS-04`, CWE-598), missing `Cache-Control: no-store` on token-issuing responses (RFC 6749 §5.1), cleartext auth over `http://` |
| Probe-verified (replay response against invalid-token baseline) | `token-weakness` (active) | Server-side signature verification, algorithm enforcement, token expiry, and session revocation (RFC 8725, `WSTG-SESS-06/10`) |
| Absent auth exchanges | Either | Insufficient evidence (`not_applicable` / `needs_follow_up`) — never report as compliant |

Passive `session-cookie-config` rules:
- **URL & `Referer` token leakage (`WSTG-SESS-04`, CWE-598):** Flag credentials/sessions in
  query strings, matrix parameters (`;jsessionid=`), `Location` redirect targets, or outbound
  `Referer` headers (`access_token`, `id_token`, `refresh_token`, `token`, `jwt`, `session_id`,
  `sid`, `api_key`). Ignore benign pagination cursors (`next_page_token`, `cursor`).
- **Token-issuing cache control (RFC 6749 §5.1):** Responses issuing bearer/OAuth tokens
  (`access_token`, `refresh_token`) must include `Cache-Control: no-store`.
- **Deduplication with `header-security`:** Do not double-report pure `Set-Cookie` attribute
  gaps (`HttpOnly`, `Secure`, `SameSite`) when `header-security` runs on the same bundle.

## 2. Active Probe Recipes (`token-weakness`)

### Step 0: Mandatory Invalid-Token Baseline Pre-Check (Anti-FP Guardrail)

Before probing any endpoint with mutated JWTs, verify two baseline conditions:
1. The valid engagement credential returns `2xx`.
2. A request with an obviously invalid token (`Authorization: Bearer partex.invalid.token`)
   returns `401` or `403`.

If the invalid token **also** returns `200 OK`, the route does not enforce authentication on
that request (public route or unauthenticated `authz-boundary` issue) — **stop** and do not
misreport it as a JWT signature/algorithm bypass!

### Step 1: Unverified Signature & `alg: none` Bypass (RFC 8725 §3.1, CWE-347)

1. **Corrupted signature check (1 request):** Keep the original JWT header (`alg: RS256`/`HS256`)
   and payload intact, corrupt 4 bytes of the signature segment, and replay. If `2xx`, the
   server decodes without verifying signatures at all (`critical`, CWE-347).
2. **`alg: none` & case variants (≤ 3 requests, stop at first `2xx`):** Rewrite the JWT header
   to `{"alg": "none", "typ": "JWT"}`, then `"None"`, then `"NONE"` (base64url-encoded without
   `=` padding per RFC 7515 Appendix C) and strip the signature while **keeping the trailing
   dot** (`<header>.<payload>.`).
   - Expected: `401` / `403` (`no_issue_found`).
   - Failing: `2xx` (`critical` finding + single-request `verify_recipe`).

### Step 2: Public Key Confusion (`RS256` → `HS256`, RFC 8725 §3.2, CWE-327)

When the engagement token uses an asymmetric algorithm (`RS256`) and the target's RSA public
key is available (from captured bundle evidence or an in-scope fetch to
`/.well-known/jwks.json` / `/.well-known/openid-configuration`):
- Encode the JWK `(n, e)` (or `x5c`) into standard OpenSSL PEM bytes (**SPKI**
  `-----BEGIN PUBLIC KEY-----` and **PKCS#1** `-----BEGIN RSA PUBLIC KEY-----`; see
  `docs/skills/auth-session-controls.md` §3.2 for the stdlib ASN.1 DER recipe).
- Rewrite the header to `{"alg": "HS256", "typ": "JWT"}`, keep the original claims, and sign
  with HMAC-SHA256 using the exact PEM byte string as the HMAC secret.
- Expected: `401` / `403`.
- Failing: `2xx` (`critical` finding + single-request `verify_recipe`).
- If no public key is available, record `needs_follow_up` (`no public key available for RS256->HS256 check`).

### Step 3: Expired-Token Replay (RFC 8725 §3.8, CWE-613)

- Replay a pre-expired engagement token against the protected endpoint (note: mutating `"exp"`
  inside a validly signed token without re-signing tests signature verification, not expiry,
  unless signature verification is already bypassed).
- Expected: `401` / `403` (`no_issue_found`).
- Failing: `2xx` returning the protected resource (`high` finding + `verify_recipe`).

### Step 4: Post-Logout / Revocation Replay (`WSTG-SESS-06`, CWE-613)

- Only run when the logout/revoke endpoint is in scope and **not** listed in
  `scope.exclusions` (if excluded, record `needs_follow_up: logout excluded by engagement scope`).
- Invoke logout (`2xx`/`3xx`) with a disposable role session and replay the pre-logout token;
  flag if the protected endpoint still returns `2xx`.

## 3. JWT Header Triage Leads (`jwk`, `jku`, `x5u`, `kid`) — Manual Follow-Up Only

Inspect captured JWT headers passively (`WSTG-SESS-10`, RFC 8725 §3.10–§3.11, PortSwigger JWT):
- **`jwk` (embedded public key) / `jku` (JWK Set URL) / `x5u` (X.509 URL):** If present in
  server-issued tokens or accepted headers, record as a `needs_follow_up` coverage lead for
  manual review. Do **not** trigger out-of-band `jku`/`x5u` SSRF callbacks from automated checks.
- **`kid` (Key ID):** Note unusual filesystem path or SQL-like `kid` formats as a coverage
  lead; active `kid` path-traversal (`../../../../dev/null`) or SQLi probes belong to P3
  injection playbooks, not `token-weakness`.

## 4. Redaction and Budget Rules

- Mark all credential headers/cookies in `secret_fields`; findings must never print raw
  JWTs, bearer strings, or `Set-Cookie` values.
- Do not run wordlist or dictionary attacks against token secrets under the §17.2
  verification depth — token probing stops at minimal confirmation (accept / reject
  of crafted tokens), never secret recovery.
