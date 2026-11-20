# ParTEx Skill Research Corpus

Research notes, standards mappings, false-positive guardrails, and stdlib implementation
blueprints for the skills `partex` will test and ship first.

While `skills/<name>/SKILL.md` and `skills/<name>/reference/*.md` hold compact,
agent-facing operational playbooks (to be surfaced to the agent as deferred capabilities
via `defer_loading=True`, `PLAN.md` §9–§10, #59), this
`docs/skills/` directory records the **engineering and security research** behind each
skill and its paired `PassiveCheck` / `ActiveCheck` implementation (`PARTX_SKILL_PLAN.md`,
`DEPS.md`).

---

## 1. Corpus Index and Testing Order

Skills are sequenced by milestone and slice (`PLAN.md` §15, `PARTX_SKILL_PLAN.md` §4):
P0 establishes the passive and active check contracts in M1–M3; P1.1–P1.3 form the first
post-M6 offensive/defensive web & API slices (S1–S3); P2.2 and M7 extend surface capture
and gateway policy verification.

| Priority / Slice | Research Doc | Shipped / Staged Skill | Paired Check ID(s) | Mode(s) | Primary Standards |
|---|---|---|---|---|---|
| **P0 (M1–M3)** | [header-review.md](header-review.md) | `skills/header-review/` | `header-security` | `passive` | OWASP WSTG-CONF-07, WSTG-CLNT-07/12, RFC 6797, W3C CSP3, RFC 6265bis |
| **P0 (M3)** | [version-disclosure.md](version-disclosure.md) | `skills/version-disclosure/` | `version-disclosure` | `active` (`verify_recipe`) | OWASP WSTG-INFO-02/08, WSTG-ERRH-01/02, RFC 9110, RFC 9457 |
| **P1.1 (S1)** | [api-inventory.md](api-inventory.md) | `skills/api-inventory/` | `api-contract-conformance` | `passive` | OpenAPI 3.0.3 / 3.1.0, JSON Schema 2020-12, OWASP API3:2023 & API9:2023 |
| **P1.2 (S2)** | [authorization-testing.md](authorization-testing.md) | `skills/authorization-testing/` | `authz-boundary` | `active` + `passive` (`verify_recipe`) | OWASP API1:2023, API3:2023, API5:2023, WSTG-ATHZ-01..04 |
| **P1.3 (S3)** | [auth-session-controls.md](auth-session-controls.md) | `skills/auth-session-controls/` | `session-cookie-config`, `token-weakness` | `passive` + `active` (`verify_recipe`) | RFC 8725 (JWT BCP), RFC 7515–7519, RFC 6265bis, OWASP API2:2023, WSTG-SESS/ATHN |
| **P2.2 (S5) + M7** | [gateway-and-spa-recon.md](gateway-and-spa-recon.md) | `gateway-policy` (planned) + M7 `browser.py` | `gateway-policy` (planned) | `passive` + `active` + browser harness | OWASP API4:2023, RFC 8594 (`Sunset`), RFC 9745 (`Deprecation`), IETF `RateLimit` |

---

## 2. Key Engineering Findings Across First-Tested Skills

Web research surfaced concrete edge cases where naive scanner rules either produce high
false-positive rates or miss real vulnerabilities due to byte-level protocol details:

1. **CSP Level 3 `'strict-dynamic'` backward-compatibility fallback (`header-review`):**
   W3C CSP3 and Google CSP Evaluator explicitly recommend
   `script-src 'unsafe-inline' https: 'nonce-...' 'strict-dynamic'` so legacy browsers
   degrade gracefully while modern browsers **ignore** `'unsafe-inline'` and `https:`. A
   check that flags `'unsafe-inline'` without checking for a paired nonce/hash +
   `'strict-dynamic'` false-positives on hardened production policies. Conversely, a
   nonce/`strict-dynamic` policy missing `object-src 'none'` or `base-uri 'none'`/`'self'`
   remains bypassable via `<base>` tag injection.
2. **RFC 6265bis cookie prefixes and CHIPS (`header-review` + `auth-session-controls`):**
   Cookies named `__Host-*` must carry `Secure`, `Path=/`, and **no** `Domain` attribute
   (defeating subdomain cookie tossing); `__Secure-*` and `Partitioned` (CHIPS) cookies
   must carry `Secure`. Violating these invariants causes silent browser rejection or
   broken session isolation.
3. **RFC 9457 (`application/problem+json`) vs. debug leaks (`version-disclosure`):**
   Modern APIs legitimately return structured 4xx/5xx JSON (`type`, `title`, `status`,
   `detail`, `instance`). Checks must not confuse structured validation errors (e.g.
   FastAPI 422 `loc`/`msg` or clean RFC 9457 bodies) with unhandled stack traces, while
   still catching raw tracebacks, internal filesystem paths, or SQL fragments stuffed into
   RFC 9457 `detail` or extension members.
4. **OpenAPI 3.0 vs. 3.1 schema divergences (`api-inventory`):**
   OpenAPI 3.0 uses a Draft-04 dialect (`nullable: true`, no `$ref` siblings), while
   OpenAPI 3.1 adopts JSON Schema 2020-12 (`type: ["string", "null"]`, `$ref` siblings,
   and `unevaluatedProperties: false` across `allOf` compositions). The ~300–500 line
   in-package resolver (`DEPS.md` §3.1) must handle both idioms cleanly.
5. **Defeating Soft-403 and Token Re-hydration false positives (`authorization-testing`):**
   Automated BOLA tools (Autorize, AuthMatrix) routinely false-positive when Role B gets
   `200 OK` containing either (a) an application-layer error (`{"error": "forbidden"}`),
   (b) an empty list `[]`, or (c) **Role B's own profile** because the server ignored the
   manipulated ID parameter and hydrated from the session token. True-positive `authz-boundary`
   detection requires **3-way / role-pair semantic comparison** verifying that Role A's
   distinct resource attributes or canary IDs appear in Role B's response.
6. **Stdlib-only RS256 → HS256 PEM byte-exactness (`auth-session-controls`):**
   `DEPS.md` §3.2 commits to stdlib-only JWT crafting (`base64`, `json`, `hmac`,
   `hashlib`). In real RS256 → HS256 vulnerabilities, backend libraries verify HMAC against
   the **PEM-encoded public key bytes** (`-----BEGIN PUBLIC KEY-----\n...`, 64-char base64
   lines, trailing `\n` sensitivity), not raw JWK `n`/`e` JSON strings. Synthesizing
   ASN.1 DER SubjectPublicKeyInfo (PKCS#8 SPKI) and PKCS#1 PEM strings from JWKS `n`/`e`
   takes ~30 lines of pure Python stdlib code — preserving zero external dependencies
   while matching real-world vulnerable targets.

---

## 3. Cross-Skill Standards Matrix

| Standard / Taxonomy | Covered In | Relevant Controls / Categories |
|---|---|---|
| **OWASP API1:2023** — Broken Object Level Authorization | `authorization-testing` | Cross-role/cross-tenant object ID substitution (`authz-boundary`) |
| **OWASP API2:2023** — Broken Authentication | `auth-session-controls` | JWT `alg: none`, RS256→HS256, expired/revoked token acceptance, URL token leaks |
| **OWASP API3:2023** — Broken Object Property Level Authorization | `api-inventory`, `authorization-testing` | Read-side excessive data exposure (`api-contract-conformance`); write-side mass assignment (`authz-boundary`) |
| **OWASP API4:2023** — Unrestricted Resource Consumption | `gateway-and-spa-recon` | Rate-limit headers, bounded burst checks, payload/pagination caps |
| **OWASP API5:2023** — Broken Function Level Authorization | `authorization-testing` | Admin route access, HTTP verb switching, `X-HTTP-Method-Override` |
| **OWASP API9:2023** — Improper Inventory Management | `api-inventory`, `gateway-and-spa-recon` | Shadow routes, zombie `/v1/` prefixes, `Deprecation`/`Sunset` lifecycle drift |
| **OWASP WSTG v4.2+** | `header-review`, `version-disclosure`, `auth-session-controls` | `CONF-07` (HSTS), `CLNT-07` (CORS), `CLNT-12` (CSP), `INFO-02/08`, `ERRH-01/02`, `SESS-02/03/06` |

---

## 4. Non-Negotiable ParTEx Design Constraints Applied Throughout

Every check design and test vector in this directory obeys `PLAN.md` and `AGENTS.md`:

- **Skills are Markdown data; checks are installed entry-point code.** Nothing in
  `skills/` or `docs/skills/` executes.
- **No external runtime dependencies in M0–M6.** Parsing and crafting (RFC 6265bis cookies,
  CSP3 directives, OpenAPI subset resolution, JWT HMAC/DER PEM encoding) use Python 3.14
  stdlib + locked `pyyaml`/`pydantic`.
- **Single socket door (`target.py`) & hard scope gate.** Active probes (`version-disclosure`,
  `authz-boundary`, `token-weakness`) operate strictly through `ScopedHttpClient` within
  `engagement.scope` (`max_rps`, `max_requests`, `exclusions`, `follow_redirects=False`).
- **Minimal confirmation (`PLAN.md` §17.2) & secret safety.** Verification stops at
  boundary confirmation (never data exfiltration, brute-force cracking, or shell payloads),
  and findings never echo raw credentials, cookie values, or PII.
