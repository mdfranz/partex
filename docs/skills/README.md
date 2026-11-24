# ParTEx Skill Research Corpus

Research notes, standards mappings, false-positive guardrails, and stdlib implementation
blueprints for the skills `partex` will test and ship first.

While `skills/<name>/SKILL.md` and `skills/<name>/reference/*.md` hold compact,
agent-facing operational playbooks (to be surfaced to the agent as deferred capabilities
via `defer_loading=True`, `PLAN.md` §9–§10, #59), this
`docs/skills/` directory records the **engineering and security research** behind each
skill and its paired `PassiveCheck` / `ActiveCheck` implementation ([`docs/skills/PLAN.md`](PLAN.md),
`DEPS.md`).

---

## 1. Corpus Index and Testing Order

Skills are sequenced by milestone and slice (`PLAN.md` §15, [`docs/skills/PLAN.md`](PLAN.md) §4):
P0 establishes the passive and active check contracts in M1–M3; P1.1–P1.3 form the first
post-M6 offensive/defensive web & API slices (S1–S3); P2.2 and M7 extend surface capture
and gateway policy verification.

| Priority / Slice | Research Doc | Shipped / Staged Skill | Paired Check ID(s) | Mode(s) | Bundled References (`skills/<name>/reference/`) | Primary Standards & References |
|---|---|---|---|---|---|---|
| **P0 (M1–M3)** | [header-review.md](header-review.md) | `skills/header-review/` (shipped) | `header-security` | `passive` | `response-policies.md` | [OWASP WSTG v4.2 CONF-07](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Strict_Transport_Security), [CLNT-07](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing), [CLNT-12](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/12-Testing_for_CSP), [SESS-02](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes), [RFC 6797](https://www.rfc-editor.org/rfc/rfc6797), [W3C CSP3](https://www.w3.org/TR/CSP3/), [RFC 6265bis](https://httpwg.org/http-extensions/draft-ietf-httpbis-rfc6265bis.html), [WHATWG Fetch](https://fetch.spec.whatwg.org/#http-cors-protocol) |
| **P0 (M3)** | [version-disclosure.md](version-disclosure.md) | `skills/version-disclosure/` (shipped) | `version-disclosure` | `active` (`verify_recipe`) | `verification-criteria.md` | [OWASP WSTG v4.2 INFO-02](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server), [INFO-08](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework), [ERRH-01](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/08-Error_Handling/01-Testing_for_Improper_Error_Handling), [RFC 9110 §10.2.4](https://www.rfc-editor.org/rfc/rfc9110#section-10.2.4), [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457), [CWE-200](https://cwe.mitre.org/data/definitions/200.html), [CWE-209](https://cwe.mitre.org/data/definitions/209.html) |
| **P0 (M3, #128)** | [version-disclosure.md](version-disclosure.md) §3 | `skills/server-error/` (shipped, #128) | `server-error` | `passive` | — | [OWASP WSTG v4.2 ERRH-01](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/08-Error_Handling/01-Testing_for_Improper_Error_Handling), [RFC 9110 §15.6](https://www.rfc-editor.org/rfc/rfc9110#section-15.6), [CWE-755](https://cwe.mitre.org/data/definitions/755.html), [CWE-209](https://cwe.mitre.org/data/definitions/209.html) |
| **P0+ (M3/M5)** | [gateway-and-spa-recon.md](gateway-and-spa-recon.md) §2 & [graphql.md](graphql.md) §7 | `skills/js-analysis/` (shipped, #69, #193) | `js-analysis` | `passive` | `analysis-rules.md` | [ECMA-426 Source Map v3](https://tc39.es/ecma426/), [OWASP WSTG v4.2 CLNT-01](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/01-Testing_for_DOM-based_Cross_Site_Scripting), [CLNT-11](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/11-Testing_Web_Messaging), [PortSwigger DOM-based Vulnerabilities](https://portswigger.net/web-security/dom-based), [CWE-798](https://cwe.mitre.org/data/definitions/798.html), [CWE-540](https://cwe.mitre.org/data/definitions/540.html), [CWE-79](https://cwe.mitre.org/data/definitions/79.html) |
| **P1.1 (S1)** | [api-inventory.md](api-inventory.md) | `skills/api-inventory/` (shipped, #24) | `api-contract-conformance` | `passive` | `contract-matching.md` | [OpenAPI 3.0.3](https://spec.openapis.org/oas/v3.0.3.html) & [3.1.0](https://spec.openapis.org/oas/v3.1.0.html), [JSON Schema 2020-12](https://json-schema.org/draft/2020-12/json-schema-core.html), [OWASP API3:2023](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/), [API9:2023](https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/), [CWE-213](https://cwe.mitre.org/data/definitions/213.html), [CWE-1059](https://cwe.mitre.org/data/definitions/1059.html) |
| **P1.1+ (#156)** | [api-inventory.md](api-inventory.md) | `skills/openapi-spec-review/` (shipped, #156) | `openapi-spec-review` | `passive` | — | [OpenAPI 3.0.3](https://spec.openapis.org/oas/v3.0.3.html) & [3.1.0](https://spec.openapis.org/oas/v3.1.0.html), [OWASP API2:2023](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/), [API3:2023](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/), [API7:2023](https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/), [CWE-522](https://cwe.mitre.org/data/definitions/522.html), [CWE-598](https://cwe.mitre.org/data/definitions/598.html), [CWE-200](https://cwe.mitre.org/data/definitions/200.html), [CWE-918](https://cwe.mitre.org/data/definitions/918.html), [CWE-601](https://cwe.mitre.org/data/definitions/601.html) |
| **P1.2 (S2)** | [authorization-testing.md](authorization-testing.md) | `skills/authorization-testing/` (shipped, #27) | `authz-boundary` | `active` + `passive` (`verify_recipe`) | `role-pair-probing.md` | [OWASP API1:2023](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/), [API3:2023](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/), [API5:2023](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/), [WSTG v4.2 ATHZ-02](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema), [ATHZ-03](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/03-Testing_for_Privilege_Escalation), [ATHZ-04](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References), [CWE-639](https://cwe.mitre.org/data/definitions/639.html), [CWE-285](https://cwe.mitre.org/data/definitions/285.html), [CWE-915](https://cwe.mitre.org/data/definitions/915.html) |
| **P1.3 (S3)** | [auth-session-controls.md](auth-session-controls.md) | `skills/auth-session-controls/` (staged, #26) | `session-cookie-config`, `token-weakness` (staged) | `passive` + `active` (`verify_recipe`) | `session-and-token-checks.md` | [RFC 8725 (JWT BCP)](https://www.rfc-editor.org/rfc/rfc8725), [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515)–[7519](https://www.rfc-editor.org/rfc/rfc7519), [RFC 6749 §5.1](https://www.rfc-editor.org/rfc/rfc6749#section-5.1), [RFC 6265bis](https://httpwg.org/http-extensions/draft-ietf-httpbis-rfc6265bis.html), [OWASP API2:2023](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/), [WSTG v4.2 SESS-02/04/06/10](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens) |
| **P1.4 (#224)** | [privacy-review.md](privacy-review.md) | `skills/privacy-review/` (shipped, #224) | `privacy-signals` | `passive` | `tracker-signatures.md` | [GDPR (EU 2016/679) Arts. 5–7/13](https://eur-lex.europa.eu/eli/reg/2016/679/oj), [ePrivacy Directive 2002/58/EC Art. 5(3)](https://eur-lex.europa.eu/eli/dir/2002/58/2009-12-19), [OWASP Top 10 Privacy Risks](https://owasp.org/www-project-top-10-privacy-risks/), [OWASP ASVS V8](https://owasp.org/www-project-application-security-verification-standard/) (signals only, no legal conclusions) |
| **P2.1 (S4, #187)** | — (`PLAN.md` §13.4, `verify.py`) | `skills/regression-verify/` (shipped, #187) | — (`checks: []`; playbook over `partex verify` & `export-bundle`) | `passive` + `active` | `drift-classes.md`, `prioritization.md` | [OWASP WSTG v4.2 Reporting](https://owasp.org/www-project-web-security-testing-guide/v42/5-Reporting/README), [NIST SP 800-115 §7](https://csrc.nist.gov/pubs/sp/800/115/final), [OWASP ASVS v5.0](https://owasp.org/www-project-application-security-verification-standard/) |
| **P2.2 (S5) + M7** | [gateway-and-spa-recon.md](gateway-and-spa-recon.md) | `gateway-policy` (planned, #188) + M7 `browser.py` (#191) | `gateway-policy` (planned) | `passive` + `active` + browser harness | — | [OWASP API4:2023](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/), [API9:2023](https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/), [RFC 8594 (`Sunset`)](https://www.rfc-editor.org/rfc/rfc8594), [RFC 9745 (`Deprecation`)](https://www.rfc-editor.org/rfc/rfc9745), [IETF `RateLimit` headers](https://datatracker.ietf.org/doc/draft-ietf-httpapi-ratelimit-headers/) |
| **Data-only (#192)** | [graphql.md](graphql.md) | `skills/graphql/` (shipped, #192) | — (`checks: []`; deterministic check follow-up) | `passive` + `active` | `graphql-probing.md` | [GraphQL Spec](https://spec.graphql.org/October2021/), [GraphQL-over-HTTP](https://graphql.github.io/graphql-over-http/draft/), [OWASP WSTG v4.2 APIT-01](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL), [OWASP GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html), [Apollo CSRF](https://www.apollographql.com/docs/apollo-server/security/cors) & [Federation](https://www.apollographql.com/docs/graphos/schema-design/federated-schemas/reference/subgraph-spec) |

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
   Per [IETF `draft-ietf-httpbis-rfc6265bis`](https://httpwg.org/http-extensions/draft-ietf-httpbis-rfc6265bis.html),
   cookies with the `__Host-` prefix must carry `Secure`, `Path=/`, and **no** `Domain`
   attribute (defeating subdomain cookie tossing), and cookies with the `__Secure-` prefix
   must carry `Secure`. Separately, cookies carrying the `Partitioned` attribute
   ([CHIPS — `draft-cutler-httpbis-partitioned-cookies`](https://datatracker.ietf.org/doc/html/draft-cutler-httpbis-partitioned-cookies))
   must also carry `Secure`. Violating these invariants causes silent browser rejection or
   broken session isolation.
3. **RFC 9457 (`application/problem+json`) vs. debug leaks (`version-disclosure`, `server-error`):**
   Modern APIs legitimately return structured 4xx/5xx JSON (`type`, `title`, `status`,
   `detail`, `instance`; [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457)). Checks must
   not confuse structured validation errors (e.g. FastAPI 422 `loc`/`msg`, clean RFC 9457
   bodies, or bare Spring Boot `Whitelabel Error Page` templates without stack traces) with
   unhandled stack traces, while still catching raw tracebacks, internal filesystem paths,
   or SQL fragments stuffed into RFC 9457 `detail` or extension members.
4. **OpenAPI 3.0 vs. 3.1 schema divergences (`api-inventory`, `openapi-spec-review`):**
   OpenAPI 3.0 uses a Draft-04/05 dialect (`nullable: true`, no `$ref` siblings), while
   OpenAPI 3.1 adopts [JSON Schema 2020-12](https://json-schema.org/draft/2020-12/json-schema-core.html)
   (`type: ["string", "null"]`, `$ref` siblings, `$id` / `$anchor` / `$dynamicRef`, and
   `unevaluatedProperties: false` across `allOf` compositions). Per `DEPS.md` §3.1 (#153),
   `src/partex/openapi_resolver.py` pairs an in-package OpenAPI subset resolver with
   [`referencing`](https://github.com/python-jsonschema/referencing) (already in `uv.lock`
   via `mcp`, initialized with **no external retriever** so external `$ref`s never open
   sockets and degrade cleanly to `not_applicable` insufficient evidence).
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
| **[OWASP API1:2023](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)** — Broken Object Level Authorization | `authorization-testing`, `graphql` | Cross-role/cross-tenant object ID substitution (`authz-boundary`), Relay `node(id)` & nested edges |
| **[OWASP API2:2023](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/)** — Broken Authentication | `auth-session-controls`, `openapi-spec-review` | JWT `alg: none`, RS256→HS256, expired/revoked token acceptance, URL token leaks, weak spec auth schemes |
| **[OWASP API3:2023](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/)** — Broken Object Property Level Authorization | `api-inventory`, `openapi-spec-review`, `authorization-testing`, `graphql` | Read-side excessive data exposure (`api-contract-conformance`, `openapi-spec-review`, GraphQL widening); write-side mass assignment (`authz-boundary`) |
| **[OWASP API4:2023](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/)** — Unrestricted Resource Consumption | `gateway-and-spa-recon`, `graphql` | Rate-limit headers, bounded burst checks, payload/pagination caps, GraphQL array/alias batching & depth observation |
| **[OWASP API5:2023](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/)** — Broken Function Level Authorization | `authorization-testing`, `graphql` | Admin route/mutation access, HTTP verb switching, `X-HTTP-Method-Override` |
| **[OWASP API7:2023](https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/)** — Server Side Request Forgery | `openapi-spec-review` | SSRF and open-redirect parameter coverage leads (`ssrf-or-open-redirect`, [CWE-918](https://cwe.mitre.org/data/definitions/918.html), [CWE-601](https://cwe.mitre.org/data/definitions/601.html)) |
| **[OWASP API9:2023](https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/)** — Improper Inventory Management | `api-inventory`, `gateway-and-spa-recon`, `js-analysis` | Shadow routes, zombie `/v1/` prefixes, `Deprecation`/`Sunset` lifecycle drift, client bundle endpoint discovery |
| **[OWASP WSTG v4.2](https://owasp.org/www-project-web-security-testing-guide/v42/)** | `header-review`, `version-disclosure`, `server-error`, `auth-session-controls`, `authorization-testing`, `js-analysis`, `graphql` | `CONF-06/07`, `CLNT-01/07/11/12`, `INFO-02/08`, `ERRH-01`, `ATHZ-02/03/04`, `INPV-04`, `SESS-02/04/05/06/10`, `APIT-01` |
| **[OWASP ASVS v5.0](https://owasp.org/www-project-application-security-verification-standard/)** | `header-review`, `authorization-testing`, `auth-session-controls`, `privacy-review` | `V3.4/V3.5` (Headers/CORS), `V8` (Data Protection/Privacy), `V9` (Self-contained Tokens), Authorization controls |

---

## 4. Non-Negotiable ParTEx Design Constraints Applied Throughout

Every check design and test vector in this directory obeys `PLAN.md` and `AGENTS.md`:

- **Skills are Markdown data; checks are installed entry-point code.** Nothing in
  `skills/` or `docs/skills/` executes.
- **Locked dependency discipline (`DEPS.md`).** Parsing and crafting use Python 3.14
  stdlib + locked `pyyaml`, `pydantic`, `referencing` (offline `$ref` resolution, #153),
  and `tree-sitter` + `tree-sitter-javascript` (non-executing JS AST analysis, #69).
- **Single socket door (`target.py`) & hard scope gate.** Active probes (`version-disclosure`,
  `authz-boundary`, `token-weakness`) operate strictly through `ScopedHttpClient` within
  `engagement.scope` (`max_rps`, `max_requests`, `exclusions`, `follow_redirects=False`).
- **Minimal confirmation (`PLAN.md` §17.2) & secret safety.** Verification stops at
  boundary confirmation (never data exfiltration, brute-force cracking, or shell payloads),
  and findings never echo raw credentials, cookie values, or PII.
