# Research: `auth-session-controls` (`session-cookie-config` & `token-weakness`)

- **Priority / Slice:** P1.3 — Third post-M6 integration slice (S3, `docs/skills/PLAN.md` §4)
- **Skill Path:** `skills/auth-session-controls/SKILL.md` (`reference/session-and-token-checks.md`)
- **Check IDs & Protocols:**
  - `session-cookie-config` (`PassiveCheck` — session semantics & URL/header token leakage)
  - `token-weakness` (`ActiveCheck` + `verify_recipe` — JWT & session lifecycle boundary probes)
- **Engine Dependency Decision (`DEPS.md` §3.2 & §3.3):** Pure Python 3.14 stdlib (`base64`, `json`, `hmac`, `hashlib`, `urllib.parse`), hand-rolled RFC 6265bis parser shared with capture redaction (`DEPS.md` §8.5). Zero `PyJWT` or `cryptography` dependency in base install.
- **Standards & References:**
  - [IETF RFC 8725 — JSON Web Token Best Current Practices (JWT BCP)](https://www.rfc-editor.org/rfc/rfc8725)
  - [IETF RFC 7515 (JWS)](https://www.rfc-editor.org/rfc/rfc7515), [RFC 7517 (JWK)](https://www.rfc-editor.org/rfc/rfc7517), [RFC 7518 (JWA)](https://www.rfc-editor.org/rfc/rfc7518), [RFC 7519 (JWT)](https://www.rfc-editor.org/rfc/rfc7519)
  - [IETF RFC 6749 §5.1 — OAuth 2.0 Token Response `Cache-Control: no-store`](https://www.rfc-editor.org/rfc/rfc6749#section-5.1)
  - [IETF `draft-ietf-httpbis-rfc6265bis` — Cookies: HTTP State Management Mechanism](https://httpwg.org/http-extensions/draft-ietf-httpbis-rfc6265bis.html)
  - [OWASP API Security Top 10 (2023): API2:2023 — Broken Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/)
  - OWASP Web Security Testing Guide (WSTG) v4.2:
    - [WSTG-SESS-02 — Testing for Cookies Attributes](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes)
    - [WSTG-SESS-03 — Testing for Session Fixation](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/03-Testing_for_Session_Fixation)
    - [WSTG-SESS-04 — Testing for Exposed Session Variables](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/04-Testing_for_Exposed_Session_Variables)
    - [WSTG-SESS-06 — Testing for Logout Functionality](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/06-Testing_for_Logout_Functionality)
    - [WSTG-SESS-10 — Testing JSON Web Tokens](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens)
  - [OWASP JSON Web Token for Java Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html) & [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
  - [PortSwigger Web Security Academy — JWT Attacks](https://portswigger.net/web-security/jwt) & [Algorithm Confusion Attacks](https://portswigger.net/web-security/jwt/algorithm-confusion)
  - CWEs: [CWE-347](https://cwe.mitre.org/data/definitions/347.html) (Improper Verification of Cryptographic Signature), [CWE-327](https://cwe.mitre.org/data/definitions/327.html) (Broken/Risky Crypto Algorithm), [CWE-613](https://cwe.mitre.org/data/definitions/613.html) (Insufficient Session Expiration), [CWE-598](https://cwe.mitre.org/data/definitions/598.html) (Use of GET Request Method With Sensitive Query Strings)

---

## 1. Clean Boundary Between `header-security` and `session-cookie-config`

Per `skills/auth-session-controls/SKILL.md` and `skills/header-review/SKILL.md`, when both
checks run over the same bundle, **cookie-attribute gaps must never be double-reported**:

| Responsibility | Owned By | Examples |
|---|---|---|
| Raw `Set-Cookie` flag hygiene (`HttpOnly`, `Secure`, `SameSite`, `__Host-` / `__Secure-` / `Partitioned` invariants) | `header-security` (`header-review`) | `Set-Cookie: sid=xyz` missing `HttpOnly` or `Secure` |
| **Session & credential transport semantics** | `session-cookie-config` (`auth-session-controls`) | Bearer/JWT/session tokens in URL query strings (`?token=`, `?access_token=`, `?sid=`, `?api_key=`), tokens leaked in `Location` redirects or cross-origin `Referer` headers, unencrypted Basic Auth or Bearer headers over plain `http://`, sensitive cleartext PII/claims decoded inside client-readable cookies, `Cache-Control: no-store` missing on token-issuing responses (RFC 6749 §5.1) |
| **Runtime token acceptance & revocation** | `token-weakness` (`auth-session-controls`) | `alg: none` acceptance, RS256→HS256 key confusion, expired `exp` acceptance, post-logout token replay |

---

## 2. Passive Check Research (`session-cookie-config`)

### 2.1 Session Identifier & Token Exposure in URLs (`WSTG-SESS-04` / CWE-598)
Tokens placed in URL paths or query parameters (`GET /dashboard?session_id=...`,
`302 Location: https://app.example.com/callback?access_token=eyJ...`) persist in browser
history, proxy/CDN access logs, and outbound `Referer` headers:
- **High-signal query/fragment parameter names:** `access_token`, `id_token`, `refresh_token`,
  `token`, `jwt`, `auth_token`, `session_id`, `sid`, `jsessionid` (including URL matrix
  `;jsessionid=...`!), `phpsessid`, `api_key`, `apikey`.
- **Structural value confirmation (avoiding false positives on `?token=invalid` or pagination
  `?page_token=next_20`):**
  - Distinguish opaque pagination cursors (`next_page_token`, `cursor`, `continuation_token`)
    from auth credentials!
  - Confirm JWT structure (`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`) or high
    Shannon entropy / known session parameter names, and check `Referer` headers in captured
    requests for leaked tokens sent to third-party hosts.

### 2.2 Token-Issuing Response Caching (OAuth 2.0 RFC 6749 §5.1)
Responses that issue authentication tokens (`POST /oauth/token`, `POST /api/login` returning
JSON `access_token` / `refresh_token`) must include `Cache-Control: no-store` so shared
intermediaries and browser caches do not persist bearer credentials.

### 2.3 Shared RFC 6265bis Value-Only Secret Splitter (`DEPS.md` §8.5)
`DEPS.md` §8.5 specifies that `Set-Cookie` redaction in M3/M7 must redact **only the cookie
value** while preserving attribute tokens:
- Raw captured: `Set-Cookie: __Host-sid=secret_val_123; Secure; HttpOnly; SameSite=Lax; Path=/`
- Redacted export / bundle: `Set-Cookie: __Host-sid=<redacted>; Secure; HttpOnly; SameSite=Lax; Path=/`
Sharing one ~40-line RFC 6265bis parser/redactor utility ensures exported bundles preserve
full fidelity for passive re-review (`PLAN.md` §13.4 & §13.6).

---

## 3. Active Check Research (`token-weakness` — RFC 8725)

All active probes in `token-weakness` operate within `PLAN.md` §17.2 **minimal confirmation
depth**: they craft deterministic mutant tokens from an engagement-provisioned credential
and compare a protected endpoint's response against an authenticated baseline (`2xx`) and an
invalid-token control (`401`/`403`).

> **Baseline Pre-Check (False-Positive Guardrail!):**
> Before probing any endpoint with mutated JWTs, send **one** request with an obviously
> invalid token (`Authorization: Bearer partex.invalid.token`) or no token! If the endpoint
> **still** returns `200 OK`, the endpoint does not enforce authentication at all (a public
> route or an `authz-boundary` unauthenticated endpoint), **not** a JWT signature-bypass
> vulnerability! Only run `token-weakness` probes against endpoints proven to return `2xx`
> with the valid engagement token and `401`/`403` with a garbage token.

### 3.1 Probe 1: JWT `alg: none` Bypass (RFC 8725 §3.1)

Historical and modern custom JWT verifiers sometimes reject `"alg": "none"` via case-sensitive
comparison (`if header["alg"] == "none"`), remaining vulnerable to case variants.
Test a minimal bounded set (≤ 3 requests, stopping at first `2xx`):
1. `{"alg": "none", "typ": "JWT"}` → `<b64url(header)>.<b64url(payload)>.` (note the
   **mandatory trailing dot `.`** — JWS compact serialization has 3 dot-separated parts with
   an empty 3rd signature segment!).
2. `{"alg": "None", "typ": "JWT"}` → `<b64url(header)>.<b64url(payload)>.`
3. `{"alg": "NONE", "typ": "JWT"}` (or stripped trailing dot if parser splits `<= 2` parts).

Base64url rule (RFC 7515 Appendix C): always strip `=` padding (`base64.urlsafe_b64encode(b).rstrip(b'=')`).

### 3.2 Probe 2: RS256 / ES256 → HS256 Public Key Confusion (RFC 8725 §3.2)

#### Crucial Engineering Finding on `DEPS.md` §3.2 (Exact PEM Bytes!)
`DEPS.md` §3.2 states that `token-weakness` uses Python stdlib only (`base64`, `json`,
`hmac`, `hashlib`) without `cryptography`. Research into real-world RS256→HS256 vulnerabilities
(CVE-2015-9235, CVE-2016-5431, PortSwigger JWT Algorithm Confusion labs, `node-jsonwebtoken`,
legacy `PyJWT` / PHP `firebase/php-jwt`) shows a critical byte-level requirement:

**Vulnerable servers do NOT pass raw JWK `n`/`e` JSON strings into HMAC-SHA256!**
Instead, the backend loads its RSA verification key in memory as a **PEM-encoded ASCII byte
string** (either **SPKI / PKCS#8** `-----BEGIN PUBLIC KEY-----` or **PKCS#1**
`-----BEGIN RSA PUBLIC KEY-----`) and mistakenly passes that buffer as the HMAC secret when
the attacker changes the header to `{"alg": "HS256"}`.

Because HMAC-SHA256 hashes exact bytes, a single difference in ASN.1 header bytes, 64-char
base64 line wrapping, or trailing `\n` produces a completely different signature!

#### Pure-Stdlib JWK `(n, e)` → DER / PEM Encoder (~30 Lines, Zero Dependencies)
We can convert any RSA JWK `{"kty": "RSA", "n": "...", "e": "..."}` (captured from
`/.well-known/jwks.json`, `/jwks.json`, or `/.well-known/openid-configuration` → `jwks_uri`,
or `x5c` certificate chain) into **exact standard OpenSSL PEM bytes** using pure Python
stdlib ASN.1 DER encoding:

```python
import base64


def _b64url_decode(data: str) -> bytes:
    pad = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _der_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(encoded)]) + encoded


def _der_int(raw_unsigned: bytes) -> bytes:
    raw = raw_unsigned.lstrip(b'\x00') or b'\x00'
    if raw[0] & 0x80:  # positive ASN.1 INTEGER requires leading 0x00 if MSB set
        raw = b'\x00' + raw
    return b'\x02' + _der_len(len(raw)) + raw


def _der_seq(body: bytes) -> bytes:
    return b'\x30' + _der_len(len(body)) + body


def jwk_rsa_to_pems(n_b64u: str, e_b64u: str) -> tuple[bytes, bytes]:
    """Return (spki_pem_bytes, pkcs1_pem_bytes) matching exact OpenSSL PEM layout."""
    pkcs1_der = _der_seq(_der_int(_b64url_decode(n_b64u)) + _der_int(_b64url_decode(e_b64u)))
    # rsaEncryption OID 1.2.840.113549.1.1.1 + NULL parameters
    alg_id = bytes.fromhex('300d06092a864886f70d0101010500')
    bit_string = b'\x03' + _der_len(len(pkcs1_der) + 1) + b'\x00' + pkcs1_der
    spki_der = _der_seq(alg_id + bit_string)

    def _wrap_pem(label: str, der: bytes) -> bytes:
        b64 = base64.b64encode(der).decode('ascii')
        lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
        pem = f'-----BEGIN {label}-----\n' + '\n'.join(lines) + f'\n-----END {label}-----\n'
        return pem.encode('ascii')

    return _wrap_pem('PUBLIC KEY', spki_der), _wrap_pem('RSA PUBLIC KEY', pkcs1_der)
```

*(Note: in implementation, test `spki_pem` with trailing `\n`, `spki_pem.rstrip(b'\n')`, and
`pkcs1_pem` — just 3 deterministic requests total! And if the JWK includes `"x5c"`, also
wrap `x5c[0]` as `-----BEGIN CERTIFICATE-----` if needed.)*

Key discovery sources (within engagement scope):
1. Existing `HttpExchange` or `ConfigExcerpt` in the run containing a JWKS or PEM public key.
2. Bounded in-scope fetch to `/.well-known/jwks.json` or `/.well-known/openid-configuration`
   (matching `kid` from the engagement token's JWS header when multiple keys exist).
3. If no public key is available in bundle or well-known endpoints, record
   `CoverageEntry(outcome='needs_follow_up', reason='no public key available for RS256->HS256 check')`.

### 3.3 Probe 3: Unverified Signature Tampering (Missing `verify_signature` Bug)

Some applications call `jwt.decode(token, options={"verify_signature": False})` (calling
`decode` instead of `verify`!) while still rejecting `alg: none` because the header parser
requires `alg: "RS256"` or `"HS256"`.
- **Single-request probe:** Keep the original header (`{"alg": "RS256", ...}`) and original
  payload unchanged, **corrupt 4 bytes of the signature segment** (or sign with a random
  throwaway HMAC key keeping the original `alg`), and send to the protected endpoint!
- If accepted (`2xx`), the backend is **not verifying signatures at all** (`critical`,
  CWE-347) — an even more common real-world bug than `alg: none`!

### 3.4 Probe 4: Expired Token Acceptance (`exp` Claim — RFC 8725 §3.8)

- When an already-expired token is explicitly supplied via engagement credentials (e.g.
  `PARTEX_CRED_EXPIRED`), replay it directly against the protected endpoint.
- Note: Simply mutating `"exp": 1` inside a **validly signed** JWT without re-signing will
  fail signature verification on any server that checks signatures! Therefore:
  - Test `"exp"` mutation directly only if a pre-expired genuine token is provided **or**
    after signature bypass is already present, **or** record `needs_follow_up` if only a
    long-lived valid token is available.

### 3.5 Probe 5: Post-Logout / Revocation Replay (`WSTG-SESS-06`)

- **Gate:** Only run if a logout/revoke endpoint is known **and NOT in `scope.exclusions`**!
  (Notice in `PLAN.md` §4.1 example, `"/logout"` **is** in `scope.exclusions` by default so
  automated checks do not accidentally kill the shared engagement session mid-run!)
- If logout is excluded (`ScopeViolation` or matched in `scope.exclusions`), skip cleanly and
  record `CoverageEntry(outcome='needs_follow_up', reason='logout excluded by engagement scope')`.
- When running with a dedicated disposable session role where logout is permitted, invoke
  logout (`2xx`/`3xx`) and replay the prior session cookie / token; flag if protected state
  still returns `2xx` (noting the architectural distinction between stateless short-lived
  JWTs vs. server-side session cookies).

### 3.6 Explicitly Out of v1 Scope (`skills/auth-session-controls/SKILL.md`)

- Offline dictionary / brute-force cracking of weak `HS256` secrets.
- `jku` / `x5u` SSRF out-of-band callbacks (requires external callback listener, violating
  hermetic / target-only network rules).
- `kid` SQL injection or path traversal (`../../../../dev/null` HMAC signing) — deferred to
  P3 injection playbooks.
- Multi-step interactive OAuth `redirect_uri` / PKCE / `state` flow manipulation.

---

## 4. Fixture Triad Design (`fixtures/skills/auth-session-controls/`)

1. **Clean cases:**
   - Passive: HTTPS login + API exchanges using `__Host-session` cookie (`Cache-Control: no-store`
     on login response, no URL tokens).
   - Active: Protected `/api/me` rejects corrupted signature, `alg: none`, RS256→HS256 SPKI
     PEM-signed token, and expired token with `401 Unauthorized`.
2. **Finding cases:**
   - Passive (`session-cookie-config`): `302` redirect leaking `?access_token=eyJ...` in URL
     and outbound `Referer` (`high`), asserting zero double-reporting with `header-security`
     on cookie flags and `<redacted>` token values.
   - Active (`token-weakness`): Fixture endpoint accepting `alg: None` and a second fixture
     endpoint exposing `/.well-known/jwks.json` + accepting an RS256→HS256 SPKI PEM-signed
     token (`critical`), both confirmed via single-request `verify_recipe`.
3. **Insufficient-evidence / excluded cases:**
   - Public-only bundle with zero auth headers or cookies (`not_applicable`).
   - Engagement where `/logout` is in `scope.exclusions` and no JWKS public key exists →
     clean `needs_follow_up` coverage entries without errors.
