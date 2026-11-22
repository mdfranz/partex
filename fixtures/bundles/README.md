# Bundle fixtures

- `valid/` — a sanitized passive bundle (PLAN §4.3). Evidence covers every `header-security`
  finding class (missing HSTS/CSP/`X-Content-Type-Options`, cookie attribute gaps, CORS `*` with
  credentials), a clean response, a non-HTML response (insufficient evidence), and an OpenAPI
  config excerpt. Credentials appear only as the `<redacted>` marker.
- `server-error/` — one ordinary HTTP 500 JSON response (`{"error": "internal server error"}`),
  no stack-trace or debug-page disclosure. `server-error` applies, yields exactly one `low`
  `route:` finding, and cites the saved exchange (issue #178).
- `js-inert/` — one successful `application/javascript` response whose body has nothing to find.
  `js-analysis` applies and produces zero findings (checked-and-clean, distinguishable from a
  skipped check).
- `clean-openapi/` — a clean, secured OpenAPI 3.1 spec (HTTPS server, global bearer
  `security`, no credential/sensitive properties). `openapi-spec-review` applies, produces zero
  findings, and emits one `needs_follow_up` coverage lead (the `callback_url` query parameter —
  SSRF/redirect follow-up, never a finding).
- `clean-headers/` — one fully hardened HTTPS response (HSTS, CSP with
  `frame-ancestors 'none'`, `X-Content-Type-Options`, secure session cookie). `header-security`
  applies and produces zero findings.
- `api-inventory/` — per-case contract-conformance bundles (issue #24): conforming responses,
  shadow routes, external refs, insufficient evidence.
- `malformed/<rule-code>--<case>/` — one bundle per failure mode. Loading it must raise
  `ValidationFailed` whose `rule_code` is the part of the directory name before `--`
  (`tests/test_bundle.py`, experiment 13.3 b).

Caps that would need very large files (body/excerpt over 256 KiB, URL over 64 KiB, raw file
over the read cap) are exercised with generated bundles in `tests/test_bundle.py` instead.

Headers are JSON arrays of `[name, value]` pairs in wire order (`[["Set-Cookie", "a=1"],
["Set-Cookie", "b=2"]]`), so repeated headers and original casing survive; a JSON object is
rejected. `secret_fields` paths address header values by index (`$.http.request.headers[0][1]`)
and must resolve, or the file fails `evidence-invalid`.
