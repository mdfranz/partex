# Bundle fixtures

- `valid/` — a sanitized passive bundle (PLAN §4.3). Evidence covers every `header-security`
  finding class (missing HSTS/CSP/`X-Content-Type-Options`, cookie attribute gaps, CORS `*` with
  credentials), a clean response, a non-HTML response (insufficient evidence), and an OpenAPI
  config excerpt. Credentials appear only as the `<redacted>` marker.
- `malformed/<rule-code>--<case>/` — one bundle per failure mode. Loading it must raise
  `ValidationFailed` whose `rule_code` is the part of the directory name before `--`
  (`tests/test_bundle.py`, experiment 13.3 b).

Caps that would need very large files (body/excerpt over 256 KiB, URL over 64 KiB, raw file
over the read cap) are exercised with generated bundles in `tests/test_bundle.py` instead.
