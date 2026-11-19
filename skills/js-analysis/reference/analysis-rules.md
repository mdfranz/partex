# JavaScript Analysis Reference Rules

## 1. False-Positive Filtering

- **Placeholders:** Strings such as `<redacted>`, `changeme`, `placeholder`, `example`,
  `your_api_key`, `todo`, `null`, `undefined`, `test`, and `dummy` are excluded from
  embedded-secret findings.
- **Short values:** Secret-key assignments with fewer than 6 characters are ignored.
- **Vendor / minified bundles:** High-volume minified bundles may legitimately contain
  DOM sinks (`innerHTML`, `postMessage`) inside framework internals (e.g., React, Vue,
  webpack runtime). Treat sink findings as low-confidence leads requiring manual
  reachability verification.

## 2. Non-Finding Cases

- Empty or comment-only JavaScript files with no endpoints, secrets, version metadata,
  source maps, or risky sinks produce zero findings.
- Generic non-API string literals (e.g., `'/'`, `'text/html'`) are not reported as API
  endpoints.

## 3. Partial / Truncated Input

- If an inline `HttpEvidence` JS response was truncated at the 256 KB capture cap
  (`body_note == 'truncated'`), or if `tree-sitter` reports syntax errors on a malformed
  or partial bundle, `js-analysis` emits an `info` `js:parse-status` finding rather than
  crashing or reporting a clean result, while still surfacing any AST items recovered.
