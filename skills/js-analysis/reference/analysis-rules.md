# JavaScript Analysis Reference Rules

## 1. False-Positive Filtering

- **Placeholders:** Strings such as `<redacted>`, `changeme`, `placeholder`, `example`,
  `your_api_key`, `todo`, `null`, `undefined`, `test`, and `dummy` are excluded from
  embedded-secret findings.
- **Short values:** Secret-key assignments with fewer than 6 characters are ignored.
- **Entropy, not just names (#193):** a long (20–512 char), high-entropy token in the
  base64/url-safe alphabet (Shannon entropy ≥ 4.5 bits/char) is flagged even on an
  innocuous identifier. Forty-char hex strings are excluded (they are commit/build
  SHAs, ~4.0 bits/char), so hashes stay out while random base64 secrets are caught.
  Known token prefixes (`sk-`, `ghp_`, `AKIA…`, `AIza…`, JWT `eyJ…`) match by structure
  regardless of identifier and are reported once (`token-literal`).
- **Integrity and cache values are not secrets.** Subresource-integrity values
  (`sha384-<base64>`, `sha512-…`, `md5-…`) and values under keys such as `integrity`, `hash`,
  `contentHash`, `checksum`, `digest`, `etag`, `nonce` or `chunk…` are high-entropy by
  construction; the entropy rule skips them. A secret-named key (`apiKey`, `passwordHash`) is
  still judged by the name-based rule.
- **Vendor / minified bundles:** High-volume minified bundles may legitimately contain
  DOM sinks (`innerHTML`, `postMessage`) inside framework internals (e.g., React, Vue,
  webpack runtime). Treat sink findings as low-confidence leads requiring manual
  reachability verification.

## 2. Non-Finding Cases

- Empty or comment-only JavaScript files with no endpoints, secrets, version metadata,
  source maps, or risky sinks produce zero findings.
- Generic non-API string literals (e.g., `'/'`, `'text/html'`) are not reported as API
  endpoints.

## 3. Source maps (#193)

- A bundle's `//# sourceMappingURL=` is a **reference, not proof of disclosure**: with no
  captured map it stays the `low` `js:sourcemap` finding (referenced but not fetched or
  parsed — out of scope, missing, or `404`).
- When the map artifact itself is captured, `js-analysis` parses it (`version`, `sources`,
  `sourcesContent`, `names`) and re-runs the same rules over each original source body.
  This is the **biggest disclosure win per effort**: original (unminified) source, comments,
  and dead code surface endpoints, secrets, versions, and sinks the bundle hides.
- **Third-party code is not the application.** Sources under `node_modules/` and bundler
  runtime entries (`webpack/bootstrap`, `webpack/runtime`, `external …`) are counted in the
  disclosure finding but not analyzed: a library's `innerHTML` or test token would otherwise
  appear on every parsed map. A map whose only content is third-party is `low`, not `medium`.
- **Inline maps** (`sourceMappingURL=data:…`) are reported as `low` and described as inline;
  they are not parsed yet, and the data URI is never copied into a finding. A downloaded `.map`
  is matched to its bundle ignoring any query string.
- **Source names are target-controlled text.** A `sources` entry is cleaned (control characters
  and newlines removed) and capped (120 characters) before it appears in a finding.
- **Redaction is absolute.** Original source bodies are never copied into findings or model
  context. Only source *filenames* (paths), identifiers, and `<redacted>` secret values may
  appear. A map that is not valid v3 JSON (no `sources` list) is skipped — it is a signal,
  not an error.

## 4. Router / webpack endpoints (#193)

- Object literals keyed `path`, `pathname`, `route`, or `to` whose value is a `/…` string
  are endpoints (React/Vue route tables) and rank above generic `/api/` string matching.
- Webpack chunk URLs (`*.chunk.js` / `*.chunk.mjs`) are endpoint leads: they reveal
  feature/route structure in minified bundles.
- Dynamic `import()` chunk specifiers remain download/discovery leads (never auto-fetched).

## 5. Partial / Truncated Input

- If an inline `HttpEvidence` JS response was truncated at the 256 KB capture cap
  (`body_note == 'truncated'`), or if `tree-sitter` reports syntax errors on a malformed
  or partial bundle, `js-analysis` emits an `info` `js:parse-status` finding rather than
  crashing or reporting a clean result, while still surfacing any AST items recovered.
