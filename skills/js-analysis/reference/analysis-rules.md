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

## 3. GraphQL Query Literal Harvesting

- Queries ship as string literals in clients (`gql` tagged templates, `"query …"` /
  `"mutation …"` strings, `__APOLLO_STATE__` hydration payloads, persisted-query (APQ)
  manifests). Harvest them as **coverage leads** for the
  [`skills/graphql/`](../../graphql/SKILL.md) playbook: a literal names a query the
  client sends; it is not itself a finding and never becomes a synthetic operation key.
- **Minified-bundle false positives:** template fragments (`${…}` interpolations inside
  `gql` tagged templates) yield partial queries — record the fragment, do not fabricate
  the interpolated names. String literals that merely *mention* GraphQL (SDK names,
  `graphql-tag` imports, `application/graphql` content types) are not queries. A
  literal shorter than `query {` / `mutation {` / `subscription {` with no selection
  set is not harvested.

## 4. Partial / Truncated Input

- If an inline `HttpEvidence` JS response was truncated at the 256 KB capture cap
  (`body_note == 'truncated'`), or if `tree-sitter` reports syntax errors on a malformed
  or partial bundle, `js-analysis` emits an `info` `js:parse-status` finding rather than
  crashing or reporting a clean result, while still surfacing any AST items recovered.
