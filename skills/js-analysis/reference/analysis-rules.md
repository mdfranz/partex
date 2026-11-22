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

## 3. GraphQL Operation & Manifest Harvesting

- Harvest GraphQL operations from captured JS/HTML assets as **coverage leads** for the
  [`skills/graphql/`](../../graphql/SKILL.md) playbook: harvested items record what the
  client invokes; they are never findings on their own and never become synthetic operation
  keys in `api-inventory`.
- **Sources to extract:**
  - Raw query/mutation/subscription string literals (`gql` tagged templates, `"query …"`,
    `"mutation …"`, `"subscription …"`, and valid GraphQL anonymous shorthand queries
    starting with `{ <field> { … } }`).
  - **Compiled `DocumentNode` ASTs:** build tools (`graphql-tag/loader`,
    `babel-plugin-graphql-tag`, `graphql-codegen`) often compile `gql` templates into JS
    object literals (`kind: "Document"`, `definitions: [{ kind: "OperationDefinition",
    operation: "query"|"mutation", name: { kind: "Name", value: "..." } }]`) with no raw
    query string remaining in the production bundle.
  - **Relay `ConcreteRequest` artifacts:** compiled objects carrying
    `params: { id, name, operationKind, text }` (where `text` may be `null` under Trusted
    Documents / persisted queries).
  - **SSR hydration stores & manifests:** `__APOLLO_STATE__`, `__NEXT_DATA__`,
    `__URQL_DATA__`, `__RELAY_STORE__` (reveal `__typename`, field names, and IDs) and
    persisted-query hash maps (note: APQ hashes are client caching metadata, distinct from
    server-enforced Trusted Documents allowlists).
- **Minified-bundle false positives:** template interpolations (`${…}` inside `gql`
  templates) yield partial fragments — record the fragment without fabricating interpolated
  names. Ignore strings that merely *mention* GraphQL (SDK names, `graphql-tag` imports,
  `application/graphql` content types) and generic JSON/CSS brace blocks lacking GraphQL
  field/selection structure.

## 4. Partial / Truncated Input

- If an inline `HttpEvidence` JS response was truncated at the 256 KB capture cap
  (`body_note == 'truncated'`), or if `tree-sitter` reports syntax errors on a malformed
  or partial bundle, `js-analysis` emits an `info` `js:parse-status` finding rather than
  crashing or reporting a clean result, while still surfacing any AST items recovered.
