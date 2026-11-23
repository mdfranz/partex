---
name: js-analysis
description: >-
  Invoke when downloading full JavaScript bundles locally and analyzing them offline with
  tree-sitter for API endpoints, embedded secrets/config, build metadata, source maps,
  and risky DOM/JS sinks.
modes:
  - passive
checks:
  - js-analysis
---

# JavaScript Bundle Analysis

Download full JavaScript bundles locally (beyond the 256 KB inline capture cap) through the
scoped client and analyze them deterministically with `tree-sitter` — never execute target
JavaScript.

## Workflow

1. **Discover assets** with `discover_js_assets` from captured HTML `<script src>` tags and
   JS `import` / `sourceMappingURL` references. Out-of-scope URLs (such as third-party CDNs)
   are listed but never fetched automatically; the operator must run `/scope add` and
   `/scope confirm` if they want to include another host.
2. **Download full bodies** with `download_asset` (GET-only, scope- and budget-gated).
   Stored artifacts are written beside the run database with mode `0600`, content-addressed
   by SHA-256, and registered as `ArtifactEvidence` (`ev_*`). The full JS body is never
   dumped into the model context.
3. **Run the deterministic check** with `run_check('js-analysis')` to parse stored
   JavaScript artifacts and emit evidence-backed findings.
4. **Source maps**: when a bundle's `sourceMappingURL` references a `.map` and that
   map has been captured in scope, download it with `download_asset` (GET-only,
   scope/budget-gated — map URLs are untrusted data) and re-run the check: it parses
   the map, re-runs the same rules over every `sourcesContent` original source, and
   upgrades the finding (`js:sourcemap-parsed`, `medium` when original source bodies
   are present). A referenced map that is out of scope, missing, or `404` stays the
   `low` `js:sourcemap` finding with a coverage note.

## Check Mapping (`js-analysis`)

| Finding Class | Signal | Expected Severity |
|---|---|---|
| API endpoints discovered | `fetch`, `axios`, `XMLHttpRequest.open`, router `path:` literals, webpack `*.chunk.js` URLs, and `/api/` / `/v1/` / `/graphql` literals | `info` |
| Embedded secret / credential | Secret/token/key identifiers, known token prefixes/structures, and long high-entropy tokens on innocuous identifiers (always `<redacted>`) | `medium` |
| Version / build metadata | `appVersion`, `releaseTag`, `commitSha`, `buildId`, etc. with version/commit tokens | `info` |
| `sourceMappingURL` exposed | `//# sourceMappingURL=...` or `//@ sourceMappingURL=...` comment with no captured/parsed map | `low` |
| Original source recovered from source map | downloaded-and-parsed `.map` (severity `medium` with `sourcesContent`, else `low`) | `medium` / `low` |
| Risky DOM / JS sinks | `eval`, `innerHTML`, `outerHTML`, `document.write`, `postMessage` | `low` |
| Partial / unreadable input | Truncated inline body, tree-sitter syntax errors, or missing local artifact file | `info` |

## Safety and False-Positive Rules

- **Never execute JavaScript.** Parsing uses `tree-sitter` ASTs only.
- **Untrusted URLs.** URLs extracted from JavaScript are untrusted data and are never
  fetched automatically.
- **Redaction.** Secret values are always replaced with `<redacted>` in findings, exports,
  and model-facing summaries. Original source bodies from a source map are analyzed but
  never enter model context or finding text — only source filenames, identifiers, and
  `<redacted>` values appear.
- **Never execute.** Neither downloaded JavaScript nor source-map JSON is ever executed;
  parsing uses `tree-sitter` and `json` only.
- Consult [analysis-rules.md](reference/analysis-rules.md) for vendor/minified filtering
  and non-finding criteria.
