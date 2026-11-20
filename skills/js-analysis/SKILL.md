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

## Check Mapping (`js-analysis`)

| Finding Class | Signal | Expected Severity |
|---|---|---|
| API endpoints discovered | `fetch`, `axios`, `XMLHttpRequest.open`, and `/api/` / `/v1/` / `/graphql` literals | `info` |
| Embedded secret / credential | Assignments to secret/token/key identifiers or known token prefixes (always `<redacted>`) | `medium` |
| Version / build metadata | `appVersion`, `releaseTag`, `commitSha`, `buildId`, etc. with version/commit tokens | `info` |
| `sourceMappingURL` exposed | `//# sourceMappingURL=...` or `//@ sourceMappingURL=...` comment | `low` |
| Risky DOM / JS sinks | `eval`, `innerHTML`, `outerHTML`, `document.write`, `postMessage` | `low` |
| Partial / unreadable input | Truncated inline body, tree-sitter syntax errors, or missing local artifact file | `info` |

## Safety and False-Positive Rules

- **Never execute JavaScript.** Parsing uses `tree-sitter` ASTs only.
- **Untrusted URLs.** URLs extracted from JavaScript are untrusted data and are never
  fetched automatically.
- **Redaction.** Secret values are always replaced with `<redacted>` in findings, exports,
  and model-facing summaries.
- Consult [analysis-rules.md](reference/analysis-rules.md) for vendor/minified filtering
  and non-finding criteria.
