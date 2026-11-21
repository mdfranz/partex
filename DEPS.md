# Partex dependency decisions and browser automation strategy

> Status: decisions recorded and active (§8). Answers two questions left implicit by
> `PLAN.md` and `RUNTIME.md`: (1) which Python libraries the engine needs beyond the
> locked Pydantic AI / Monty stack, and (2) how browser automation should work. **Stance: ParTEx
> requires active probing via the scoped Python client *and* via browser automation, plus
> HAR import — the same three paths the original ARTEX frameworks ran** (§5). Sequencing and
> the browser engine choice are decided in §8; later reviewed additions (e.g. `tree-sitter` in
> §8.9) are appended there. Every load-bearing claim cites its source document.

## 1. Relationship to the other docs

| Doc | Boundary |
|---|---|
| `PLAN.md` §3.1 | Owns the environment contract (uv, local path sources, dev toolchain). This doc's amendments are **applied** to `PLAN.md` (§1 non-goals, §2 layer rules, §3.1 deps, §5 source convention, §8 CLI, §13.4, §13.6, §15 M7, §16, §17.5, §18); the review questions are resolved in §8 below. |
| `RUNTIME.md` | Owns execution environments (Monty Code Mode, microVM deferral). The browser capture harness gained its section there (M7). |
| `PARTX_SKILL_PLAN.md` §4 | Owns slice sequencing. The S1 `api-inventory` skill is the first consumer of the harness's captures. |

## 2. What the locked stack already provides

Direct dependencies of the local packages `partex` must install anyway (verified against the
checkout pyprojects, November 2026):

| Library | Floor | Via | Used by partex for |
|---|---|---|---|
| `httpx` | 0.28.1 | `pydantic-clai2` (direct, transitional until its own httpx2 migration) | Fallback for `target.py` if the M0 API gate fails (§3.9, §8.1) |
| `httpx2` | 2.7 | `pydantic-ai-slim`, `pydantic-ai-harness` (direct) | `target.py` scoped client — **decided §8.1**, M0 API gate §3.9 |
| `anyio` | 4.7.0 | `pydantic-ai-slim` (direct, pinned for cancellation delivery) | Worker task groups, `CapacityLimiter`, `fail_after`, `to_thread` (`PLAN.md` §7.1) |
| `pydantic` | 2.12 | `pydantic-ai-slim` | All data contracts (`PLAN.md` §5) |
| `pyyaml` | 6.0.2 | `pydantic-clai2` (direct) | `SKILL.md` frontmatter lint (D6) and `format: openapi` `ConfigExcerpt`s, which may be YAML |
| `rich` | 14 | `pydantic-clai2` (direct) | CLI summary output |
| `prompt-toolkit` | 3.0.52 | `pydantic-clai2` (direct) | `chat` TUI (via CLAI2) |
| `logfire[httpx]` | 4.31.0 | `pydantic-clai2` (direct) | Opt-in observability (`PLAN.md` §11.1) |
| `pydantic-monty` family | >=1.5.0,<2 | `pydantic-ai-harness[code-mode]` | CLAI2 Code Mode; required by CLAI2 even when Code Mode is off (`RUNTIME.md`) |
| `opentelemetry-api` | 1.28.0 | `pydantic-ai-slim` | Tracing surface (already imported by the agent stack) |

**Headline claim (initial baseline, amended by §8.9):** the original v1 milestones (M0–M6)
targeted zero new direct PyPI dependencies beyond the locked agent stack (`httpx2`, `anyio`,
`pydantic`, `pyyaml`, `rich`, `logfire`, `pydantic-monty`), with `pyyaml` and `logfire`
explicitly declared in `pyproject.toml` since `partex` imports them directly. The one
reviewed M0–M6 addition is `tree-sitter` + `tree-sitter-javascript` for deterministic,
non-executing JS AST analysis (§8.9, #69). The post-M6 browser harness (§7) remains the
scheduled addition for `playwright` (or `websockets`).

## 3. Runtime decisions per engine module

### 3.1 OpenAPI handling — `api-contract-conformance` (S1)

Need: load a `format: openapi` `ConfigExcerpt`, resolve local `$ref`/`allOf`, match concrete
captured paths against path templates, check `properties`/`additionalProperties`, carry
`revision` onto findings and coverage rows (`skills/api-inventory`, D1).

**Decision: minimal in-package resolver as check code** (~300–500 lines), covering exactly
the JSON Schema subset the check emits findings on. Rejected alternatives:

- `openapi-core` — full request/response validation we do not perform in v1; pulls a large
  dependency tree. **Revisit trigger:** the P2.2 `gateway-policy` slice growing into full
  contract-conformant request validation.
- `jsonschema` — reference validator, but still leaves path-template matching to us; adds
  `referencing`/`jsonschema-specifications` for checks we can do with dict lookups.

The unresolvable-external-`$ref` → insufficient-evidence path is already specified by
`skills/api-inventory/reference/contract-matching.md` §1; the resolver implements that, not
the full spec.

### 3.2 JWT crafting — `token-weakness` (S3)

Need: `alg: none` (header rewrite, signature strip), expired-claim replay, HS256 signing,
RS256→HS256 key confusion (`skills/auth-session-controls`).

**Decision: stdlib only** — `base64` + `json` for token parsing, `hmac`/`hashlib` for HS256.
Key confusion needs only the JWKS `n`/`e` (or `x5c`) bytes as the HMAC secret — the server
does the asymmetric verification we are probing, so we never verify RS* locally.

**Revisit trigger:** checks needing local RS* verification or full claim-tampering matrices;
then add `PyJWT` + `cryptography` as an *optional extra* (`partex[jwt]`), keeping the binary
`cryptography` wheel out of the base install.

### 3.3 Cookie parsing — `session-cookie-config` (S3)

**Decision: hand-rolled RFC 6265 attribute parsing** (split on `;`, flag vs `key=value`).
Stdlib `http.cookies`/`SimpleCookie` is RFC 2109-era and mis-parses modern cookie syntax —
explicitly *not* to be used. ~40 lines of check code with fixtures for `SameSite=None`,
attribute casing, and empty values.

### 3.4 Header policy parsing — `header-security` (M1)

HSTS `max-age`, CSP directives (semicolon-separated), CORS pairing: stdlib string parsing.
No library; the policy baselines live in
`skills/header-review/reference/response-policies.md`.

### 3.5 URL canonicalization — `scope.py` (M3)

**Decision: stdlib `urllib.parse` + `yarl` (already via httpx)**, hardened by the planned
hostile-URL fixture suite (`PLAN.md` §13.4, §16 risk "URL parsing edge").

Rationale and contingency: parser differentials between RFC 3986 semantics (Python) and
WHATWG semantics (browsers, and therefore most server frameworks' idea of a path) are the
primary scope-bypass class. **Revisit trigger:** if the hostile-URL fixtures surface a
differential we cannot defend by normalization in code, adopt `ada-url` (the WHATWG Ada
parser with official Python bindings) for `scope.py` canonicalization only. That is a binary
wheel, so it must not be adopted preemptively — only on demonstrated need.

### 3.6 HAR import — proposed answer to `PLAN.md` §17.5

**Decision: `partex import-har <file.har> --out DIR` as a passive-bundle producer**, stdlib
`json` only. HAR is JSON; the producer validates and converts to `evidence/NNNN.json`
records. Scheduled for M3 (`PLAN.md` §8, §13.4); it is one of the three required capture
paths in §5. Entries outside the bundle manifest's declared scope are filtered with a
reported count and a dropped-host histogram recorded in the manifest; an import with zero
in-scope entries exits 1 as an operator-error guard (§8.6).

### 3.7 Storage, IDs, time

`sqlite3`, `json`, `hashlib`, `secrets`, `uuid`, `datetime` (timezone-aware UTC) — stdlib.
No ORM, no migration library; `PRAGMA user_version` per `PLAN.md` §7.

### 3.8 Dev/test additions to name in `PLAN.md` §3.1

| Tool | Purpose | Note |
|---|---|---|
| `coverage` / `pytest-cov` | The 100% branch target (`PLAN.md` §14) is unachievable without it; §3.1 currently omits it | PyPI, dev-only |
| `capfire` / `InMemorySpanExporter` | Logfire span assertions in the hermetic suite (`PLAN.md` §14) | From the pydantic-ai checkout; pin as a local path source like the other checkout test fixtures |
| `pytest`, `anyio` (plugin), `ruff`, `pyright`, `inline-snapshot` | Already named in §3.1 | Unchanged |

### 3.9 `target.py` pins `httpx2` (decided §8.1; M0 API gate)

`pydantic-ai-slim` and `pydantic-ai-harness` depend on **`httpx2>=2.7`** and import it
throughout, while `pydantic-clai2` pins **`httpx>=0.28.1`** only transitionally (its
pyproject comments the pin as "until its own `httpx2` migration"). `target.py` therefore
pins **`httpx2`** — one HTTP API surface to audit, on the line the stack itself maintains.
The M0 gate stands: verify by inspection that the custom-transport API covers §4.2 (pinned
resolver connect-to-IP with original `Host`/SNI/hostname cert verification,
`follow_redirects=False`); on failure, fall back to `httpx` 0.28.x. The greenfield
dependency check (§13.1) asserts which library `partex` actually imports and that both
resolve from the lockfile without conflict.

**M0 gate result (recorded 2026-11-18, issue #1): passed — `target.py` pins `httpx2`; the
`httpx` 0.28.x fallback is not needed.** `scripts/check_httpx2_gate.py` proves httpx2
2.16.2's custom-transport surface covers §4.2 rules 2 and 4, against a loopback-only TLS
server whose hostname does not exist in DNS: a `httpcore2.AsyncConnectionPool` with a
custom `network_backend` connects only to the pinned resolved address, while the request
URL keeps the original `Host` header and SNI, and certificate verification succeeds against
the original hostname — and fails, as a negative control, when the origin is the address
itself. Redirect responses are returned unfollowed with `follow_redirects=False`. Note for
`target.py`: exception mapping from httpcore2 to httpx2 types lives in the *default*
transport, so a custom transport surfaces `httpcore2.ConnectError` unless it maps them
itself.

## 4. Supply-chain posture (unchanged, restated)

All `pydantic-*` and `pydantic-monty*` packages resolve from PyPI, pinned with hashes in
`uv.lock` and installed with `uv sync --frozen` (issue #13, superseding the local-checkout rule
of #1; the November 2026 backdoor — `docs/lineage/SOURCES.md` — is why the lockfile hashes are the control).
All third-party deps resolve from the pinned lockfile. Apart from the reviewed `tree-sitter`
addition (§8.9, #69), `playwright`/`websockets` arrive with the scheduled harness milestone
(§7), while `ada-url`, PyJWT, and `openapi-core` stay behind their §3 triggers.

### 4.1 Locked stack versions

`uv.lock` is the single source of truth for the audited versions (issue #13). CI runs
`uv lock --check` and `uv sync --frozen`, and `scripts/check_greenfield.py` fails the build if
any locked requirement is unpinned, unhashed, or from a path/VCS/URL source, or if an `artex`
or `strix` distribution appears. Bumping the stack is an explicit, reviewed `uv.lock` change
(`uv lock --upgrade-package pydantic-clai2`).

Observed at the switch (2026-11-18): `pydantic-ai-slim` 2.68.0, `pydantic-ai-harness` 0.68.0,
`pydantic-clai2` 0.68.0, `pydantic-monty` (metapackage, client, runtime) 1.6.0, `httpx2` 2.16.2.

## 5. Capture and probe surfaces: three required paths

The original ARTEX frameworks ran three capture/probe paths in parallel, and ParTEx needs
all three — this is a capability requirement inherited from the lineage, not an optional
enhancement:

| # | Path | Original framework equivalent | ParTEx role | Status |
|---|---|---|---|---|
| 1 | **Scoped HTTP client** (httpx/httpx2) — active probing | Go HTTP client in the forks' active checks and retester loop (`docs/lineage/ARCHITECTURE.md`) | `target.py` (`ScopedHttpClient`): baseline capture, active check probes, verification replay, agent `http_request` tool | Landed M3 (`PLAN.md` §15) |
| 2 | **Browser automation harness** | `api-recon` Puppeteer runtime harvesting (`docs/lineage/SKILLS.md`); BaaRai's `extension/` browser traffic capture | **Active probing and capture** in real authenticated SPA flows: contexts per `engagement.roles`, mock-stub credential-free discovery, flow driving (login, forms, UI trigger points), every exchange captured into `RunStore` | **Required; scheduled as M7** (`PLAN.md` §15, gate §13.6) |
| 3 | **HAR import** | The forks' MITM proxy served this role (capture everything the operator's browser does) | `partex import-har`: passive-bundle producer from operator-exported captures — the MITM replacement, since `PLAN.md` §1 forbids interception | **Landed M3** (`#28`, `PLAN.md` §8, §17.5) |

Why paths 2 and 3 are load-bearing: the S1 `api-inventory` skill builds its observed surface
from `HttpExchange` records, and path 1 alone cannot produce the hundreds of authenticated
XHR/fetch exchanges a real SPA emits during ordinary use — a plain HTTP client has no JS
runtime, no session bootstrapping, and no way to walk UI trigger points.
`PARTX_SKILL_PLAN.md` §2 declined to port the forks' `scripts/` tree *as scripts* — which
is exactly why the capability must return as engine machinery (a harness), not as a
data-only skill's leftover Node tooling.

The harness (path 2) must respect the same constraints as everything else:

- `PLAN.md` §1 non-goal: no MITM proxy — evidence comes from partex's own client or, per
  §17.5, imported files; never from intercepting a browser.
- `PLAN.md` §2: `target.py` is the only module that opens sockets. A browser process opens
  its own sockets; a harness therefore cannot be a check or the target client. It must be
  a separate **evidence producer** writing `HttpExchange` records (source
  `capture:browser:<seq>`) into the RunStore, feeding the same passive pipeline.
- Scope enforcement in a browser cannot be socket-level from partex. It must be
  **code-level interception**: abort out-of-scope navigations and requests via the
  automation layer's route hook (the browser-world equivalent of `ScopeViolation`, recorded
  on the run).
- Secrets: browser-captured `Cookie`/`Authorization` headers are blanket-marked
  `secret_fields` (in addition to engagement-credential pattern matching), because the
  browser holds sessions partex never provisioned. `Set-Cookie` is marked **value-only** —
  attributes stay visible for `session-cookie-config` and redacted round-trips (§8.5).

## 6. Browser engine options (path 2)

All three paths in §5 are required; the open choice is the *engine* for path 2. HAR import
(path 3) stays in the table only as the zero-automation baseline it builds on.

| | A. HAR import (baseline) | B. Playwright Python | C. Raw CDP (`websockets`) | D. agent-browser CLI |
|---|---|---|---|---|
| What | Operator browses in their own browser, exports HAR, `partex import-har` builds a bundle | Official Python package; managed browsers or `connect_over_cdp` | Hand-rolled Network/Fetch domain client on `websockets` | strix's preinstalled CDP binary (`strix/strix/skills/tooling/agent_browser.md`) |
| New deps | **Zero** (stdlib JSON) | PyPI wheel bundles a **Node.js driver**; browser binaries downloaded separately and **not lockfile-pinned** | One pure-Python dep | None for partex; external binary, not a Python lib |
| Authenticated flows | Operator's real session; partex never touches credentials | `connect_over_cdp` to operator-launched Chrome: partex never manages binaries or credentials | Same attach model | Has auth vault, `state save/load` |
| Roles pairing (`engagement.roles`) | Manual (two exports) | Browser **contexts** map 1:1 onto roles; `storage_state` per role | Incognito windows as contexts, DIY | `--session` per role |
| Scope gate | N/A (no automation) | `page.route` abort → recorded refusals | `Fetch` domain interception, DIY | `network route --abort` |
| Credential-free discovery (api-recon stub pattern) | No | `page.route` mock-stubs login/bootstrap endpoints exactly as the forks' `preload.js` does | DIY | `network route --body` |
| Flow automation for the agent | None | Full API (click/fill/wait, snapshots via tracing) — **active probing in a real JS runtime**, not just capture | Expensive to reimplement | Excellent UX, but as a CLI |
| Supply-chain surface | None | Node driver in a PyPI wheel (lockfile-pinnable but not Python-auditable); binary provenance concern for managed browsers | Minimal; CDP protocol churn is code-maintenance risk, not dependency risk | Unaudited external binary; out of posture |
| Event loop | n/a | asyncio-native — compatible with anyio's asyncio backend (must pin that backend for harness commands) | anyio-compatible if written against anyio websockets... note: `websockets` is asyncio; same pin applies | Subprocess |
| Cross-browser | Browser-agnostic (HAR is generic) | Chromium/Firefox/WebKit | Chromium only (CDP); Firefox = WebDriver BiDi, still maturing | Chromium only |

Selenium/WebDriver: rejected without table row — weakest network-event visibility, dated
API, and request capture effectively requires a proxy (which §1 forbids).

## 7. Recommendation (all three paths, sequenced)

All three §5 paths ship. The proposal below sequences them and picks the path-2 engine:

1. **Path 1 — scoped HTTP client (M3, already planned).** Unchanged core of `PLAN.md`.
2. **Path 3 — `partex import-har` (decided: M3, beside `export-bundle`).** Closes
   `PLAN.md` §17.5. Zero new dependencies, no scope-gate complexity (partex never drives the
   browser; the operator exports a file). Importing a file is cleanly distinct from
   intercepting traffic, so the no-MITM rule stands.
3. **Path 2 — browser automation harness (required; decided: dedicated post-M6 milestone
   M7, gate `PLAN.md` §13.6).** Option B, Playwright, with `connect_over_cdp` as the
   primary mode. The decisive property: attaching to an operator-launched Chrome means
   partex **never
   downloads or manages browser binaries and never touches the operator's credentials** —
   the browser holds the session. That is *stronger* than the env-var credential flow for
   live-auth capture and neutralizes the binary-provenance problem for the mode that
   matters most. Use Playwright-managed Chromium only for (a) the credential-free
   mock-stub discovery mode (the api-recon pattern, where stubs gate the SPA into its
   post-login shell) and (b) CI fixtures against localhost.

   The harness serves **both passive capture and active probing**: it records every exchange
   into `RunStore` (evidence producer) *and* drives flows — role-paired browsing, form
   submission, UI-trigger-point walking — the way the forks' retester loop could drive a
   browser. It needs its own validation gate: a static HTML/JS fixture SPA served by the
   fixture target app (the current stdlib `http.server` fixture gains a small static SPA
   page), a scope-via-route-interception test, a redaction test over browser captures, and
   a capture → passive-review round-trip.

   **Raw CDP (Option C) is the documented fallback**, scoped to *capture-only* — a
   ~200-line Network-domain recorder (`requestWillBeSent` / `responseReceived` /
   `getResponseBody`, with the known caching caveat) — not full automation, which is where
   CDP reimplementation becomes expensive. Adopt only if the Node driver is ruled
   unacceptable on supply-chain grounds.
4. **Agent-driven active probing via browser, after the harness.** Expose a small
   `browser_*` toolset over the harness (open/snapshot/click/fill/wait), with the
   interaction model as data-only skill guidance — the same port the forks' `playwright-cli`
   skill already gets in `PARTX_SKILL_PLAN.md` §7, minus the Bash tool gate. Do not give
   the agent a shell to a browser CLI (the strix model); give it constrained tools scoped
   and audited like `http_request`. Deterministic `ActiveCheck`s stay on the scoped client
   in the near term; whether checks ever gain browser access (a protocol variant receiving
   the harness handle) is review question 8, not a v1 commitment.

Anyio note for the harness: Playwright's async API is asyncio-native, and pydantic-ai is
anyio-based. They coexist on anyio's **asyncio** backend only — commands that touch the
harness must pin that backend explicitly (assert in the harness entry point; fail loudly on
trio).

## 8. Decisions (resolved from review)

All eight review questions are resolved. Rationale is kept here so the §-numbered sections
above stay terse.

1. **§3.9 (httpx vs httpx2) — decided**: `target.py` pins **`httpx2`**. The whole agent
   stack already builds on it (`pydantic-ai-slim` imports `httpx2` throughout;
   `pydantic-clai2` comments its legacy `httpx` pin as "until its own `httpx2` migration"),
   so one HTTP API surface is audited instead of two, on the line the stack itself
   maintains. The M0 gate stands: verify the custom-transport API covers §4.2 (pinned
   resolver connect-to-IP with original `Host`/SNI/hostname cert verification,
   `follow_redirects=False`); on failure, fall back to `httpx` 0.28.x. The §13.1 greenfield
   check asserts which library `partex` actually imports.
2. **§3.1 (minimal OpenAPI resolver) — decided**: own the subset in check code. v1 never
   performs full request/response validation, and the resolver implements a specified
   contract (the insufficient-evidence path in
   `skills/api-inventory/reference/contract-matching.md` §1), not the whole spec.
   Edge-case risk is bounded by the S1 fixture triad; the P2.2 `gateway-policy` revisit
   trigger stands.
3. **§7.2 (import-har placement) — decided**: M3, beside `export-bundle` (applied to
   `PLAN.md` §8, §13.4, §17.5).
4. **§7.3 (Playwright Node driver) — decided**: accept the lockfile-pinned wheel. Attach
   mode (`connect_over_cdp` to operator-launched Chrome) is the mitigation: partex never
   downloads a browser binary or touches credentials in the mode that matters, and the Node
   driver is a CDP *client* library — it executes no target code and holds no credentials,
   unlike the in-boundary code-execution artifacts the source-build posture guards. Raw CDP
   trades a reviewable, lockfile-pinnable dependency for unbounded protocol-churn
   maintenance, and it cannot deliver the flow automation that is the point of path 2
   (capture-only ≠ probing). Managed Chromium stays confined to localhost fixtures and
   credential-free discovery; because `playwright install` artifacts bypass the uv lockfile,
   §13.6's driver-provenance test pins the browser build (version + hash asserted in
   fixture setup). Raw CDP remains the documented capture-only fallback.
5. **§5 (secret marking) — decided**: keep blanket `Cookie`/`Authorization` marking in
   browser captures. Under-marking leaks live session tokens into provider requests,
   transcripts, and spans; over-marking only costs the model some session-flow visibility —
   the failure costs are asymmetric. Refinement: `Set-Cookie` is **not** blanket-marked; it
   is marked **value-only** (attributes such as `Secure`/`HttpOnly`/`SameSite` stay
   visible) once the S3 RFC 6265 splitter lands and is shared between the capture layer and
   the `session-cookie-config` check. Blanket-marking `Set-Cookie` would blind the §13.4
   redacted export-bundle → passive-review round-trip for cookie-attribute findings.
6. **§3.6 (HAR provenance) — decided**: filter to the bundle manifest's declared scope and
   report the dropped count. Real HARs always carry extension/telemetry/CDN noise, so
   out-of-scope entries are normal and never an error. Two guardrails: an import with
   **zero in-scope entries exits 1** (almost always operator error — wrong file or
   manifest), and the dropped-host histogram is recorded in the bundle manifest so the
   filtering is auditable, not silent.
7. **§7.3 (harness milestone placement) — decided**: dedicated post-M6 milestone **M7**
   with its own gate (`PLAN.md` §13.6: fixture SPA, route-interception scope test,
   redaction tests, capture → passive review round-trip). Engine machinery stays out of
   the skill slices; `agent`'s `browser_*` tools land with M7.
8. **§7.4 (browser-capable checks) — decided**: the check-vs-browser separation holds; no
   `BrowserProbe` protocol in v1. A check holding a harness handle inherits JS-runtime
   nondeterminism and timing flakiness and breaks the deterministic-check boundary;
   browser-driven active testing enters via the agent `browser_*` tools, where
   nondeterminism is acceptable. If a DOM-dependent check is ever needed, the shape is a
   new evidence kind (a harness-captured DOM snapshot) plus a passive check over it —
   revisited through the D-series amendment process (`PARTX_SKILL_PLAN.md` §5) with a
   concrete skill in hand, not before.
9. **JS AST parsing (`#69`) — decided**: add `tree-sitter` (`>=0.26`) and `tree-sitter-javascript`
   (`>=0.25`) as locked PyPI runtime dependencies (prebuilt wheels, no `[tool.uv.sources]`
   override, 2-day cool-off respected). Chosen over `esprima`/`pyjsparser` (unmaintained) and
   `js2py`/`quickjs` (execute target JS, violating the non-execution boundary). Tree-sitter parses
   minified and truncated bundles deterministically with error tolerance.
10. **Google Gemini / Vertex AI native web search (`#111`) — decided**: add the `google` extra on
    `pydantic-ai-slim[google]` (`google-genai 2.34.0`, `google-auth 2.62.2`, plus transitive
    `distro 1.9.0`, `pyasn1 0.6.5`, `pyasn1-modules 0.4.2`, `tenacity 9.1.4`) via `uv.lock`
    (2-day cool-off respected, no `[tool.uv.sources]` override). Enables `--search-model google:`
    (API key) and `--search-model google-cloud:` (ADC) using provider-native server-side search
    only (`WebSearch(local=None)`), keeping partex's `target.py`-only socket boundary intact.
