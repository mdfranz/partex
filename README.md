# ParTEx (`partex`)

> **Status:** Active implementation. The passive core (`header-security`, `js-analysis`), registry, live scoped testing (including passive checks over live captures, `--insecure` TLS, and `version-disclosure` anchoring/dedup), HAR/bundle round-trip (`import-har`, `export-bundle`), host sandbox detection (`sandboxes`), reporting, read-only `chat`, and interactive `agent` (with `/scope add`) have landed (see [Implemented CLI](#implemented-cli)); M4 summarization, `--auto` agent loop, hardening gates, and the M7 browser harness remain open. Dependencies are locked PyPI releases resolved through `uv.lock`.

**ParTEx** (`partex`) is a greenfield Python framework for **authorized web application and API security testing**, built on locked PyPI releases of [Pydantic AI](https://github.com/pydantic/pydantic-ai) (`pydantic-ai-slim`, `pydantic-ai-harness`, `pydantic-clai2`) and [Monty](https://github.com/pydantic/monty) (`pydantic-monty`).

It draws workflow patterns—engagement lifecycle, evidence-linked findings, replayable exploit verification, and packaged `SKILL.md` playbooks—from the **ARTEX** multi-agent penetration-testing ecosystem and complementary open-source skill collections, while sharing **no runtime, service, schema, or code dependency** with any ARTEX fork.

---

## Documentation in This Repository

### Active Specification & Guides

| Document | Purpose |
|---|---|
| [`PLAN.md`](PLAN.md) | **Core engine & package specification**: scope, 7-layer architecture (incl. the M7 browser harness), package layout, engagement & bundle schemas, Pydantic data contracts, SQLite `RunStore` (WAL, single-writer), CLI surface, CLAI2 & `--auto` agent wiring, Logfire secret-safe observability, validation experiments (§13), and milestones **M0–M7**. |
| [`RUNTIME.md`](RUNTIME.md) | **Execution boundaries & state lifetime**: deterministic installed passive checks, CLAI2 Monty-backed Code Mode for the M5 read-only reviewer (`chat <run-id>`), opt-in speculative reads evaluation, the M7 browser capture harness (CDP attach to operator Chrome, route-hook scope gate, shared engagement budgets), deferred microVM isolation for full Python/native tools, and M0 local Monty dependencies. |
| [`DEPS.md`](DEPS.md) | **Dependency & browser automation decisions**: locked Pydantic AI / Monty stack, per-module library decisions (`httpx2`, `tree-sitter` + `tree-sitter-javascript`, stdlib OpenAPI/JWT/RFC 6265 helpers), and the three capture/probe paths (scoped Python client, HAR import, and M7 browser automation harness). |
| [`PARTX_SKILL_PLAN.md`](PARTX_SKILL_PLAN.md) | **Skill roadmap & synthesis workflow**: `skills/<name>/SKILL.md` frontmatter contract and lint (D6), 5-family taxonomy, dual-mode priority ranking (**P0** anchors + post-M6 slices **S1–S6**), engine deltas (**D1–D6**), definition of ready, and multi-source condensation targets. |
| [`docs/skills/README.md`](docs/skills/README.md) | **Skill research corpus**: security research, standards mappings, and false-positive guardrails behind the shipped and staged checks. |
| [`AGENTS.md`](AGENTS.md) | **Agent working agreement**: issue claiming, branching, `uv` environment rules, and definition of done. |

### Historical Lineage & Reference Survey

These documents preserve the external ARTEX / strix / communitytools survey that informed `partex`'s initial design; they are **not** specifications of `partex`:

| Document | Purpose |
|---|---|
| [`docs/lineage/SOURCES.md`](docs/lineage/SOURCES.md) | **ARTEX ecosystem overview**: survey of the four ARTEX codebases (`ARTEX/` Python scanner, `artex-global/`, `BaaRai/ARTEX/`, `failsafe/artex/`), lineage tree, and the November 2026 prebuilt-image supply-chain backdoor incident. |
| [`docs/lineage/ARCHITECTURE.md`](docs/lineage/ARCHITECTURE.md) | **ARTEX architectural comparison**: comparison of the Python prototype and the three Go multi-agent forks (dual-graph data model, `intercept/`, `llmpool/`, MITM traffic capture). |
| [`docs/lineage/SKILLS.md`](docs/lineage/SKILLS.md) | **ARTEX skill inventory**: breakdown of the 10 agent skills shipped across the three Go forks (`api-recon`, `playwright-cli`, `scopesentry`, plus BaaRai's 7 offensive/RE playbooks). |

---

## Key Design Principles

1. **Dual Execution Modes (`passive` & `active`)**
   - **Passive review (`partex review <bundle>`)**: Byte-deterministic analysis of offline evidence bundles (`HttpExchange` captures and `ConfigExcerpt` records, including `format: openapi` contracts with revision metadata). No model calls ever enter the passive findings path.
   - **Active live testing (`partex test <engagement> --authorized`)**: Scoped live testing against targets declared in `engagement.json`—baseline capture, passive checks, active probes, and minimal PoC verification replay (`partex verify <run-id> <finding-id>`).

2. **Hard Authorization & Scope Gates in Code**
   - Every live run requires both a non-empty `authorization.attestation` in `engagement.json` and `--authorized` on the CLI.
   - `target.py` (`ScopedHttpClient`, built on `httpx2` with `follow_redirects=False`) is the **only** module that opens network sockets — the M7 browser harness is the one sanctioned exception (the browser opens its own sockets, gated at the automation layer's route hook, never by prompt). `target.py` enforces scheme/port allowlists, exact host matching with per-run pinned DNS resolution (DNS-rebinding protection while preserving `Host` header, SNI, and hostname certificate verification), path prefix and exclusion rules, and token-bucket RPS (`max_rps`) + request (`max_requests`) budgets.
   - Capture and probing run through the **three paths the ARTEX lineage ran** ([`DEPS.md` §5](DEPS.md)): the scoped Python client (M3, the Go client libraries' successor — active checks probe through it, and the agent's `http_request` tool rides it), operator-exported **HAR import** (M3, the MITM replacement), and the **browser capture harness** (M7) for authenticated SPA flows the plain client cannot reach.

3. **Evidence-Backed Findings That Always Survive**
   - Every persisted finding (`fn_*`) must reference one or more registered evidence records (`ev_*`); verified findings attach a replayable `Verification` record (`vf_*`).
   - Live evidence commits to SQLite **at capture time** (each exchange in its own transaction), and findings commit **per check** before any model-backed summarization, agent loop, or chat session runs.

4. **First-Class Secret Handling & Redaction**
   - Engagement `credentials` and multi-identity `roles` (for two-account BOLA/IDOR/BFLA boundary verification) accept only environment variable **names** (`[A-Z0-9_]+`), never inline secrets.
   - Captured exchanges record credential locations in `secret_fields`. Storage holds cleartext for deterministic local `verify` replay, while JSON/bundle exports, model-facing tool returns (`http_request`, `lookup_evidence`), and Logfire/OpenTelemetry spans redact `secret_fields` to `<redacted>` by default.

5. **Skills as Data, Checks as Installed Code**
   - **Skills** (`skills/<name>/SKILL.md` + `reference/*.md`) are pure Markdown data (no scripts, no `allowed-tools`, no `mcps`), exposed to agents on demand via `Capability(..., defer_loading=True)`.
   - **Checks** (`PassiveCheck` and `ActiveCheck` protocols) are trusted Python code loaded exclusively from installed distributions via the `partex.checks` entry-point group—never from arbitrary filesystem paths.

6. **Sandboxed Reviewer & Scoped Agent Runtimes**
   - **`partex chat <run-id>` (Read-Only Reviewer)**: Uses Monty-backed `CodeMode` attached directly on the reviewer agent (CLAI2's own `run.code_mode` and `run.speculative_code_mode` stay **off** so no host directory is mounted; `load_plugins=False`) with only three run-scoped, secret-redacted read tools (`list_findings`, `get_finding`, `lookup_evidence`), fresh per-invocation sandbox state, resource/time limits, and zero filesystem mounts, network doors, or store handles.
   - **`partex agent <engagement>` (Tester Agent)**: Executes the deterministic `test` pipeline first, then launches an interactive CLAI2 `chat()` session or a bounded `--auto` loop (`agent.run()` / `agent.iter()`) confined to the engagement scope by the tool layer (`http_request`, `run_check`, `request_verification`, `list_findings`, `lookup_evidence`, `list_surface`, `record_coverage` — plus the M7 `browser_*` harness tools for browser-driven flows) with full `tool_calls` audit logging.

7. **Supply-Chain Hardening & Hermetic Validation**
   - Informed by the November 2026 prebuilt-image backdoor in the upstream ARTEX ecosystem (see [`docs/lineage/SOURCES.md`](docs/lineage/SOURCES.md)), `partex` installs all dependencies, including `pydantic-*` and `pydantic-monty*`, from a hash-pinned `uv.lock` via `uv sync --frozen`, checks that lockfile in CI, and publishes no prebuilt artifacts.
   - All validation experiments ([`PLAN.md` §13](PLAN.md#13-validation-experiments)) run credential-free against a local stdlib fixture target application bound to `127.0.0.1`, with non-loopback sockets and live LLM calls blocked by session fixtures.

---

## Source & Reference Repositories

### 1. Runtime & Agent Stack (Locked PyPI Releases)

These packages resolve from PyPI through `uv.lock`; the repositories below are the upstream sources and the reference for their APIs. See [`PLAN.md` §3.1](PLAN.md#31-environment-and-dependencies).

| Repository | Former Sibling Path | Role in ParTEx |
|---|---|---|
| [`pydantic/pydantic-ai`](https://github.com/pydantic/pydantic-ai) | `../pydantic-ai` | Supplies `pydantic-ai-slim` (`Agent`, `TestModel`, `FunctionModel`, tool validation), `pydantic-ai-harness` (`Caching`, `RepairToolArguments`, `ToolOutputLimits`, `SystemReminders`, `Hooks`, deferred `Capability`), and `pydantic-clai2` (`chat()` terminal UI). |
| [`pydantic/monty`](https://github.com/pydantic/monty) | `../monty` | Supplies `pydantic-monty`, `pydantic-monty-client` (`crates/monty-python`), and `pydantic-monty-runtime` (`crates/monty-runtime`) for CLAI2's sandboxed Python Code Mode in the M5 read-only reviewer ([`RUNTIME.md`](RUNTIME.md)). |

### 2. ARTEX Lineage & Reference Platforms

Studied in [`docs/lineage/SOURCES.md`](docs/lineage/SOURCES.md), [`docs/lineage/ARCHITECTURE.md`](docs/lineage/ARCHITECTURE.md), and [`docs/lineage/SKILLS.md`](docs/lineage/SKILLS.md) for workflow patterns, evidence chains, scope enforcement, supply-chain lessons, and skill playbooks:

| Repository | Language / Stack | License | Summary & Relevance to ParTEx |
|---|---|---|---|
| [`BaaRai/ARTEX`](https://github.com/BaaRai/ARTEX) | Go 1.26.10 + Next.js 16 | AGPL-3.0 | **Depth-first English fork** of upstream ARTEX. Primary English reference for the 10 built-in skills, per-host egress pacing (`egress/`), browser traffic extension (`extension/`), and the 3-loop Recursive Self-Improvement (`RSI.md`) contract. Uses its own forked agent framework ([`BaaRai/Norma`](https://github.com/BaaRai/Norma)). |
| [`failsafe-security/artex`](https://github.com/failsafe-security/artex) | Go 1.26.3 + Next.js 16 | AGPL-3.0 | **Integrity-first hardened distribution** by FailSafe Cyber Frontier Labs, forked from [`RuoJi6/ARTEX`](https://github.com/RuoJi6/ARTEX) `v0.3.15` (last audited clean tag before the Nov 2026 Docker image backdoor). Reference for supply-chain hardening, source-only builds, runtime update refusal, and audit documentation (`UPSTREAM.md`, `audit/`). |
| [`jiwoochris/artex-global`](https://github.com/jiwoochris/artex-global) | Go 1.26.3 + Next.js 16 | AGPL-3.0 | **Breadth-first multilingual edition** (EN/KO/ZH/ES/JA UI and output with Chinese internal prompts), staged self-update with crash rollback (`selfupdate/`), and defender-facing detection content (`detections/` Sigma/Suricata/YARA rules). |
| [`Autumn-27/ARTEX`](https://github.com/Autumn-27/ARTEX) | Go + Next.js | AGPL-3.0 | Original upstream Go multi-agent rewrite (July 2026; repository unreachable as of October 2026) built on [`Autumn-27/norma`](https://github.com/Autumn-27/norma). Defined the shared dual-graph architecture (asset graph + exploration graph). |
| [`RuoJi6/ARTEX`](https://github.com/RuoJi6/ARTEX) | Go + Next.js | AGPL-3.0 | Intermediate upstream fork whose `v0.3.15` tag preserved the last clean pre-backdoor source tree used by `failsafe-security/artex`. |
| [`IlyassCODEX/ARTEX`](https://github.com/IlyassCODEX/ARTEX) | Python 3.8+ (Flask) | Unlicensed | Independent monolithic Python Flask reconnaissance scanner (internally branded **"FoxRecon"**, July 2025). Shares only the `ARTEX` name; documented in [`docs/lineage/SOURCES.md`](docs/lineage/SOURCES.md) and [`docs/lineage/ARCHITECTURE.md`](docs/lineage/ARCHITECTURE.md) for contrast. |

### 3. Skill Synthesis & Playbook Sources

Used in [`PARTX_SKILL_PLAN.md`](PARTX_SKILL_PLAN.md) and [`docs/lineage/SKILLS.md`](docs/lineage/SKILLS.md) to synthesize ParTEx's data-only `SKILL.md` playbooks and `reference/*.md` trees:

| Repository | License | Role in Skill Synthesis |
|---|---|---|
| [`transilienceai/communitytools`](https://github.com/transilienceai/communitytools) | MIT | 49 skill manifests and router `INDEX.md` (used as a coverage catalog). Provides deep scenario reference trees (`api-security` with 42 refs, `web-app-logic` with 55 refs, `authentication`, `client-side`), diff-normalization guidance (`regression-sweep`), and report schema/test packaging (`transilience-report-style`). |
| [`usestrix/strix`](https://github.com/usestrix/strix) | Apache-2.0 | 9 single-file skills (`application-security-testing`, `api-security-testing`, `web-app-penetration-testing`, CI/remediation skills). Used for concise assessment intake, asset-to-test mapping, result review, and handoff structure (rewritten to `partex` CLI conventions). |
| [`zhaoxuya520/reverse-skill`](https://github.com/zhaoxuya520/reverse-skill) | MIT | Playbook collection attributed by `BaaRai/ARTEX` for `api-security`, `edr-bypass-re`, and `patch-diff` (`patch-diff-exploit`). |
| [`ikow/php2shell-poc`](https://github.com/ikow/php2shell-poc) | MIT | Upstream PoC repository attributed by `BaaRai/ARTEX` for the `php2shell` LFI-to-RCE session-file-injection skill. |

---

## Implemented CLI

Available today (`uv run partex --help`):

| Command | Mode / Role | Coverage |
|---|---|---|
| `partex review <bundle>` | Passive | Deterministic passive checks (`header-security`, `js-analysis`) over an offline bundle. |
| `partex test <engagement>` | Active + Passive | Live baseline capture, active checks, passive checks over live captures, and PoC verification; requires `--authorized` (supports `--insecure` TLS). |
| `partex verify <run-id> <finding-id>` | Active | Re-runs the minimal verification recipe for one finding; requires `--authorized`. |
| `partex import-har <file.har>` | Import | Build a passive-reviewable bundle from an operator-exported HAR file (scope-filtered, MITM-free). |
| `partex export-bundle <run-id>` | Export | Export a live run's captured exchanges as a passive-reviewable bundle (secrets redacted by default). |
| `partex runs` | Query | Lists recorded runs from SQLite (`RunStore`). |
| `partex show <run-id>` | Export | Canonical JSON or text export of a run, secrets redacted by default. |
| `partex report` | Query | Cross-run rollup of findings, model spend, and tool calls. |
| `partex checks` | Registry | Installed checks, linked skills, and frontmatter lint. |
| `partex sandboxes` | Host | Detect which sandboxes (`monty`, `docker`, `podman`, `bubblewrap`) this host can run. |
| `/report`, `/secrets` (inside `partex agent`) | Operator only | `/report [path]` writes a redacted Markdown report; `/secrets [path]` writes unredacted secret values to a `0600` file and never prints them. The model has no tool for either. |
| `partex chat <run-id>` | Read-only + Model | Read-only review chat over a saved run (CLAI2 terminal). |
| `partex agent <engagement>` | Active + Model | Live operator-directed session (with `download_asset`, `discover_js_assets`, operator-confirmed `/scope add`, Monty `run_code` sandbox over read tools and downloaded artifacts, and optional `--search-model` native-only `web_search` on `anthropic:`, `google:`, or `google-cloud:` ADC); requires `--authorized`. |

## Planned CLI Surface

Not implemented yet, from [`PLAN.md` §8](PLAN.md#8-cli-surface):

| Command | Mode / Role | Description |
|---|---|---|
| `partex engage init <dir>` / `engage check <dir>` | Setup / Validation | Scaffold and validate `engagement.json` without sending traffic. |
| `partex summarize <run-id>` | Model | Generate or retry a reference-validated `ReviewSummary` over committed findings (M4). |
| `partex browse <engagement>` | Active + Browser (M7) | Browser capture harness via operator Chrome (CDP attach) or managed Chromium (requires `--authorized`). |

---

## Implementation Roadmap

### Engine Milestones ([`PLAN.md` §15](PLAN.md#15-milestones))

| Milestone | Focus | Key Deliverables | Validation Gate |
|---|---|---|---|
| **M0** | Environment | Standalone `uv` project, locked PyPI releases of `pydantic-ai` and `pydantic-monty` via `uv.lock`, hermetic socket & model-blocking test fixtures. | [§13.1](PLAN.md#131-greenfield-dependency-check) |
| **M1** | Passive Core | `models.py`, `bundle.py`, `ids.py`, `storage.py`, `export.py`, `engine.py` (passive path), `header-security` check, `review`/`runs`/`show`/`checks` CLI. | [§13.3 (a–d)](PLAN.md#133-engine-repeatability-and-failure-policy) |
| **M2** | Registry & Skill Separation | `registry.py`, data-only skills + frontmatter lint (D6), entry-point check loading, `banner-leak` fixture distribution, `--skill-dir`. | [§13.2](PLAN.md#132-skill-separation) |
| **M3** | Live Testing | `engagement.py` (incl. `roles` D2), `scope.py`, `target.py` (`ScopedHttpClient`), `verify.py`, per-capture/per-check commits, local fixture target app, `version-disclosure` active check, `engage`/`test`/`verify`/`export-bundle` CLI. | [§13.3 (e)](PLAN.md#133-engine-repeatability-and-failure-policy), [§13.4](PLAN.md#134-scope-gate-capture-and-verification) |
| **M4** | Summarization | `summarize.py`, `partex summarize`, two-layer finding ID reference validation, retry & timeout handling. | [§13.5](PLAN.md#135-model-and-terminal-integration) |
| **M5** | Agent & Reviewer | `agent_adapter/`, `partex chat` (read-only Monty Code Mode + opt-in speculative reads evaluation per [`RUNTIME.md`](RUNTIME.md)), `partex agent` (interactive CLAI2 + `--auto`), hook-based `tool_calls` audit table. | [§13.4 (agent)](PLAN.md#134-scope-gate-capture-and-verification), [§13.5](PLAN.md#135-model-and-terminal-integration) |
| **M6** | Hardening | 100% branch coverage target (with audited I/O pragmas), operator/engagement authoring docs, recorded validation experiment results. | All §13 gates |
| **M7** | Browser Capture Harness | `browser.py` (Playwright over CDP — operator-launched Chrome primary, managed Chromium for credential-free discovery and CI), `partex browse` CLI, route-interception scope gate with budget accounting, blanket `secret_fields` marking of browser captures, fixture SPA, agent `browser_*` tools. | [§13.6](PLAN.md#136-browser-capture-harness-m7) |

### Post-M6 Skill Slices ([`PARTX_SKILL_PLAN.md` §4](PARTX_SKILL_PLAN.md#4-re-ranked-priorities-dual-mode))

| Priority / Slice | Skill & Check(s) | Mode(s) | Scope |
|---|---|---|---|
| **P0** (M1–M3) | `header-review` (`header-security`), `version-disclosure`, `banner-leak` | Passive & Active | Built-in milestone fixtures proving passive determinism, registry separation, and probe → verify → replay. |
| **P1.1 / S1** | `api-inventory` (`api-contract-conformance`) | Passive | Operation inventory from bundle `HttpExchange`s matched against `format: openapi` `ConfigExcerpt` contracts (D1); normalized operation keys. |
| **P1.2 / S2** | `authorization-testing` (`authz-boundary`) | Active + Passive | Two-role BOLA/IDOR/BFLA boundary probes over the S1 operation inventory using engagement `roles` (D2) and replayable `verify_recipe`s. |
| **P1.3 / S3** | `auth-session-controls` (`session-cookie-config`, `token-weakness`) | Passive + Active | Passive cookie/token policy review + active probes for expired-token replay, logout invalidation, and token confusion. |
| **P2.1 / S4** | `regression-verify` | Passive + Verify | Re-verification workflows via `partex verify`, live export-bundle round-trips, drift classes (`confirmed` → `not_reproduced`), and prioritization. |
| **P2.2 / S5** | `gateway-policy` | Passive + Active | Declared contract/gateway limits vs. verified rate/size limits within engagement budgets; deprecated operation detection. |
| **P2.3 / S6** | `coverage-validation` | Passive | Defensive CI-result import (blocked on D4) and owner role/tenant matrix validation. |

---

## Legal & Authorization Notice

ParTEx and the reference projects documented in this repository are designed strictly for **authorized security assessments** of systems you own or have explicit written permission to test. In `partex`, authorization attestation and target scope boundaries are enforced as non-bypassable runtime checks before any network socket is opened.
