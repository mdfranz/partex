# Project Lineage & Evolution: partex

## Overview

`partex` is a standalone Python 3.14 web and API security testing framework built on the Pydantic AI, CLAI2, and Monty stack. It connects deterministic passive traffic analysis, authorized scoped live probing, replayable exploit verification, and model-assisted investigation workflows to evidence persisted in SQLite.

The project grew out of a comparative study of the external ARTEX security platforms (`ARTEX/` Python Flask scanner, `artex-global/`, `BaaRai/ARTEX/`, and `failsafe/artex/`) but shares **no code, database schema, or runtime dependency** with any ARTEX fork. Historical fork surveys and skill inventories live separately in [`docs/lineage/SOURCES.md`](docs/lineage/SOURCES.md), [`docs/lineage/ARCHITECTURE.md`](docs/lineage/ARCHITECTURE.md), and [`docs/lineage/SKILLS.md`](docs/lineage/SKILLS.md).

This document traces `partex`'s own evolution through **86 merged PRs** on `main` (November 18–22, 2026), capturing:
- **Code and capability changes**, from the repository scaffold through the passive engine, live probing, agent sessions, and the OpenAPI and authorization checks
- **Living document evolution** across [`PLAN.md`](PLAN.md), [`RUNTIME.md`](RUNTIME.md), [`DEPS.md`](DEPS.md), [`PARTX_SKILL_PLAN.md`](PARTX_SKILL_PLAN.md), [`README.md`](README.md), [`CLAUDE.md`](CLAUDE.md), and `docs/`
- **Technical decisions and concerns addressed**, including supply-chain hardening, scope and write safety, secret redaction, sandbox isolation, detection precision, and type enforcement

As of the latest merge on `main`, the repository registers 7 entry-point checks in [`pyproject.toml`](pyproject.toml) (`api-contract-conformance`, `authz-boundary`, `header-security`, `js-analysis`, `openapi-spec-review`, `server-error`, `version-disclosure`), ships 8 data-only skill playbooks under `skills/`, uses SQLite RunStore schema v4, and provides two CLAI2-backed sessions: a read-only reviewer (`partex chat`) and a live interactive tester (`partex agent`), both using Monty Code Mode (`run_code`) for sandboxed reads.

## How to Read This Document

- **Phases** are grouped by the calendar days on which their work landed on `main`, so each one reads as a period of development rather than a numbered release.
- **`#NN` references** are GitHub pull request numbers (issue numbers where a PR number is not available). Each one leads to the full discussion, diff, and review thread for that change.
- **File links** point to the file as it exists on `main` today. Some referenced files, such as the `docs/lineage/` historical notes, are kept intentionally and are not current design documents.
- **Commit-level history** is not repeated here. To trace a specific change, use `git log --oneline -- <path>` on the file of interest, or open the referenced PR.

---

## Phase 1: Pre-Implementation Architecture, Scope Pivot & Skill Roadmap (November 18, 2026)

**Outcome:** By the end of the day the project had a written spec set, a settled scope model, and a rule that no code would be written before those decisions were recorded.


### Key Accomplishments
- **Initial Workspace & Fork Survey**: Added the initial planning set (`PLAN.md`, `ARCHITECTURE.md`, `SKILLS.md`, and fork-comparison `README.md`) documenting the Python `ARTEX/` scanner alongside the three Go forks (`artex-global/`, `BaaRai/ARTEX/`, `failsafe/artex/`) and the November 2026 prebuilt-image backdoor incident.
- **Offensive Scope Pivot & Package Identity**: Replaced the offline-only defensive-review sketch with full authorized offensive testing — engagement files with hard scope gates and attestation, active probing via a scoped HTTP client, replayable exploit verification, and interactive and `--auto` agent loops alongside deterministic passive review. Aligned the design with Pydantic AI, Harness, and Logfire patterns, and renamed the package from `artex-web` (`artex_web`) to `partex`.
- **Skill Taxonomy & Staged Playbooks**: Documented web/API skill priorities and source synthesis, consolidated them into [`PARTX_SKILL_PLAN.md`](PARTX_SKILL_PLAN.md), and amended `PLAN.md` with deltas D1, D2, and D6. Staged initial P0 (`header-review`, `version-disclosure`, and fixture `banner-leak`) and P1 (`api-inventory`, `authorization-testing`, `auth-session-controls`) data-only skills with license provenance and check-boundary hardening.
- **Runtime, Dependency & Multi-Agent Conventions**: Separated execution boundaries into [`RUNTIME.md`](RUNTIME.md), added [`DEPS.md`](DEPS.md) covering the three-path capture model and the planned browser harness, resolved pre-implementation inconsistencies across layout and Code Mode, and established [`CLAUDE.md`](CLAUDE.md) with an [`AGENTS.md`](AGENTS.md) symlink for parallel multi-agent work.

### Document Evolution
- `README.md` shifted from the multi-fork ARTEX comparison to a `partex`-centric overview and documentation index.
- `WEB_API_SKILL_PRIORITIES.md` and `SOURCE_SKILL_SYNTHESIS.md` were retired and folded into [`PARTX_SKILL_PLAN.md`](PARTX_SKILL_PLAN.md), establishing `name == dirname` and required `modes` frontmatter.
- [`PLAN.md`](PLAN.md), [`RUNTIME.md`](RUNTIME.md), and [`DEPS.md`](DEPS.md) became the canonical three-document specification split: architecture and roadmap, sandbox and runtime lifetimes, and dependency and library selection.

### Technical Decisions & Concerns Addressed
- **Supply-chain isolation from ARTEX**: Responded to the November 2026 upstream ARTEX Docker image backdoor by committing to a greenfield Python implementation with zero runtime, schema, or package dependency on any ARTEX fork.
- **Skills as inert data**: Defined Markdown skill playbooks as purely descriptive guidance (never imported, executed, or interpreted by the engine), while executable check code loads solely from installed distributions.
- **Evidence-first durability**: Required captured exchanges to be committed immediately at capture time and deterministic findings to persist before any model stage, so mid-run crashes or LLM failures cannot lose paid-for evidence.

---

## Phase 2: Foundation, Supply-Chain Hardening & Early Live-Probing Spine (November 18–19, 2026)

**Outcome:** A working passive pipeline (bundle in, findings and export out) backed by a hermetic test suite, plus the first scoped live probe that cannot send traffic outside the engagement.


### Key Accomplishments
- **Scaffold & Supply-Chain Pivot (PR `#12`; PR `#14`; PRs `#16`, `#17`, `#32`)**: Built the Python 3.14 package layout, CI workflow, [`scripts/check_greenfield.py`](scripts/check_greenfield.py), and [`scripts/check_httpx2_gate.py`](scripts/check_httpx2_gate.py). Switched `pydantic-*` and `pydantic-monty*` from local `[tool.uv.sources]` path overrides to hash-pinned PyPI wheels in `uv.lock` (`#13`/`#14`), enforced a 2-day `exclude-newer` supply-chain cool-off (`#16`), documented unsigned repo commits in `CLAUDE.md` (`#17`), and restored the `PLAN.md` §1–§3 sections inadvertently dropped during `#14` (`#32`).
- **Hermetic Harness & Core Contracts (PRs `#29`, `#15`)**: Added hermetic test fixtures that block non-loopback network traffic, live model calls, and external telemetry (`tests/conftest.py`, `#2`). Implemented `models.py`, `ids.py` (canonical JSON encoding and content-hash IDs `ev_`, `fn_`, `vf_`, `eng_`), `errors.py`, the `checks/__init__.py` protocols, and `redact()` (`#3`).
- **Passive Pipeline & CLI (PRs `#18`, `#19`, `#30`, `#34`, `#42`, `#46`)**: Implemented bundle loading with valid and malformed fixtures (`bundle.py`, `#4`), a SQLite `RunStore` with WAL and single-writer/read-only-reader separation (`storage.py`, `#5`), the `header-security` passive check (`#6`), `engine.run_review` (`#8`), canonical redacted JSON export (`export.py`, `#7`), and CLI subcommands `review`, `runs`, `show`, and `checks`, with exit code `3` for findings and optional `--logfire` (`cli.py`, `#9`).
- **Early Live-Probing Spine (PRs `#31`, `#33`, `#41`, `#45`)**: Added engagement schema validation E1–E7 and hostile-URL scope matching (`engagement.py`, `scope.py`, `#11`). Built `ScopedHttpClient` with a send-time scope gate, DNS pinning, and request/RPS budgets (`target.py`, `#20`). Delivered the first live probe (`partex test`, the `version-disclosure` check, and local `fixtures/target_app/app.py`, `#21`), and added role-scoped client handles that share one budget and DNS pin table across per-role sessions (`roles.py`, `#23`).
- **Contract Hardening & Store Schema v2 (PRs `#43`, `#39`, absorbing `#35`)**: Converted HTTP headers from flattened dicts to wire-order `(name, value)` pairs. Added `Finding.subject` to `fn_` hashes so distinct findings sharing a title and evidence no longer collide. Required validated JSON index paths in `secret_fields` (`$.http.request.headers[i][1]`), made `ActiveCheck.probe` async and returning `HttpEvidence`, enforced `PARTEX_[A-Z0-9_]+` env var naming for credentials, unified `engagement_id`, and bumped SQLite to **schema v2** (refusing v1 stores).
- **Skill Research Corpus (PR `#47`)**: Tracked curated testing methodology references under [`docs/skills/README.md`](docs/skills/README.md).

### Document Evolution
- [`PLAN.md`](PLAN.md), [`DEPS.md`](DEPS.md), [`RUNTIME.md`](RUNTIME.md), [`README.md`](README.md), and [`CLAUDE.md`](CLAUDE.md) were updated to remove sibling checkouts in favor of registry-locked PyPI dependencies (`#13`), add the 2-day cool-off rule (`#16`), record the unsigned-commit configuration (`#17`), and document the `#39` contract changes.
- PR `#32` restored the `PLAN.md` §1 constraints, §2 architecture diagram, and §3 package layout lost in PR `#14`.

### Technical Decisions & Concerns Addressed
- **Supply-chain hardening (`#13`, `#16`)**: Hash-pinned `uv.lock` verified by `check_greenfield.py`, combined with `exclude-newer = "2 days"`, keeps freshly published compromised PyPI releases or local path leaks out of the environment.
- **Fail-open redaction & header fidelity (`#35`, `#39`)**: Index-based `secret_fields` paths validated at evidence construction, and wire-order `(name, value)` header pairs, prevent case-sensitivity misses and preserve repeated `Set-Cookie` headers.
- **DNS rebinding & host boundary enforcement (`#11`, `#20`)**: `target.py` is the sole socket opener. It pins resolved IPs and enforces engagement scope and rate/request budgets at send time rather than at planning time.

---

## Phase 3: Agent Layer, Verification Runner, Registry & Security Hardening (November 19, 2026)

**Outcome:** Operators could review a finished run in a read-only chat, drive a live agent session under scope guardrails, and replay a finding's recipe to confirm it, with early scope and capture bypasses closed.


### Key Accomplishments
- **Read-Only Reviewer & Gateway Routing (PRs `#50`, `#49`)**: Delivered `partex chat <run-id>` over `pydantic_clai2.chat` (`load_plugins=False`, pinned settings), `models_config.resolve_model` supporting full pydantic-ai model strings and Pydantic AI Gateway routes (normalizing a trailing-route `PYDANTIC_AI_GATEWAY_BASE_URL`), run briefings, and redacted, framed read tools (`list_findings`, `get_finding`, `list_evidence`, `lookup_evidence`) in [`src/partex/agent_adapter/reviewer.py`](src/partex/agent_adapter/reviewer.py).
- **Scope & Target-Capture Hardening (PRs `#55`, `#56`)**: Closed scope path-matching bypasses (`//`, case sensitivity, segment boundaries, double-encoding refusal, `#36`). Enforced response-body size caps with body notes, and automatically marked target-issued `Set-Cookie` headers as secret (`#37`).
- **Interactive Live Agent & Live Scope Extension (PRs `#57`, `#63`, `#68`)**: Added the cancellation-shielded `engine.live_session()` and `partex agent <engagement>` ([`src/partex/agent_adapter/tester.py`](src/partex/agent_adapter/tester.py)), with GET/HEAD/OPTIONS `http_request`, `run_check`, `--from` prior-run reads (`list_runs`), `llm_usage` persistence, and local `tool_calls` auditing that omits header values. Added operator-confirmed `/scope add` via [`src/partex/agent_adapter/scope_plugin.py`](src/partex/agent_adapter/scope_plugin.py) (`#54`, `#64`).
- **Plugin Registry & Verification Runner (PRs `#60`, `#48`)**: Built [`src/partex/registry.py`](src/partex/registry.py) for `partex.checks` entry-point loading, skills-as-data discovery (`--skill-dir`), and D6 frontmatter linting (`#25`). Implemented [`src/partex/verify.py`](src/partex/verify.py) and `partex verify <run-id> <finding-id>` to replay minimal PoC recipes and record verdicts with replay evidence (`#22`).
- **Cross-Run Reporting, Local JSONL Telemetry & Launcher (PRs `#62`, `#66`, `#67`, `#70`)**: Added the `partex report` cross-run rollup and `llm_usage` visibility in `show` (`#61`), enabled default local JSONL span logging in [`src/partex/telemetry.py`](src/partex/telemetry.py) (`#67`), and evolved `probe.sh` into [`partex.sh`](partex.sh), with authorization prompts, flags, `--resume`, and `list` (`#66`, `#70`).

### Document Evolution
- [`PLAN.md`](PLAN.md) was updated with live-agent behavior (`#54`), operator-confirmed `/scope add` (`#64`), default local JSONL span logging (`#67`), and refreshed §15 status tables.
- `.gitignore` replaced a fragile top-level allowlist with targeted ignores for local SQLite databases and probe logs.

### Technical Decisions & Concerns Addressed
- **Prompt injection & tool confinement (`#49`, `#54`, `#64`)**: Wrapped all model-facing evidence returns with `pydantic_ai.framing` as untrusted target data, restricted `pydantic_clai2` imports to `agent_adapter/`, kept findings and scope non-writable by the model, and gated live host additions behind explicit operator confirmation via `/scope add`.
- **Path-matching bypasses & unbounded response captures (`#36`, `#37`)**: Refused double-encoded URLs, checked multiple path interpretations at segment boundaries, capped captured response bodies, and ensured `target.py` marks response `Set-Cookie` values secret and records requested URLs rather than pinned IP strings.
- **Auditability & spend visibility (`#54`, `#61`, `#67`)**: Recorded every agent tool invocation in `tool_calls`, tracked token usage in `llm_usage`, and wrote local telemetry traces by default for live and model commands.

---

## Phase 4: JS Analysis, HAR Round-Trip, Monty Code Mode, Precision Hardening & Lineage Split (November 19–20, 2026)

**Outcome:** Passive analysis now covers JavaScript and HAR round-trips, live sessions run passive checks automatically, agent code runs in a read-only sandbox, and false-positive rates dropped on both Linux and macOS CI.


### Key Accomplishments
- **Full JS Download & Tree-Sitter AST Check (PRs `#75`, `#69`)**: Added `ArtifactEvidence` (`kind='artifact'`, mode-`0600` files under `<db>.artifacts/`, with `file_path` excluded from `ev_*` content hashes), the `download_asset` and `discover_js_assets` tools, and the `js-analysis` check and skill, which parse JavaScript with `tree-sitter` and `tree-sitter-javascript`.
- **HAR Round-Trip, Live Passive Checks & Probe Seeding (PRs `#78`, `#90`, `#95`)**: Delivered `partex import-har` and `partex export-bundle` ([`src/partex/har_io.py`](src/partex/har_io.py), `#28`), automatic passive-check execution over live-captured evidence in `partex test` and `agent` (`#51`), and bundle-surface seeding into scoped live probe candidates (`--bundle`, [`src/partex/probes.py`](src/partex/probes.py), `#76`).
- **Precision Hardening, Catch-All Detection, Opt-In TLS & CI Matrix (PRs `#77`, `#82`, `#87`, `#91`, `#94`)**: Persisted scope extensions and audit rows atomically (`#72`) and fixed relative-path `partex.sh list` (`#73`). Added opt-in `--insecure` / `tls.verify=false`, recorded on runs and evidence (`#71`). Added a Linux x86_64 and macOS CI matrix with portable socket-path handling (`#86`). Hardened `header-security` (case-insensitive lookups, HSTS, cookie, CORS, and framing precision, plus report-only CSP) and `version-disclosure` (`path_prefixes` anchoring, banner dedup) (`#38`, `#52`, `#80`, superseding closed PR `#92`). Added catch-all 200 SPA detection, recording error pages as not exercised (`#53`).
- **Monty Code Mode, Deferred Skills & Operator Exports (PRs `#85`, `#89`, `#97`, `#98`, `#99`, `#105`, `#106`)**: Added host sandbox detection (`partex sandboxes`, [`src/partex/sandboxes.py`](src/partex/sandboxes.py), `#84`) and operator-only `/report` and `/secrets` (`0600` export, never echoed to chat, [`src/partex/operator_export.py`](src/partex/operator_export.py), `#88`, with a coverage fix in `#96`/`#97`). Surfaced skills as deferred capabilities via `load_capability` ([`src/partex/agent_adapter/skills.py`](src/partex/agent_adapter/skills.py), `#59`). Shipped live-session Monty Code Mode, where `run_code` wraps pure read tools with a per-run read-only `/artifacts` mount and no network, shell, or write access (`#83`, `#103`). Added the `save_report` host tool (`#104`) and disabled CLAI2's session namer, which tripped its 250-token limit on reasoning models (`#102`).
- **Pydantic Stack Upgrade & Selective Cool-Off (PRs `#108`, `#107`)**: Bumped `pydantic-ai-slim`, `pydantic-graph`, `pydantic-ai-harness`, and `pydantic-clai2` to `2.71`/`0.71`, keeping the global 2-day cool-off and exempting only the named `pydantic-*` packages via `exclude-newer-package`.

### Document Evolution
- **Lineage Separation (PR `#93`)**: Moved `ARCHITECTURE.md`, `SKILLS.md`, and `SOURCES.md` out of the repo root into [`docs/lineage/`](docs/lineage/SOURCES.md) with explicit historical-reference banners, keeping root docs focused on `partex`.
- Amended `PLAN.md` §10 / D7 (`#44`, `#79` for async `ActiveCheck.probe` and `HttpEvidence`-returning `TargetClient`), [`DEPS.md`](DEPS.md) §8.9 (sanctioned `tree-sitter` runtime addition, `#69`), [`RUNTIME.md`](RUNTIME.md) (Monty Code Mode and per-run artifact isolation, `#83`), [`CLAUDE.md`](CLAUDE.md) (permitting small unrelated issues to share one PR), and synced [`docs/skills/README.md`](docs/skills/README.md) (`#81`).

### Technical Decisions & Concerns Addressed
- **Non-executing JS inspection (`#69`)**: Chose `tree-sitter` AST parsing over regexes or executing untrusted target JavaScript, amending the zero-new-runtime-deps assumption explicitly in `DEPS.md`.
- **Per-run sandbox isolation (`#83`, `#104`)**: Mounted only `<db>.artifacts/<run_id>` read-only inside Monty, and exposed `save_report` as a host tool rather than giving the sandbox writable host filesystem mounts.
- **Signal quality & OS portability (`#38`, `#52`, `#53`, `#80`, `#86`)**: Eliminated false positives from header case sensitivity, report-only CSPs, and SPA catch-all routes. Anchored active probes under permitted `path_prefixes`, and fixed macOS Unix-socket path length and OpenSSL error portability in CI.

---

## Phase 5: Web Research, URL Allowlists, State-Changing Write Gates & OpenAPI/Authz Checks (November 21–22, 2026)

**Outcome:** Engagements gained exact URL allowlists, state-changing requests required explicit operator approval, and the project added OpenAPI contract checks and cross-role authorization probing.


### Key Accomplishments
- **Native Web Search & Persistent Research (Schema v3; PRs `#112`, `#142`, `#143`, `#145`, `#147`)**: Added optional `web_search` ([`src/partex/agent_adapter/search.py`](src/partex/agent_adapter/search.py)), executed in an isolated one-shot agent with `WebSearch(local=None)` across `anthropic:` (`allowed_callers=['direct']`), `google:`, `google-cloud:` (defaulting to `global`), and `openai:` Responses API. Persisted results to the SQLite `web_research` table (**schema v3**, `#113`), capped returned sources at 20, and audited failed research writes (`#146`).
- **Batch Probing, URL Allowlists, User-Agent & Shared State (PRs `#115`, `#122`, `#148`, `#150`, `#158`)**: Added concurrent read-only `http_request_batch` with per-item audit (`#109`). Added an exact authorized-URLs allowlist (`Scope.urls`, `--urls-file`, `partex.sh -u` with `--recursive`, implicit 80/443 handling, typed scope denials, `#121`). Added an engagement default `User-Agent` (`http.user_agent` / `--user-agent`, `#135`). Unified local state under `PARTEX_STATE_DIR` / `$XDG_STATE_HOME/partex` ([`src/partex/paths.py`](src/partex/paths.py)), while isolating `partex.db.clai2/` and temporary live-agent terminal storage (`#148`). Recorded and announced TLS verification state for hosts added via `/scope add` under `-k` (`#101`).
- **Report Lifecycle, Noise Reduction & Storage Atomicity (PRs `#131`, `#136`–`#139`, `#149`, `#161`)**: Added the passive `server-error` check for 5xx responses and its skill playbook (`#128`). Grouped passive `header-security` findings by `(host, rule)` with capped affected-URL lists (`#127`, `#140`). Added read-only `list_reports` / `read_report` tools and the `partex reports` CLI, with TTY control-sequence neutralization (`#123`, `#141`). Added actionable near-miss host and rule-ID refusal hints (`#125`), a `download_asset` audit status, and lazy JSONL log creation (`#126`). Fixed storage integrity error typing (`StoreError`), rollback-safe error preservation, and atomic `requests_spent` accounting (`#40`).
- **State-Changing Write Policy & Operator Approval Gate (Schema v4; PRs `#120`, `#166`, `#171`, `#182`)**: Settled engagement `scope.allowed_methods`, `scope.max_write_requests`, `ws`/`wss` scope mapping, and one shared approval primitive in `PLAN.md` §4.1/§4.2 (`#119`). Implemented operator-approved `POST`/`PUT`/`PATCH`/`DELETE` in `http_request` via [`src/partex/agent_adapter/approval.py`](src/partex/agent_adapter/approval.py): a `WriteGate` with a CLAI2 picker, fail-closed headless denial, and **schema v4** adding `runs.write_requests_spent` (`#65`, `#171`, `#182`).
- **OpenAPI Suite & Authorization Probing (PRs `#151`, `#164`, `#165`, `#167`, `#168`, `#169`)**: Added the OpenAPI subset resolver and the `api-contract-conformance` check ([`src/partex/openapi_resolver.py`](src/partex/openapi_resolver.py), [`src/partex/checks/api_inventory.py`](src/partex/checks/api_inventory.py), `#24`). Registered live-captured OpenAPI 3.0/3.1 documents as `ConfigEvidence` (`#155`), adopted the already-locked `referencing` package for `$ref` resolution (`#153`), and added the passive `openapi-spec-review` check and skill (`#156`). Correlated target-request Logfire spans with `run_id` (`#58`). Shipped the `authz-boundary` check for BOLA/IDOR/BFLA role-pair probing ([`src/partex/checks/authorization.py`](src/partex/checks/authorization.py), `#27`).

### Document Evolution
- [`README.md`](README.md) was rewritten into a streamlined quick-start with live probe examples, OpenRouter and Pydantic AI Gateway configuration, tool tables, and the XDG state layout (`#114`, `#148`).
- [`PLAN.md`](PLAN.md) was amended with the `#119` method and write-budget policy and reconciled its §15 status tables (`#163`, `#162`). [`DEPS.md`](DEPS.md) §3.1 was amended for `referencing` (`#153`), and [`RUNTIME.md`](RUNTIME.md) documented the `anthropic:`, `google:`, `google-cloud:`, and `openai:` search behavior (`#111`, `#144`).

### Technical Decisions & Concerns Addressed
- **Defense-in-depth for state-changing requests (`#119`, `#65`, `#171`)**: Write methods require both the engagement allowlist and budget (`allowed_methods`, `max_write_requests`), enforced at send time in `ScopedHttpClient`, and per-action (or session-scoped) operator approval via `WriteGate`. Writes are denied automatically when no terminal is attached.
- **Terminal escape safety & finding noise (`#127`, `#140`, `#141`)**: Neutralized terminal control sequences when printing saved reports to a TTY, and grouped repetitive per-URL header findings by `(host, rule)` with capped URL lists.
- **Zero host sockets in web search (`#111`, `#143`)**: Ran provider-native web search via `WebSearch(local=None)` in a separate zero-tool, zero-DB agent, so searches never expose engagement secrets or open local host sockets.
- **Standards-compliant `$ref` resolution (`#153`)**: Replaced custom subset `$ref` handling with the already-locked `referencing` package, without expanding external dependency risk.

---

## Phase 6: Strict Test Type-Checking, Skill Alignment & End-to-End Fixture Coverage (November 22, 2026)

**Outcome:** The test suite is now type-checked as strictly as the source, skill metadata matches check behavior, and end-to-end tests cover saved passive outcomes and sandboxed research isolation.


### Key Accomplishments
- **Pyright Strict Over `tests/` (PRs `#197`, `#160`)**: Added `tests/pyrightconfig.json` and wired it into CI, bringing test type errors down to 0 and tightening test assertions so they can't pass against empty evidence.
- **Skill Modes & Severity Alignment (PRs `#199`, `#203`)**: Surfaced deduplicated `skill.modes` in deferred capability catalog descriptions ([`src/partex/agent_adapter/skills.py`](src/partex/agent_adapter/skills.py), `#186`). Aligned permissive-CORS severity in [`skills/header-review/SKILL.md`](skills/header-review/SKILL.md) (`high` → `medium`) with the reference tables and check output (`#201`).
- **End-to-End Passive Outcome & Sandboxed Research Tests (PRs `#207`, `#202`)**: Added clean, inert, and server-error bundle fixtures (`clean-headers`, `clean-openapi`, `js-inert`, `server-error`) that verify saved passive-check outcomes end to end in [`tests/test_cli.py`](tests/test_cli.py) (`#178`). Added integration coverage in [`tests/test_agent_tester.py`](tests/test_agent_tester.py) asserting that `run_code` sandboxed `list_research`/`lookup_research` reads stay isolated across runs and keep audit metadata clean (`#179`).

### Document Evolution
- [`fixtures/bundles/README.md`](fixtures/bundles/README.md) was expanded to catalog the new outcome-coverage fixtures (`#207`).
- [`skills/header-review/SKILL.md`](skills/header-review/SKILL.md) was updated for severity consistency (`#203`). Open documentation issues (`#170`, `#172`, `#173`) track reconciling the root tool, skill, and check inventories with recent additions.

### Technical Decisions & Concerns Addressed
- **Test contract drift (`#160`)**: Running strict pyright over `tests/` via a dedicated config keeps stale test doubles and untyped fixtures from diverging from production contracts.
- **Playbook-to-code consistency (`#186`, `#201`)**: Exposing `skill.modes` in capability discovery, and matching skill guidance severities to check output, keeps agent reasoning aligned with deterministic findings.
- **Cross-run research isolation (`#179`)**: Verified in Code Mode that `web_research` lookups stay scoped to the active target run and that answer text is omitted from `tool_calls` audit metadata.

---

## Cross-Cutting Concerns Addressed

| Concern Track | Risk / Problem Addressed | Mitigation Landed | Key Issues / PRs |
|---|---|---|---|
| **Supply-Chain & Dependency Hygiene** | Upstream ARTEX image backdoor; unvetted PyPI releases; local path leaks | Greenfield Python package, hash-pinned `uv.lock`, 2-day `exclude-newer` cool-off (exempting only named `pydantic-*` packages), `check_greenfield.py`, explicit `DEPS.md` review for `tree-sitter` & `referencing` | `#13`, `#14`, `#16`, `#69`, `#107`, `#153` |
| **Scope, Authorization & Write Safety** | Out-of-scope targets, DNS rebinding, URL-encoding bypasses, accidental state mutations | Engagement attestation + E1–E7 validation, send-time gate & IP pinning in `target.py`, canonical path/double-encoding refusal, exact `--urls-file` allowlists, `/scope add` confirmation, `allowed_methods` + `max_write_requests` + `WriteGate` | `#11`, `#20`, `#36`, `#64`, `#72`, `#119`, `#121`, `#65`, `#171` |
| **Secret Safety & Untrusted Data** | Credential leaks in exports, logs, and LLM context; prompt injection; TTY escape injection | `PARTEX_*` env var names only, validated `secret_fields` JSON paths, `Set-Cookie` value-only marking, `pydantic_ai.framing`, `/secrets` `0600` file-only export, `-k` TLS disclosure, TTY control neutralization | `#3`, `#35`, `#37`, `#39`, `#49`, `#71`, `#88`, `#101`, `#141` |
| **Storage Durability & Schema Evolution** | Lost mid-run evidence; non-atomic counters; silent schema mismatch | Capture-time commits, WAL single-writer/read-only-reader split, `StoreError` & rollback-safe handling, atomic `requests_spent`/`write_requests_spent`, explicit schema v1 → v4 migrations/refusals, XDG state layout | `#5`, `#39`, `#40`, `#113`, `#65`, `#148` |
| **Detection Precision & Signal-to-Noise** | Header-case false positives; SPA catch-all noise; per-URL finding spam; severity drift | Case-insensitive header-pair inspection, report-only CSP & framing handling, catch-all 200 detection, prefix-anchored probes, `(host, rule)` grouping with URL caps, skill severity alignment | `#38`, `#52`, `#53`, `#80`, `#127`, `#140`, `#201` |
| **Sandbox & External Research Isolation** | Model host filesystem/socket escape; cross-run data leakage | Monty `run_code` with read-only per-run `/artifacts` mount and zero host network/shell/write tools; `save_report` host tool; isolated zero-tool `WebSearch(local=None)` agent | `#83`, `#84`, `#103`, `#104`, `#111`, `#143`, `#146`, `#179` |
| **Testing, Determinism & Type Safety** | Non-hermetic network/LLM tests; OS drift; untyped test doubles | Network/model/telemetry blocking in `conftest.py`, Linux + macOS CI matrix, strict pyright across `src/`, `scripts/`, and `tests/`, end-to-end outcome bundle fixtures | `#2`, `#86`, `#160`, `#178` |

---

## Document Evolution Summary

| Document | Evolution Arc |
|---|---|
| [`PLAN.md`](PLAN.md) | Began as an offline defensive-review plan, pivoted to full offensive dual-mode scope, became `partex`, recorded 6 superseded assumptions under *Design evolution* (`#13`, `#69`, `#39`/`#44`, `#71`, `#119`), and serves as the living architecture and §15 status ledger. |
| [`RUNTIME.md`](RUNTIME.md) | Split out in Phase 1 to own runtime boundaries, sandbox lifetimes, and failure isolation. Evolved to specify Monty Code Mode per-run `/artifacts` isolation (`#83`), multi-provider `web_search` isolation (`#111`, `#144`), and the planned browser harness. |
| [`DEPS.md`](DEPS.md) | Introduced in Phase 1 to settle library choices and the three-path capture model. Pivoted from sibling checkouts to PyPI-locked wheels (`#13`), documented the sanctioned `tree-sitter` (`#69`) and `referencing` (`#153`) runtime additions, and retains the `httpx2` gate and planned browser-harness notes. |
| [`PARTX_SKILL_PLAN.md`](PARTX_SKILL_PLAN.md) | Consolidated `WEB_API_SKILL_PRIORITIES.md` and `SOURCE_SKILL_SYNTHESIS.md`, defined the five-family skill taxonomy, engine deltas D1–D6, and the staged roadmap. |
| [`README.md`](README.md) | Progressed from an ARTEX fork overview to a doc index, then to a streamlined operator quick-start covering offline review, live local probes, OpenRouter/Gateway routing, tool inventories, and the `PARTEX_STATE_DIR` layout (`#114`, `#148`). |
| [`CLAUDE.md`](CLAUDE.md) / [`AGENTS.md`](AGENTS.md) | Established multi-agent claiming, branch-per-issue, and non-negotiable architectural rules in Phase 1, later amended for PyPI-only deps (`#13`), 2-day cool-off (`#16`), unsigned commits (`#17`), and bundling small unrelated issues. |
| [`docs/lineage/`](docs/lineage/SOURCES.md) | Root `ARCHITECTURE.md`, `SKILLS.md`, and `SOURCES.md` were relocated into `docs/lineage/` with explicit historical-reference notices in PR `#93`. |
| [`docs/skills/`](docs/skills/README.md) & [`skills/header-review/SKILL.md`](skills/header-review/SKILL.md) | Curated methodology research notes tracked in PR `#47` and synced in PR `#81`. The bundled `skills/` directory grew to 8 data-only playbooks (`header-review`, `version-disclosure`, `js-analysis`, `server-error`, `api-inventory`, `openapi-spec-review`, `authorization-testing`, `auth-session-controls`). |

---

## Branch & PR Timeline

### Merged Feature Waves
All 86 merged PRs landed via issue-scoped branches targeting `main`:
- **Foundation (`#12`–`#47`, Nov 18–19)** — the scaffold, hermetic harness, and passive pipeline that everything later builds on: Package scaffold & CI (`#12`), PyPI lock & cool-off (`#14`, `#16`), contracts & redaction (`#15`, `#43`), hermetic harness (`#29`), bundles & SQLite RunStore (`#18`, `#30`), `header-security` (`#19`), passive engine & export (`#34`, `#42`), CLI (`#46`), early engagement, scope, target, roles, and first probe (`#31`, `#33`, `#41`, `#45`), and `docs/skills/` (`#47`).
- **Agent, Verify, Registry & Capture Safety (`#48`–`#70`, Nov 19)** — the first agent sessions, replay verification, and the scope and capture guardrails they depend on: Verification runner (`#48`), `partex chat` (`#50`), scope & capture hardening (`#55`, `#56`), `partex agent` & live `/scope add` (`#57`, `#63`, `#68`), plugin registry & lint (`#60`), `partex report` (`#62`), default JSONL logs (`#67`), and `partex.sh` (`#66`, `#70`).
- **JS Analysis, HAR, Monty Code Mode & Hardening (`#75`–`#108`, Nov 19–20)** — analysis breadth, sandboxed agent code, and the precision work that cut noise: `js-analysis` (`#75`), atomic scope persistence (`#77`), HAR round-trip (`#78`), `--insecure` TLS (`#82`), `partex sandboxes` (`#85`), Linux/macOS CI (`#87`), `/report` & `/secrets` (`#89`, `#97`), live passive checks & probe seeding (`#90`, `#95`), check precision & catch-all (`#91`, `#94`), lineage doc split (`#93`), Monty Code Mode & deferred skills (`#98`, `#99`, `#105`, `#106`), and Pydantic stack upgrade (`#108`).
- **Web Search, URL Allowlists, Write Approval, OpenAPI & Authz (`#112`–`#182`, Nov 21–22)** — the largest wave, covering research, scope tightening, write safety, and the new OpenAPI and authorization checks: Native `web_search` & schema v3 (`#112`, `#142`, `#143`, `#145`, `#147`), `http_request_batch` (`#115`), README & XDG state (`#114`, `#148`), write-approval policy & implementation / schema v4 (`#120`, `#166`, `#171`, `#182`), `--urls-file` (`#122`), `server-error` (`#131`), hints, audit, reports, and header grouping (`#136`–`#139`, `#149`), `User-Agent` & `/scope add -k` (`#150`, `#158`), storage fixes (`#161`), PLAN §15 sync (`#163`), OpenAPI suite (`#151`, `#164`, `#165`, `#167`), target tracing (`#168`), and `authz-boundary` (`#169`).
- **Test Typing, Skill Alignment & Outcome Fixtures (`#197`–`#207`, Nov 22)** — tightening the test suite and making skill guidance match check output: Strict pyright over `tests/` (`#197`), `skill.modes` catalog (`#199`), CORS severity alignment (`#203`), sandboxed research & isolation tests (`#202`), and end-to-end passive-outcome fixtures (`#207`).

### Open PRs & Unmerged Branches (as of November 22, 2026)
- **`post-testing` (unmerged remote branch)**: Adds `--allow-method` / `--max-writes` CLI flags and `partex.sh -M/--method`, plus an explicit `DEFAULT_REQUEST_LIMIT = 200` / `--request-limit` for `partex chat` and `partex agent`, so long sessions do not hit `pydantic_ai`'s 50-turn default limit (`UsageLimitExceeded`).
- **PR `#198` (`issue-176-verify-match-all`, open)**: Passes all replays to `verify_match`, so role-pair findings do not rest on the first replay alone.
- **PR `#200` (`issue-177-skill-coverage-session`, open)**: Adds a scripted session test that exercises the shipped `api-inventory` skill through persisted coverage.
- **PR `#92` (`issue-80-version-disclosure-anchoring`, closed without merge)**: Superseded by and folded into merged PR `#91` (`issue-38-52-80-checks-hardening`).
