# partex

**`partex` is a local, terminal-native, evidence-first web and API security testing workbench in Python 3.14, built on the Pydantic AI stack with Pax TUI as the primary operator interface.**

Review captured traffic offline with deterministic checks, probe authorized targets through a code-enforced scope gate, replay verification recipes, and run interactive AI investigation sessions backed by an auditable SQLite engagement record.

## Positioning & why `partex` exists

Web and API security testing usually splits into two extremes:

- **Traditional scanners and proxies** are deterministic and controllable, but brittle when reasoning about API contracts, business workflows, or cross-role authorization boundaries.
- **Autonomous AI pentesting platforms** are exploratory, but often arrive as heavy multi-service stacks (Docker, Postgres, web UIs, MITM proxies) that enforce scope in prompts, execute third-party skill scripts, and let models invent findings without replayable proof.

`partex` takes a deliberate middle path, built for two audiences:

- **Security engineers & operators** who want a controllable, reproducible, single-machine CLI/TUI workbench where every finding links to captured evidence and every outbound request passes a code-level scope gate.
- **AI & Pydantic engineers** studying a real-world reference architecture for pairing an LLM with hard security boundaries, sandboxed Code Mode, untrusted-data framing, and deterministic persistence.

The core boundary splits the work cleanly: **a deterministic Python engine owns authorization, network sockets, scope, secret redaction, SQLite durability, checks, and verification**, while **the AI agent owns interactive investigation, synthesis, and sandboxed evidence correlation**. Offline review and baseline active/verification runs work completely model-free; interactive sessions layer over the exact same store. Because `partex` is multi-model and provider-agnostic, you can pair direct frontier providers, open-weights models through OpenRouter or Pydantic AI Gateway, and an independently configured, isolated search model without vendor lock-in.

## What `partex` deliberately avoids

| Deliberate non-goal | What `partex` does instead |
| --- | --- |

| **No GUI or web UI** | Terminal-first CLI and Pax TUI (`partex chat`, `partex agent`, `./partex.sh`), scriptable and headless-capable for CI. |
| **No multi-user server or hosted daemon** | Built for one operator on one machine with a local SQLite (WAL) database (`partex.db`). No Postgres, message broker, or container cluster required. |
| **No MITM proxy** | Captures traffic only through `partex`'s own `ScopedHttpClient`, operator-exported HAR files (`partex import-har`), and the planned M7 Playwright/CDP capture harness (`browser.py`) — never by intercepting external tools or browser traffic. |
| **Not completely autonomous** | Operator-in-the-loop by design: live runs require written engagement authorization (`--authorized`), strict scope/RPS/request budgets, operator confirmation via operator-only slash commands out of model reach (`/scope add`, `/scope nmap`), and interactive terminal approval for every state-changing request (`POST`/`PUT`/`PATCH`/`DELETE`, denied automatically when headless). The model can never mutate findings or scope directly. |
| **No executable skills** | Markdown playbooks under [`skills/`](skills/) are inert data loaded on demand via `load_capability` — never imported or executed. Executable checks load solely from installed Python distributions via `partex.checks` entry points. |

## How and why it was built

`partex` grew out of studying the ARTEX security platforms ([docs/lineage/SOURCES.md](docs/lineage/SOURCES.md)) while committing to a greenfield Python implementation with zero shared code, schema, or runtime — hardened after the November 2026 ARTEX prebuilt-image backdoor via hash-pinned `uv.lock`, a 2-day PyPI cool-off (`exclude-newer = "2 days"`, exempting only named `pydantic-*` packages in [`pyproject.toml`](pyproject.toml)), [`scripts/check_greenfield.py`](scripts/check_greenfield.py), and zero prebuilt images ([DEPS.md](DEPS.md)).

It was designed spec-first ([PLAN.md](PLAN.md), [RUNTIME.md](RUNTIME.md)) and built through parallel multi-agent PRs ([CLAUDE.md](CLAUDE.md), [LINEAGE.md](LINEAGE.md)) with a hermetic test suite (`tests/conftest.py` blocks non-loopback sockets, real LLM calls, and external telemetry), strict Pyright across `src/`, `scripts/`, and `tests/`, and capture-time SQLite durability.

## Architecture & Pydantic stack

```mermaid
flowchart LR
    Offline["Bundle or HAR (import-har)"] --> Review["partex review (passive, model-free)"]
    Target["Target + Scope (-u / -N)"] --> Client["ScopedHttpClient (scope + write-approval gate)"]
    Client --> Live["partex test / partex agent (passive + active + verify)"]
    Review --> DB[("partex.db")]
    Live --> DB
    DB --> Inspect["partex show / chat / reports"]
```

The [Pydantic](https://github.com/pydantic/pydantic) ecosystem provides the typed contracts, agent runtime, sandboxed code execution, terminal shell, and trace observability that enforce these boundaries:

- **Pydantic (`pydantic`):** Evidence records (`http`, `config`, `artifact`), engagements, scope rules, and findings are `BaseModel`s with `extra='forbid'`. Discriminated unions and `TypeAdapter` round-trip records through bundle import, SQLite storage, and canonical JSON export; engagement validation errors map directly onto E-rule failure codes.
- **Pydantic AI (`pydantic-ai-slim`):** `Agent` and `RunContext` drive both the read-only reviewer (`partex chat`) and live tester (`partex agent`). `Capability` defers skill playbooks until `load_capability` is called; `pydantic_ai.framing.wrap` and `register_tag` quarantine target-controlled tool output as untrusted data; `WebSearch(local=None)` isolates optional provider-native web search in a separate zero-tool agent; and a `WrapperModel` (`UsageRecordingModel`) records per-request token spend in `llm_usage`.
- **Pydantic AI Harness (`pydantic-ai-harness`):** Supplies `CodeMode` (connecting Monty to the agent), `DetectLoops` (nudging repetitive tester loops instead of burning request budget), and the `ask_user` request/response contracts powering interactive write approvals.
- **Pax (`pydantic-ai-pax`):** `chat()` runs the interactive terminal loop. Operator-only Pax `Plugin`s provide `/scope`, `/targets`, `/report`, and `/secrets` outside model reach (`partex chat` loads only the read-only `/targets` plugin), `TerminalAnswerer` renders inline write-approval pickers, and terminal history stays separated in `partex.db.clai2/`.
- **Monty (`pydantic-monty`):** Runs model-generated Python inside `run_code` (`eager=True`, `max_tool_calls=50`, 10-second timeout, 256 MiB memory cap) with a per-run read-only `/artifacts` `MountDir` and `os_access=None` — no host filesystem, environment, clock, network, or shell. `partex sandboxes` reports the installed Monty runtime alongside host sandboxes.
- **Logfire (`logfire`):** Local JSONL trace logs are written by default with tool-content secret scrubbing; `--logfire` opts into remote span export, and `target.py` emits manual metadata-only request spans (global `logfire.instrument_httpx()` is forbidden so engagement credentials never leak).

## Multi-model control: analyst vs. search models

`partex` separates model configuration into two independent roles ([`src/partex/models_config.py`](src/partex/models_config.py), [`src/partex/agent_adapter/search.py`](src/partex/agent_adapter/search.py)):

- **Provider-agnostic analyst & reviewer (`--model` / `-m`):** Accepts any Pydantic AI `provider:model` string (`anthropic:`, `openai:`, `google:`, `google-cloud:`, `openrouter:`, and more) as well as Pydantic AI Gateway routes (`gateway/...`, or a bare model name paired with `--gateway-route` / `-r`, such as `zai-org/GLM-5.3` over `doubleword`). Because `partex.db` is the durable engagement record rather than a vendor-hosted thread, you can **switch models across phases of the same assessment** — run deterministic checks with `partex review` or `partex test`, probe live with a fast or open-weights model in `partex agent` (`./partex.sh --resume` continues live testing from a saved run's scope and authorization), and re-examine any saved run read-only with a heavier reasoning model (`./partex.sh --read-only` / `partex chat`).
- **Why `partex` decouples `--model` from `--search-model` (`-S`):**
  - *Pair any analyst with native web search (or turn search off):* Open-weights and Gateway-routed models often lack native server-side web search. Decoupling lets them delegate public reference lookups to a dedicated native-search provider — or omit `-S` to disable external research egress entirely.
  - *Independent cost, latency, and filter tuning:* Tune analyst reasoning effort (`--thinking` / `-T`), turn caps (`--request-limit` / `-L`), and Gemini content filters (`PARTEX_GOOGLE_SAFETY_SETTINGS`, defaulting configurable filters `off` for security evidence while keeping non-configurable CSAM/PII filters on) independently from search, with spend recorded per run in `llm_usage`.
  - *Hard egress and privilege isolation:* `web_search` runs in a separate one-shot `Agent` with `WebSearch(local=None)`, **zero** host tools/DB/target-client/filesystem access, and no Gateway routing; outbound queries pass `validate_search_query` and results return framed as untrusted data into `web_research`. See [USAGE.md](USAGE.md) and [RUNTIME.md](RUNTIME.md) for the enforced limits and provider settings.

| Role | Flag | Supported providers | Capabilities & access | Granular controls |
| --- | --- | --- | --- | --- |
| **Analyst / Reviewer** (`partex agent`, `partex chat`) | `--model` / `-m` (+ optional `--gateway-route` / `-r`) | Any Pydantic AI `provider:model` (`anthropic:`, `openai:`, `google:`, `google-cloud:`, `openrouter:`, …) or Pydantic AI Gateway route | Scoped live tools, Monty `run_code` sandbox, deferred skills, read-only DB views | `--thinking` / `-T`, `--request-limit` / `-L`, `PARTEX_GOOGLE_SAFETY_SETTINGS`, `DetectLoops`, `llm_usage` tracking |
| **Web Search** (optional, off by default) | `--search-model` / `-S` | Native server-side search only: `anthropic:`, `google:`, `google-cloud:` (Vertex ADC), `openai:` (Responses API); never Gateway | Isolated one-shot `Agent` with `WebSearch(local=None)` only — zero tools, DB, target client, or filesystem | Query egress validation (no secrets/URLs/`ev_`/`fn_` IDs, 200-char max), 20 calls/session, 20 sources/query, Anthropic `direct`-only + `max_uses=3`, results persisted to `web_research` |

See **[USAGE.md](USAGE.md)** for interactive AI sessions (`partex.sh`, OpenRouter, Pydantic AI Gateway, direct Gemini), `nmap -oX` and URL-list scoping (`-N`, `-u`), write-approval flags (`-M`, `-w`, `-W`), operator slash commands, CLI subcommands, and `PARTEX_STATE_DIR` management.

## Skills and checks

Skills are Markdown playbooks in [`skills/`](skills/) surfaced on demand via `load_capability`; executable checks live in [`src/partex/checks/`](src/partex/checks/) and register via `partex.checks` entry points (`uv run partex checks`).

| Skill | Mode | Check | What it covers | Playbook and references |
| --- | --- | --- | --- | --- |
| [`header-review`](skills/header-review/SKILL.md) | passive | [`header-security`](src/partex/checks/header_security.py) | Missing or weak security headers (HSTS, CSP, framing, `X-Content-Type-Options`), cookie attributes, and permissive CORS, applied by response type | [response policies](skills/header-review/reference/response-policies.md), [research notes](docs/skills/header-review.md) |
| [`version-disclosure`](skills/version-disclosure/SKILL.md) | active | [`version-disclosure`](src/partex/checks/version_disclosure.py) | Server and framework version banners and stack traces, confirmed by replaying a single request | [verification criteria](skills/version-disclosure/reference/verification-criteria.md), [research notes](docs/skills/version-disclosure.md) |
| [`js-analysis`](skills/js-analysis/SKILL.md) | passive | [`js-analysis`](src/partex/checks/js_analysis.py) | Full JavaScript bundles parsed offline with `tree-sitter` for endpoints, embedded config, and risky DOM sinks; fetches and parses exposed ECMA-426 source maps and flags high-entropy embedded secrets | [analysis rules](skills/js-analysis/reference/analysis-rules.md) |
| [`api-inventory`](skills/api-inventory/SKILL.md) | passive | [`api-contract-conformance`](src/partex/checks/api_inventory.py) | Normalized inventory of observed API operations reconciled against declared OpenAPI 3.0/3.1 contracts (shadow routes, unobserved operations, schema gaps) | [contract matching](skills/api-inventory/reference/contract-matching.md), [research notes](docs/skills/api-inventory.md) |
| [`openapi-spec-review`](skills/openapi-spec-review/SKILL.md) | passive | [`openapi-spec-review`](src/partex/checks/openapi_spec_review.py) | Spec-level gaps in OpenAPI 3.0/3.1 documents: missing auth, weak schemes, internal server URLs, credential query params, sensitive response fields | none |
| [`server-error`](skills/server-error/SKILL.md) | passive | [`server-error`](src/partex/checks/server_error.py) | Unhandled HTTP 5xx responses and debug-page disclosure already present in captured evidence | none |
| [`privacy-review`](skills/privacy-review/SKILL.md) | passive | [`privacy-signals`](src/partex/checks/privacy_signals.py) | Third-party tracker, analytics, session-replay, error-monitoring, ad, chat, and CAPTCHA SDKs and consent-management signals (static signals, not legal conclusions) | [tracker signatures](skills/privacy-review/reference/tracker-signatures.md), [research notes](docs/skills/privacy-review.md) |
| [`authorization-testing`](skills/authorization-testing/SKILL.md) | active and passive | [`authz-boundary`](src/partex/checks/authorization.py) | Broken object-level and function-level authorization (BOLA, IDOR, BFLA) by replaying operations across two engagement roles | [role-pair probing](skills/authorization-testing/reference/role-pair-probing.md), [research notes](docs/skills/authorization-testing.md) |
| [`auth-session-controls`](skills/auth-session-controls/SKILL.md) | passive and active | Not yet registered | Session cookie configuration and token lifecycle weaknesses (`session-cookie-config`, `token-weakness` staged; left out of catalog until installed) | [session and token checks](skills/auth-session-controls/reference/session-and-token-checks.md), [research notes](docs/skills/auth-session-controls.md) |
| [`graphql`](skills/graphql/SKILL.md) | passive and active | No check (playbook only) | GraphQL introspection, field suggestions, federation subgraphs, CSRF, per-field/nested-edge/mutation authorization, and batching/alias/depth limits | [graphql probing](skills/graphql/reference/graphql-probing.md), [research notes](docs/skills/graphql.md) |
| [`regression-verify`](skills/regression-verify/SKILL.md) | passive and active | No check (playbook only) | Re-verifying earlier findings against a changed target and re-reviewing exported bundles for regression drift between runs | [drift classes](skills/regression-verify/reference/drift-classes.md), [prioritization](skills/regression-verify/reference/prioritization.md) |

## Documentation map

| Document | Purpose |
| --- | --- |
| [USAGE.md](USAGE.md) | Operator guide: installation, providers, `nmap`/URL scoping, write approvals, slash commands, tools, CLI reference, state cleanup |
| [PLAN.md](PLAN.md) | Canonical architecture, data contracts, scope & approval rules, validation gates, and milestone status (§15) |
| [RUNTIME.md](RUNTIME.md) | Execution boundaries, Monty Code Mode isolation, web search isolation, and planned M7 browser capture runtime |
| [DEPS.md](DEPS.md) | Dependency policy, locked stack decisions, `tree-sitter`/`referencing`/`httpx2`, and browser automation strategy |
| [LINEAGE.md](LINEAGE.md) | Project evolution log across merged PRs, technical decisions, and cross-cutting concerns addressed |
| [CLAUDE.md](CLAUDE.md) / [AGENTS.md](AGENTS.md) | Multi-agent repo conventions, `uv` rules, and non-negotiable architectural invariants |
| [docs/skills/PLAN.md](docs/skills/PLAN.md) | Skill taxonomy, frontmatter contract, engine deltas D1–D7, and staged roadmap |
| [docs/skills/README.md](docs/skills/README.md) | Security research notes, primary standards links, and false-positive guardrails per skill |
| [docs/lineage/SOURCES.md](docs/lineage/SOURCES.md) | Historical provenance of external ARTEX platforms and open-source skill corpora studied during design |