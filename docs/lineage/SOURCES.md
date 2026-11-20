# ARTEX Codebase Overview

> **Historical Reference:** This document surveys the external ARTEX codebases studied during initial design. It is **not** a specification of `partex` (which shares no runtime, schema, or code dependency with any ARTEX fork). For `partex`'s current design and status, see [`PLAN.md`](../../PLAN.md) and [`RUNTIME.md`](../../RUNTIME.md).

Three Go-based multi-agent autonomous penetration-testing platforms forked from a
common upstream (`Autumn-27/ARTEX`), alongside an unrelated Python Flask
reconnaissance scanner (`ARTEX/`, from `IlyassCODEX/ARTEX`) that shares only the
name.

---

## Projects at a Glance

| Project | Language | Purpose | Storage |
|---|---|---|---|
| `ARTEX/` | Python | Reconnaissance scanner (independent project, `IlyassCODEX/ARTEX`) | In-memory (ephemeral) |
| `artex-global/` | Go + Next.js | Autonomous multi-agent pentesting platform — multilingual edition | PostgreSQL (primary + dual-graph) + SQLite (traffic index) |
| `BaaRai/ARTEX/` | Go + Next.js | Autonomous multi-agent pentesting platform — BaaRai fork | PostgreSQL (primary + dual-graph) + SQLite (traffic index) |
| `failsafe/artex/` | Go + Next.js | Autonomous multi-agent pentesting platform — FailSafe hardened distribution | PostgreSQL (primary + dual-graph) + SQLite (traffic index) |

---

## 1. `ARTEX/` — Python Flask Reconnaissance Scanner

An independent monolithic Flask web app (`IlyassCODEX/ARTEX`, standing for
*Automated Reconnaissance & Threat Exposure Analyzer*, with PDF reports internally
branded **"FoxRecon"**) that runs security reconnaissance against a given domain.
Aside from sharing the `ARTEX` name, it has no shared lineage or code with the
Go platforms below.

### Stack

- **Python 3.8+**, Flask 2.3.2, Jinja2 server-side templates
- System dependency: `nmap` (PDF reports are generated with `reportlab`, a pip
  dependency — `wkhtmltopdf` appears in the project's own install docs but is
  not used by the code)

### Scan modules

- Subdomain enumeration (`modules/subdomains.py`)
- Port scanning (via `python-nmap` with socket fallback, `modules/port_scanner.py`)
- DNS record scanning (`modules/dns_scan.py`)
- Real / origin IP discovery behind CDNs (`modules/real_ip_discovery.py`)
- SSL/TLS configuration scanning (`modules/ssl_scanner.py`)
- Technology stack fingerprinting (`modules/tech_detector.py`)
- Email/user enumeration (`modules/enumeration.py`)
- Rule-based subdomain security/risk categorization (`modules/FastAnalyst.py`)
- AI-powered analysis (Groq / Llama3 integration, `modules/AI_analyst.py`)
- Dual-perspective reports: Owner view vs. Hunter (bug bounty) view

### Architecture

- Single `app.py` entry point — all routes, scan orchestration, and state in one file.
- Scans run in a **daemon background thread** (`threading.Thread`).
- Results stored in **module-level dicts** (`scan_results`, `scan_status`) — lost on restart.
- No authentication, no multi-tenancy, no persistence.
- Templates in `templates/`, report generation in `utils/reporting.py`, and shared HTTP/DNS/IP/tech helpers in `core/` (`constants.py`, `dns_utils.py`, `http_client.py`, `ip_utils.py`, `tech_imp.py`).

### Key observations

- **No persistent storage.** Restarting the server wipes all scan history.
- **API key overwritten in source.** `modules/AI_analyst.py` line 17 hardcodes
  `self.groq_api_key = ""`, ignoring the `groq_api_key` argument passed by
  `app.py` (which reads `GROQ_API_KEY` from the environment). Unless a key is
  pasted directly into `AI_analyst.py`, it always falls back to rule-based
  analysis — and pasting a key there risks leaking it via source control.
- **Sequential stages, threaded internals.** Top-level scan modules execute
  sequentially inside `run_scan`, though individual modules (`SubdomainEnumerator`,
  `PortScanner.batch_scan`, `RealIPDiscovery`) use `ThreadPoolExecutor` internally.
- **Single try/except** around the entire scan body — any exception discards partial results.
- **Unrelated to the Go rewrite.** Written in July 2025 (`IlyassCODEX/ARTEX`,
  internally branded "FoxRecon" in `utils/reporting.py`), it is a separate tool
  from the July 2026 `Autumn-27/ARTEX` Go platform.

---

## 2. `artex-global/` — Multilingual Multi-Agent Platform

A **localized edition** of the upstream `Autumn-27/ARTEX` Go rewrite, adapted for
international teams with five-language UI and output support.

### Stack

- **Go 1.26.3** backend, single binary with embedded Next.js frontend
- **PostgreSQL** (primary store, including the asset and exploration dual-graph stores) + **SQLite** (local HTTP traffic metadata/FTS index at `_index/index.sqlite`)
- Agent framework: `github.com/Autumn-27/norma` v0.4.4
- Frontend: Next.js 16 (React 19) with shadcn/ui and Tailwind CSS v4

### Architecture

| Layer | Key Packages | Role |
|---|---|---|
| Entry point | `cmd/artex/` | Single binary, self-update bootstrap, signal handling |
| Config | `config/` | Runtime configuration loading (JSON + environment variable precedence) |
| Agent system | `agent/` | MainAgent (human chat), Planner (goal decomposition), Worker (tool execution), Retester, NoA compaction, adversarial gate |
| Server / API | `server/` (148 Go files, 57 excluding tests) | REST + WebSocket API, findings, tasks, goals, intercepts, notifications, skills, triggers |
| Database | `db/` (99 files) | PostgreSQL access layer: assets, dual-graph exploration store, tasks, findings, traffic metadata, LLM usage, notifications, triggers |
| Enrichment | `enrich/` | Async DNS resolution (`dnsx`) and HTTP asset probing written back to the asset graph |
| Evidence | `evidence/` | Preserves finding evidence snapshots independently of disposable traffic |
| Traffic proxy | `traffic/` | MITM recording proxy (via `go-mitmproxy`) + SQLite traffic index (`_index/index.sqlite`) — captures HTTP evidence for findings |
| Intercept engine | `intercept/` | Request interception, review queue, judgment, labeling |
| LLM pool | `llmpool/` | Multi-provider connection pool with health checking and failover |
| LLM recording | `llmrec/` | Capture and replay of LLM interactions for audit and retry |
| MCP HTTP | `mcphttp/` | Remote Streamable HTTP and legacy SSE MCP clients |
| Notifications | `notify/` | Email, DingTalk, Feishu, WeCom, Telegram, custom webhooks |
| Guard | `guard/` | Quality / adversarial gate on agent tool output |
| Report | `report/` | Finding export (CSV) and reporting helpers |
| Side questions | `sidequestion/` | Immutable main-agent checkpoints for `/btw` operator side-questions |
| Skills | `skills/` | Built-in agent skill definitions (`api-recon`, `playwright-cli`, `scopesentry`) |
| Detections | `detections/` | Defender-facing content: Sigma and Suricata rules, triage playbooks, ATT&CK mappings, indicator feeds, plus detection tests |
| Self-update | `selfupdate/` | Staged binary updates with automatic rollback of builds that crash repeatedly |
| Frontend | `web/` | Next.js 16 app (TypeScript, React 19, shadcn/ui, Tailwind CSS v4) |

### Design principles

- **Two linked graphs**: asset graph (what exists) + exploration graph (what was tried and what it produced).
- **Findings with evidence**: captured HTTP request/response bound to each finding.
- **Autonomy with brakes**: human-in-the-loop approvals, scope/deny rules, token/turn budgets, prompt-injection framing on tool output.
- **Internal prompts in Chinese**, user-facing output in selected language — preserves upstream agent performance while making results readable in English, Korean, Spanish, or Japanese.
- **Self-updating**: binary stages updates and auto-rolls back builds that crash repeatedly.

### Key files

| File | Purpose |
|---|---|
| `cmd/artex/main.go` | Server bootstrap, signal handling, self-update orchestration |
| `server/server.go` | HTTP handler assembly and route registration |
| `server/engine.go` | Event-driven exploration engine (run loop) |
| `server/manager.go` | Application lifecycle: store opening, worker pool, shutdown |
| `agent/planner.go` | Goal decomposition into intents |
| `agent/worker.go` | Intent execution with real tools |
| `agent/mainagent.go` | Human-interface orchestrator (chat, steer) |
| `db/schema.sql` | Full PostgreSQL schema (companies, assets, tasks, findings, intercepts, traffic, etc.) |
| `web/` | Next.js frontend source |

---

## 3. `BaaRai/ARTEX/` — BaaRai Fork

A **technical-forward, fully English-translated fork** of the same upstream.
Shares the core multi-agent architecture with `artex-global` but diverged with
different priorities.

### Stack

- **Go 1.26.10** (newer), Next.js 16 (React 19) frontend
- Agent framework: `github.com/Autumn-27/norma` v0.4.11 (newer)
- Additional deps: `gorilla/websocket`, `mvdan.cc/sh/v3` (shell parsing)
- Expanded backend (`server/`: 165 Go files, 68 excluding tests; `db/`: 130 files, 59 non-test Go files)

### How it differs from `artex-global`

| Feature | `artex-global` | `BaaRai/ARTEX` |
|---|---|---|
| **i18n** | 5 languages (UI/output); Chinese internal prompts | English only (UI, docs, skills, and internal prompts) |
| **Go version** | 1.26.3 | 1.26.10 |
| **norma** | v0.4.4 | v0.4.11 |
| **Self-update** | `selfupdate/` package | Not present (opt-in read-only `update_check.go` only) |
| **Detections** | `detections/` package (Sigma, Suricata, ATT&CK, triage) | Not present |
| **Egress pacing** | Not present | `egress/` package — rate limits outbound traffic (target noise governor) |
| **Browser extension** | Not present | `extension/` — Chrome extension for traffic capture |
| **Built-in skills** | 3 (`api-recon`, `playwright-cli`, `scopesentry`) | 10 (adds `api-security`, `bbot-recon`, `codeaudit`, `edr-bypass-re`, `patch-diff`, `php2shell`, `rea`) |
| **RSI framework** | Not present | `RSI.md` + implemented Loop B (`lessons.go`, `task_outcome.go`, `/api/skill-gaps`) |
| **Docker build** | Pulls prebuilt `ghcr.io/jiwoochris/artex-global` | Source-built multi-stage `Dockerfile` with SHA256-verified recon binaries |
| **README tone** | Global accessibility, legal compliance, defense/detection guides | Technical architecture, dual-graph design, evidence chain |

### BaaRai-specific additions

- **`egress/`** — Network egress pacing and rate limiting. Controls how fast the
  platform sends requests to targets, preventing accidental DoS.
- **`extension/`** — Browser extension (`manifest.json`, `background.js`,
  `popup.html`, `popup.js`) for capturing browser-side traffic into the evidence
  chain.
- **`RSI.md` & Loop B implementation** — A formal 3-loop contract for recursive
  self-improvement, with Loop A & Loop B wired into code:
  - Loop A: within-task (planner → worker → retester → gate)
  - Loop B: across-tasks (implemented via `GET /api/tasks/{id}/outcome` in
    `server/task_outcome.go`, evidence-gated lessons in `server/lessons.go`
    controlled by `ARTEX_RSI_LESSONS=off|shadow|inject`, and
    `GET /api/skill-gaps` in `server/skill_gaps.go`)
  - Loop C: harness optimization (prompt/skill edits, not yet built — contract only)
  - Defines immutable surfaces (scope checks, injection defenses, tool allowlists)
    and requires owner approval + benchmark validation for every adopted edit.
- **Expanded built-in `skills/` (10 skills)** — Adds `api-security`, `bbot-recon`,
  `codeaudit`, `edr-bypass-re`, `patch-diff`, `php2shell`, and `rea` alongside
  the 3 shared upstream skills (`api-recon`, `playwright-cli`, `scopesentry`).
- **Multi-LLM worker rotation, Keenable search, target gates, and `scripts/`** —
  Round-robin multi-provider worker rotation (`llm_rotate`), opt-in Keenable
  web-search backend, target scope/redirect gates (`target_gate_*.go`,
  `target_redirect_test.go`), and benchmark/submission-review harnesses in
  `scripts/`.

---

## 4. `failsafe/artex/` — FailSafe Hardened Distribution

A **security-hardened, source-built distribution** maintained by FailSafe Cyber
Frontier Labs. Forked from `RuoJi6/ARTEX` v0.3.15 — the last known clean tag
before a backdoor was introduced into upstream prebuilt Docker images (Nov 2026).

### Stack

- **Go 1.26.3** backend, Next.js 16 (React 19) frontend
- Agent framework: `github.com/Autumn-27/norma` v0.4.3 (oldest among Go forks, pinned to audited tag)
- Additional dep: `andybalholm/brotli` (for static asset compression)

### Origin — the November 2026 supply-chain incident

On 2026-11-03/04, public analysis found that prebuilt Docker images published
under `tomicdd/artex` (and copies under `congdonglinux/artex`) contained an
**unauthenticated command-execution backdoor** in `server/auth.go`:

- A hidden `server.verifyCaptcha` function called `exec.Command("sh", "-c", input)`.
- `authLogin` invoked it when the `captcha` JSON field began with a secret marker,
  **before** checking credentials.
- Command output was returned in the login response as `{"captcha": ...}`.
- The GitHub source did **not** contain the implant — it was image-only.

FailSafe responded by forking the last audited clean source tag (`v0.3.15`),
removing all prebuilt-image references, and providing a build-from-source
distribution with supply-chain hardening.

### What changed from upstream

| Area | Upstream default | FailSafe build |
|---|---|---|
| Image | Prebuilt `tomicdd/artex` (backdoored) | Compiled from audited source tree |
| Console binding | `0.0.0.0:8787` | `127.0.0.1:8787` (loopback only) |
| Recording proxy | Published | Not published by compose |
| Self-update repo | `RuoJi6/ARTEX` | `failsafe-security/artex` (disabled at runtime) |
| Dockerfile | Pulled external image | `Dockerfile.safe` with base images pinned by digest |
| npm deps | Runtime `npx @playwright/mcp` | Pinned Puppeteer 25.17.0, preinstalled at build, integrity-checked, lifecycle scripts disabled |
| Browser MCP | `npx @playwright/mcp` (registry lookup) | Pinned `playwright-mcp` binary with `--headless --no-sandbox` |
| UI delivery | Raw `embed.FS` via `http.ServeFileFS` (uncompressed, no validators) | Custom `static_files.go`: Brotli/gzip compression, content-hash ETags, immutable caching for `/_next/static/` |
| Language | Chinese interface, prompts, and skills | English UI, documentation, and skills; Chinese internal prompts |
| Installers | `install.sh`, `update.sh`, prebuilt release workflows | All removed |

### Unique additions

- **`audit/`** — Full audit report (`artex-v0.3.15-audit.md`) documenting the
  source review that confirmed tag cleanliness.
- **`ci/`** — Smoke-test suite: binary e2e (`e2e_binary.py`), API recon
  (`api-recon-smoke.js`), browser MCP (`browser-mcp-smoke.cjs`), Go tests
  (`go-tests-isolated.py`), runtime smoke (`runtime_smoke.py`).
- **`tests/`** — Integration tests: API recon runtime, startup verification,
  and `verify.sh` for checking known implant indicators.
- **`UPSTREAM.md`** — Full provenance document: upstream tag, commit hash,
  import date, change inventory, incident summary, update policy.
- **`SECURITY.md`** — Vulnerability reporting, deployment guidance, supported
  versions policy.
- **`Makefile`** — Build, test, and verification targets.
- **Prompt-cache fix backport** — Per-intent artifact path and task block placed
  after stable worker prompt; deferred host-tool names sorted before rendering.
  Backported from PR #10 without importing v0.3.30.
- **Online update disabled** — `selfupdate.Enabled = false` independently of
  version string. FetchLatest and Stage refuse before network access.
- **Node 22, Playwright, Chromium, nmap** — Full upstream runtime capabilities
  preserved for parity with the original.

### How it compares to the other Go forks

| Feature | `artex-global` | `BaaRai/ARTEX` | `failsafe/artex` |
|---|---|---|---|
| **Upstream base** | Autumn-27/ARTEX | Autumn-27/ARTEX | RuoJi6/ARTEX v0.3.15 |
| **Go version** | 1.26.3 | 1.26.10 | 1.26.3 |
| **norma** | v0.4.4 | v0.4.11 | v0.4.3 |
| **i18n** | 5 languages (UI/output); Chinese internal prompts | English only (UI, docs, skills, and internal prompts) | English UI, docs, and skills; Chinese internal prompts |
| **Supply-chain hardening** | ❌ (pulls GHCR image) | Partial (source-built, SHA256-verified recon tools) | ✅ Source-build only, digest-pinned base images, implant checks |
| **Static UI delivery** | Standard embed | Standard embed | Brotli/gzip + ETags + immutable cache |
| **Self-update** | Enabled (crash rollback) | ❌ (opt-in check only) | Disabled (rebuild required) |
| **Defender detections** | ✅ (`detections/`) | ❌ | ❌ |
| **Audit report** | ❌ | ❌ | ✅ (`audit/`) |
| **Built-in skills** | 3 | 10 | 3 |
| **Egress pacing** | ❌ | ✅ (`egress/`) | ❌ |
| **Browser extension** | ❌ | ✅ (`extension/`) | ❌ |
| **RSI framework** | ❌ | ✅ (`RSI.md` + Loop B) | ❌ |
| **CI smoke tests** | GitHub Actions only | GitHub Actions only | ✅ (`ci/` + `tests/`) |

---

## Lineage

```
ARTEX/  (Python Flask — IlyassCODEX/ARTEX, July 2025, "FoxRecon")
  (independent project; shares only the ARTEX name)

Autumn-27/ARTEX  (upstream Go rewrite — July 2026, repo unreachable as of Oct 2026)
  │
  ├─▶ artex-global/       JiwooChris's global / multilingual edition
  │     • 5-language i18n (EN/KO/ZH/ES/JA) with Chinese internal prompts
  │     • Auto-update with crash rollback
  │     • Defense & detection suite (detections/)
  │     • Legal compliance framing for international use
  │
  ├─▶ BaaRai/ARTEX/       BaaRai's fork
  │     • Full English translation (UI, docs, skills, and internal prompts)
  │     • Newer norma framework (0.4.11)
  │     • Egress pacing / rate limiting (egress/)
  │     • Browser extension (extension/)
  │     • RSI contract + Loop B implementation (RSI.md, lessons.go, task_outcome.go)
  │     • 10 built-in skills, multi-LLM worker rotation, Keenable search, target gates
  │     • gorilla/websocket, mvdan.cc/sh/v3, benchmark/review scripts (scripts/)
  │
  └─▶ RuoJi6/ARTEX v0.3.15  (intermediate fork — pre-backdoor source)
        │
        └─▶ failsafe/artex/   FailSafe Cyber Frontier Labs
              • Audited source tag, no prebuilt images
              • Docker base images pinned by digest
              • npm deps preinstalled at build, integrity-checked
              • Self-update disabled at runtime
              • Brotli/gzip static delivery
              • English UI, docs, and skills (Chinese internal prompts)
              • CI smoke tests, implant-verification scripts
```

All three Go forks share the same **Go module path** (`github.com/Autumn-27/artex`)
and the same **core architecture**: PostgreSQL schema (including the asset and
exploration dual-graph stores), local SQLite HTTP traffic index
(`_index/index.sqlite`), planner/worker/retester agent loop, MITM traffic proxy,
and Next.js 16 frontend.

`failsafe/artex` is unique in that it explicitly prioritizes **supply-chain
integrity over feature advancement** — it stays on an older, audited codebase
with additive hardening rather than pulling new features from later (unaudited)
tags. `artex-global` went broad (languages, legal, auto-update, defender
detections), while `BaaRai` went deep (egress control, RSI Loop B, expanded
skills, browser integration).

---

## Quick Start (Go Projects)

All three Go projects follow a similar Docker Compose pattern, with distinct
image and env-file defaults:

```bash
# artex-global (pulls prebuilt ghcr.io/jiwoochris/artex-global:latest)
cd artex-global
cp .env.example .env          # set POSTGRES_PASSWORD
docker compose up -d          # pulls image, starts PostgreSQL

# BaaRai/ARTEX (builds from source checkout; no prebuilt image)
cd BaaRai/ARTEX
cp .env.example .env          # set POSTGRES_PASSWORD
docker compose up -d --build  # builds from checkout, starts PostgreSQL

# failsafe/artex (builds from source using .env.safe and docker-compose.safe.yml)
cd failsafe/artex
cp .env.safe.example .env.safe     # set POSTGRES_PASSWORD
docker compose --env-file .env.safe -f docker-compose.safe.yml up -d --build
# (or simply: make up)
```

All three listen on `http://localhost:8787`, and all three compose files bind
the console port to **loopback by default** (`127.0.0.1:8787`) — hardcoded in
`failsafe/artex`, configurable via `ARTEX_BIND` (artex-global) or
`ARTEX_BIND_ADDR` (BaaRai). On first visit `/setup` asks for the one-time setup
token printed at startup.

For the Python `ARTEX/` project:

```bash
cd ARTEX
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python app.py                  # starts on http://127.0.0.1:5000
```

---

## Important Notes

- **License**: The three Go forks are AGPL-3.0. The Python `ARTEX/` project
  ships no license file.
- **Legal**: These are offensive security tools. Only use against systems you own
  or have explicit written authorization to test. Unauthorized use is illegal in
  most jurisdictions.
- **Upstream**: The original `Autumn-27/ARTEX` Go repository was unreachable as
  of October 2026. The intermediate fork `RuoJi6/ARTEX` provides the last
  available source tree.
- **Supply-chain warning**: Prebuilt Docker images from `tomicdd/artex` or
  `congdonglinux/artex` were found to contain a command-execution backdoor in
  November 2026. Only build from audited source. See `failsafe/artex/UPSTREAM.md`
  for the full incident report.