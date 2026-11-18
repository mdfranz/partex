# ARTEX Architecture Comparison

Four penetration-testing projects sharing a common lineage but diverging
dramatically in architecture, scope, and priorities. One is a Python script; the
other three are forks of the same Go multi-agent platform operating at different
points on the feature-vs-integrity spectrum.

---

## High-Level Comparison

| Dimension | `ARTEX/` (Python) | `artex-global/` | `BaaRai/ARTEX/` | `failsafe/artex/` |
|---|---|---|---|---|
| **Type** | Single-user scanner | Multi-user autonomous platform | Multi-user autonomous platform | Hardened, source-built distribution |
| **Language** | Python 3.8+ | Go 1.26.3 + Next.js/TS | Go 1.26.10 + Next.js/TS | Go 1.26.3 + Next.js/TS |
| **Agent framework** | None (direct API calls) | norma v0.4.4 | norma v0.4.11 | norma v0.4.3 |
| **Storage** | In-memory dicts | PostgreSQL + SQLite | PostgreSQL + SQLite | PostgreSQL + SQLite |
| **Frontend** | Jinja2 SSR templates | Next.js 14+ (embedded SPA) | Next.js 14+ (embedded SPA) | Next.js 14+ (embedded SPA) |
| **Deployment** | `python app.py` | Docker Compose (build) | Docker Compose (build) | Docker Compose (source-build only) |
| **Auth** | None | JWT + bcrypt + setup token | JWT + bcrypt + setup token | JWT + bcrypt + setup token |
| **Architecture weight** | ~5,800 lines (+2,100 templates) | ~160k lines (101k Go + 59k TS) | ~196k lines (138k Go + 58k TS) | ~150k lines (94k Go + 56k TS) |
| **i18n** | English only | 5 languages (EN/KO/ZH/ES/JA) | Chinese only | English only |

---

## 1. `ARTEX/` — Python Flask Scanner

### Architecture Diagram

```
┌─────────────────────────────────────────┐
│              Flask (app.py)              │
│                                          │
│  Routes    Templates     Scan Orchestr.  │
│  ──────    ─────────     ─────────────   │
│  /         scan.html     run_scan()      │
│  /start    results.html  (bg thread)     │
│  /status   base.html                     │
│  /results                                │
│  /export                                 │
│  /health                                 │
├─────────────────────────────────────────┤
│              Core Library                │
│  ┌─────────┬──────────┬───────────┐     │
│  │http_cli │ dns_utils│ ip_utils  │     │
│  └─────────┴──────────┴───────────┘     │
├─────────────────────────────────────────┤
│             Scan Modules                 │
│  ┌──────────┬──────────┬──────────┐     │
│  │subdomain │   port   │   dns    │     │
│  │ enum     │ scanner  │  scan    │     │
│  ├──────────┼──────────┼──────────┤     │
│  │   ssl    │   tech   │  email   │     │
│  │ scanner  │ detector │   enum   │     │
│  ├──────────┼──────────┼──────────┤     │
│  │ Fast     │   AI     │  real IP │     │
│  │ Security │ Analyst  │  discov  │     │
│  └──────────┴──────────┴──────────┘     │
├─────────────────────────────────────────┤
│                 Utils                    │
│  ┌──────────────┬──────────────────┐    │
│  │   helpers    │   reporting      │    │
│  │ (validation) │ (PDF/JSON gen)   │    │
│  └──────────────┴──────────────────┘    │
└─────────────────────────────────────────┘
```

### Control Flow

```
HTTP POST /start_scan  ──▶  run_scan() [threading.Thread]
                               │
                    ┌──────────┼──────────┐
                    ▼          ▼          ▼
               subdomain    port       DNS scan
               enum (1)    scan (3)      (4)
                    │          │          │
                    └────┬─────┘          │
                         ▼                │
                    SSL scan (5)          │
                         │                │
                    tech detect (6)       │
                         │                │
                    security              │
                    analysis (7)          │
                         │                │
                    AI analysis (8)       │
                         │                │
                         ▼                │
                    scan_results[scan_id]  │
                    (in-memory dict) ◀────┘
```

### Key Design Characteristics

- **Sequential, blocking execution.** Each module completes before the next starts.
- **Ephemeral state.** `scan_results` and `scan_status` are module-level
  dictionaries — process death loses everything.
- **No concurrency control.** A single `threading.Thread` runs the entire scan.
  No worker pool, no queue, no backpressure.
- **Hardcoded external deps.** Groq API key is a hardcoded placeholder in
  source (`modules/AI_analyst.py:17`) — credentials-in-source as the
  configuration mechanism. `nmap` called via `python-nmap` subprocess
  wrapper. `wkhtmltopdf` for PDF generation.
- **Error handling is all-or-nothing.** A single `try/except` around the entire
  `run_scan()` body — any exception discards all partial progress.
- **No authentication, no authorization, no multi-tenancy.**
- **Two-tier AI analysis.** `FastSecurityAnalyst` (rule-based pattern matching
  on subdomain names) + `AIAnalyst` (Groq/Llama3 API call producing structured
  JSON with owner and hunter perspectives).

---

## 2. Go Multi-Agent Platform (Common Core)

All three Go forks share this architecture. The differences are additive.

### System Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    cmd/artex/main.go                              │
│         Single binary: boot + signal + self-update                │
└──────────────────────────┬───────────────────────────────────────┘
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
┌─────────────────────┐     ┌──────────────────────┐
│  Server / API Layer │     │   Embedded Web UI    │
│  (server/)          │     │   (web/ → embed.FS)  │
│                     │     │                      │
│  • REST JSON API    │     │  • Next.js 14+       │
│  • WebSocket (live) │     │  • shadcn/ui + TW    │
│  • Setup wizard     │     │  • @xyflow graphs    │
│  • Auth (JWT)       │     │  • @tanstack tables  │
│  • Admin mgmt       │     │  • i18n framework    │
└──────────┬──────────┘     └──────────────────────┘
           │
    ┌──────┴──────┐
    ▼             ▼
┌─────────┐ ┌──────────┐
│ Manager │ │  Engine  │
│ • store │ │ • run    │
│   open  │ │   loop   │
│ • proxy │ │ • sche-  │
│   start │ │   duler  │
│ • pool  │ │ • admit  │
└────┬────┘ └────┬─────┘
     │           │
     │    ┌──────┴──────────────────────────┐
     │    │         Agent Layer              │
     │    │  ┌────────┬───────┬──────────┐  │
     │    │  │ Main   │Plan-  │ Workers  │  │
     │    │  │ Agent  │ ner   │ (x N)    │  │
     │    │  │(chat)  │(goal  │(intent   │  │
     │    │  │        │ decomp│ exec)    │  │
     │    │  └────────┴───────┴──────────┘  │
     │    │  ┌────────────┬──────────────┐  │
     │    │  │  Retester  │  ColdGraph   │  │
     │    │  │ (verify)   │  (compact)   │  │
     │    │  └────────────┴──────────────┘  │
     │    └─────────────────────────────────┘
     │
     ▼
┌──────────────────────────────────────────┐
│            Data Layer (db/)               │
│  ┌────────────┬────────────┬───────────┐ │
│  │ PostgreSQL │  SQLite    │  File     │ │
│  │ (primary)  │ (traffic   │ Tree      │ │
│  │            │  index)    │ (traffic  │ │
│  │ • assets   │            │  bodies)  │ │
│  │ • tasks    │            │           │ │
│  │ • findings │            │           │ │
│  │ • config   │            │           │ │
│  └────────────┴────────────┴───────────┘ │
└──────────────────────────────────────────┘

Cross-cutting services:
┌─────────┬──────────┬─────────┬──────────┬─────────┬──────────┐
│ traffic │ intercept│ llmpool │  llmrec  │ notify  │  guard   │
│ (MITM   │ (tool    │ (multi- │ (LLM     │ (email, │ (quality │
│  proxy) │ gate)    │ provider│ capture) │ webhook)│ gate)    │
└─────────┴──────────┴─────────┴──────────┴─────────┴──────────┘

Also part of the common core (present in all three forks):
  • sidequestion/ — context-budgeted follow-up questions during task execution
  • mcphttp/      — SSE-based client for remote MCP servers
  • selfupdate/   — binary self-update (present in artex-global and failsafe;
                    enabled only in artex-global, compiled out in failsafe,
                    absent from BaaRai)
```

### Agent Run Loop (Core of the System)

```
                    ┌──────────────┐
                    │   Goal Set   │
                    │  (human or   │
                    │   trigger)   │
                    └──────┬───────┘
                           │
         ┌─────────────────▼─────────────────┐
         │           PLANNER                  │
         │  Reads asset + exploration graph   │
         │  Determines: goal met?             │
         │    NO → emits intent into frontier │
         │    YES → marks task complete       │
         └─────────────────┬─────────────────┘
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
    ┌──────────────────┐    ┌──────────────────┐
    │    Worker 1      │    │    Worker N      │
    │  Claims intent   │    │  Claims intent   │
    │  Runs tools      │    │  Runs tools      │
    │  Writes facts    │    │  Writes facts    │
    │  back to graph   │    │  back to graph   │
    └────────┬─────────┘    └────────┬─────────┘
             │                       │
             └───────────┬───────────┘
                         │
              ┌──────────▼──────────┐
              │   Graph updated     │
              │   (debounced event) │
              └──────────┬──────────┘
                         │
                         ▼
              ┌─────────────────────┐
              │  PLANNER wakes up   │  ◀── loop
              │  (reads new state)  │
              └─────────────────────┘
```

### Data Model — Dual Graph

```
ASSET GRAPH                          EXPLORATION GRAPH
(persistent across tasks)            (per-task, private)

┌─────────┐                          ┌──────────────┐
│ Company │                          │    Goal      │
└────┬────┘                          └──────┬───────┘
     │                                      │
┌────▼────┐                          ┌──────▼───────┐
│root_dom │◄─────────────────────────│   Intents    │ (planner emits)
└────┬────┘      anchors link        └──┬───┬───┬──┘
     │           the two graphs         │   │   │
┌────▼────┐                         ┌───▼───▼───▼───┐
│subdomain│                         │   Workers     │ (execute)
└────┬────┘                         └───┬───┬───┬───┘
     │                                  │   │   │
┌────▼────┐   ┌──────┐            ┌─────▼───▼───▼───┐
│ service │──▶│  IP  │            │  Facts + Findings│ (write back)
└────┬────┘   └──┬───┘            └────────┬────────┘
     │           │                         │
┌────▼────┐   ┌──▼───┐              ┌──────▼──────┐
│endpoint │   │ C-seg│              │   Evidence  │
└─────────┘   └──────┘              │ (traffic)   │
                                    └─────────────┘
```

### Agent Roles

| Agent | Responsibility | Triggers | Tools |
|---|---|---|---|
| **MainAgent** | Human chat interface, read-only observation, steering via hints | User message | Read tools, steer_work |
| **Planner** | Goal decomposition, intent generation, completion judgment | Graph change (debounced) | Read tools, emit intent |
| **Worker** | Claims ONE intent, executes tools, writes facts back, stops | Intent in frontier | Read + Write tools, Bash, WebFetch |
| **Retester** | Verifies finding remediation status (reproduced/fixed/inconclusive) | Retest workflow trigger | Read tools, WebFetch |

### Tool Gate (intercept/)

Every tool call passes through a three-action rule engine before execution:

```
Tool Call ──▶ Rule Engine (priority-ordered) ──▶ ALLOW  → execute
                        │                        │
                        ├──────────────────────▶ DENY   → block + message
                        │
                        └──────────────────────▶ ASK    → pending record
                                                           │
                                                    ┌──────▼──────┐
                                                    │ Human/Model │
                                                    │ Judge       │
                                                    │ approve or  │
                                                    │ deny        │
                                                    └─────────────┘
```

### LLM Provider Architecture (llmpool/)

```
                 ┌──────────────┐
                 │  LLM Pool    │
                 │  (health     │
                 │   checks)    │
                 └──────┬───────┘
         ┌──────────────┼──────────────┐
         ▼              ▼              ▼
   ┌──────────┐  ┌──────────┐  ┌──────────┐
   │ Profile 1│  │ Profile 2│  │ Profile 3│
   │ (e.g.    │  │ (e.g.    │  │ (e.g.    │
   │  Claude) │  │  GPT)    │  │  Ollama) │
   └──────────┘  └──────────┘  └──────────┘

   Features:
   • Connection pooling per provider
   • Health checking with failover
   • Rate limiting per provider
   • Multi-profile task chains (rotation)
   • Fallback chain: ordered + optional round-robin
```

### Traffic Capture Flow

```
Worker Bash ──▶ http_proxy=https://127.0.0.1:8788 ──▶ Target
                         │
                ┌────────▼────────┐
                │ go-mitmproxy    │
                │ (embedded)      │
                │                 │
                │ captures every  │
                │ HTTP exchange   │
                └────────┬────────┘
                         │
              ┌──────────┴──────────┐
              ▼                     ▼
        File Tree               SQLite Index
        (bodies)                (metadata)
   ├── host/                    • id, ts, host
   │   ├── method-             • method, URL
   │   │   url_template/       • status, type
   │   │   ├── id.req          • lengths, path
   │   │   └── id.resp
   │   ...
```

### PostgreSQL Schema (Core Tables)

```
companies
  │
  ├── company_scope (scope rules: domain, IP, CIDR, ICP, keyword)
  │
  └── assets (type: root_domain, ip, subdomain, app, service, endpoint)
        │
        └── explorations (task-scoped exploration graph nodes + edges)
              │
              ├── findings (severity, status, title, description, evidence)
              │     └── finding_traffic (links to captured HTTP exchanges)
              │
              ├── intercepts (pending/decided tool-call rulings)
              │
              ├── conversations (chat sessions with human)
              │
              └── activities (event stream: intents, facts, findings, approvals)

settings (JSON key-value configuration)
llm_profiles (provider configs: endpoint, key, model, rate limits)
skills / custom_tools / mcp_servers (extensible tool registry)
notifications (delivery rules: email, webhook, DingTalk, Feishu, etc.)
triggers (scheduled / event-driven task launches)
```

---

## 3. Fork-Specific Architecture Differences

### `artex-global/` — Multilingual Edition

**Added layers:**

```
┌─────────────────────────────────────────┐
│          i18n Engine                     │
│  ┌───────────────────────────────────┐  │
│  │ Output Language Enforcement        │  │
│  │ • Internal prompts: Chinese (fixed)│  │
│  │ • User-facing: selected language   │  │
│  │ • Agent reports: selected language │  │
│  │ • UI labels: 5-language resource   │  │
│  │   bundles (EN/KO/ZH/ES/JA)         │  │
│  └───────────────────────────────────┘  │
├─────────────────────────────────────────┤
│          Self-Update Engine (ENABLED)    │
│  ┌───────────────────────────────────┐  │
│  │ Only fork that enables the common- │  │
│  │ core selfupdate/ package:          │  │
│  │ • Binary staging + crash rollback  │  │
│  │ • GitHub Releases fetch            │  │
│  │ • Post-swap boot counter           │  │
│  │ • Settle delay: 30s after start    │  │
│  │ (failsafe compiles it out with     │  │
│  │  Enabled=false; BaaRai omits the   │  │
│  │  package entirely)                 │  │
│  └───────────────────────────────────┘  │
├─────────────────────────────────────────┤
│          Defense & Detection             │
│  ┌───────────────────────────────────┐  │
│  │ docs/defense-en.md (signatures,    │  │
│  │ hardening checklists, detection    │  │
│  │ guides for autonomous AI attacks)  │  │
│  └───────────────────────────────────┘  │
├─────────────────────────────────────────┤
│          Detection Signatures            │
│  ┌───────────────────────────────────┐  │
│  │ detections/ (YARA, Suricata,       │  │
│  │ Sigma rules for ARTEX activity)    │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

**Comparison baseline:** the only fork that *enables* `selfupdate/` and the
only one shipping `detections/`. Its substantive addition is the i18n framework
woven through the server and agent layers, plus the defense documentation.
Primarily a **breadth-first** fork: makes the platform accessible to more
users and defends them from it.

---

### `BaaRai/ARTEX/` — Technical-Forward Fork

**Added layers:**

```
┌─────────────────────────────────────────┐
│          Forked Agent Framework          │
│  ┌───────────────────────────────────┐  │
│  │ go.mod replace directive:          │  │
│  │   norma => github.com/BaaRai/Norma │  │
│  │   v0.4.11                          │  │
│  │ BaaRai maintains its own fork of   │  │
│  │ the agent framework itself — agent │  │
│  │ semantics can diverge from         │  │
│  │ upstream, not just platform code   │  │
│  └───────────────────────────────────┘  │
├─────────────────────────────────────────┤
│          Agent Layer Expansion           │
│  ┌───────────────────────────────────┐  │
│  │ 43 non-test Go files in agent/ vs. │  │
│  │ 29 (global) / 28 (failsafe):       │  │
│  │ • bbot_ingest — BBOT scan import   │  │
│  │   as a tool + pipeline             │  │
│  │ • coverage_ledger — per-task       │  │
│  │   coverage tracking                │  │
│  │ • Dense adversarial/quality seed   │  │
│  │   tests (gates, dedup, hygiene)    │  │
│  └───────────────────────────────────┘  │
├─────────────────────────────────────────┤
│          Egress Governor (egress/)        │
│  ┌───────────────────────────────────┐  │
│  │ Profile-based noise control:       │  │
│  │ • Token bucket per host (RPS cap)  │  │
│  │ • Concurrency cap (per-host +      │  │
│  │   global)                          │  │
│  │ • Jitter (uniform random delay)    │  │
│  │ • GET coalescing + short cache     │  │
│  │ • 429/503 backoff with Retry-After │  │
│  │ • Proxy marker for Bash traffic    │  │
│  │   pacing (artex-pace userinfo)     │  │
│  └───────────────────────────────────┘  │
├─────────────────────────────────────────┤
│          Browser Extension (extension/)  │
│  ┌───────────────────────────────────┐  │
│  │ • Chrome extension for client-side │  │
│  │   traffic capture                  │  │
│  │ • manifest.json, background.js,    │  │
│  │   popup.html, popup.js             │  │
│  └───────────────────────────────────┘  │
├─────────────────────────────────────────┤
│          RSI Contract (RSI.md)           │
│  ┌───────────────────────────────────┐  │
│  │ 3-loop recursive self-improvement: │  │
│  │ • Loop A: within-task (existing)   │  │
│  │ • Loop B: across-task lessons      │  │
│  │ • Loop C: harness optimization     │  │
│  │   (not built — contract only)      │  │
│  │ • Immutable surfaces defined       │  │
│  └───────────────────────────────────┘  │
├─────────────────────────────────────────┤
│          gorilla/websocket               │
│  ┌───────────────────────────────────┐  │
│  │ • Direct WebSocket dependency      │  │
│  │   (not indirect via norma)         │  │
│  └───────────────────────────────────┘  │
├─────────────────────────────────────────┤
│          mvdan.cc/sh                     │
│  ┌───────────────────────────────────┐  │
│  │ • Shell syntax parsing library     │  │
│  │   (command analysis / safety)      │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

**Comparison baseline:** adds `egress/` and `extension/` packages, two Go
dependencies, a ~50% larger agent layer (BBOT ingest, coverage ledger), and —
most significantly — a forked agent framework via a go.mod `replace`
directive. Primarily a **depth-first** fork: makes the platform safer at
runtime (egress control) and more capable (browser traffic, RSI framework,
deeper agent tooling), while staying on newer upstream dependencies.

---

### `failsafe/artex/` — Hardened Distribution

**Modified layers (no new packages, but significant changes within existing ones):**

```
┌─────────────────────────────────────────┐
│          Supply Chain Hardening          │
│  ┌───────────────────────────────────┐  │
│  │ • No prebuilt images (ever)        │  │
│  │ • Dockerfile.safe, base images     │  │
│  │   pinned by SHA256 digest          │  │
│  │ • .env.safe.example (isolated)     │  │
│  │ • docker-compose.safe.yml          │  │
│  │ • npm deps: pinned versions,       │  │
│  │   install at build, integrity      │  │
│  │   checked, lifecycle scripts off   │  │
│  │ • Upstream Dockerfile, installers, │  │
│  │   release workflows removed        │  │
│  └───────────────────────────────────┘  │
├─────────────────────────────────────────┤
│          Runtime Hardening               │
│  ┌───────────────────────────────────┐  │
│  │ • Console: 127.0.0.1 only          │  │
│  │ • Proxy: not published             │  │
│  │ • no-new-privileges in container   │  │
│  │ • Browser MCP: pinned binary,      │  │
│  │   --headless --no-sandbox          │  │
│  │ • Self-update: disabled at         │  │
│  │   runtime (Enabled=false)          │  │
│  └───────────────────────────────────┘  │
├─────────────────────────────────────────┤
│          Static Asset Delivery           │
│  ┌───────────────────────────────────┐  │
│  │ server/static_files.go:            │  │
│  │ • Brotli + gzip compression        │  │
│  │ • Content-hash ETags               │  │
│  │ • Immutable cache for              │  │
│  │   /_next/static/ tree              │  │
│  │ • 404 for missing assets           │  │
│  │   (not SPA fallback)               │  │
│  │ • Compressed bodies cached in      │  │
│  │   memory (sync.Map)                │  │
│  └───────────────────────────────────┘  │
├─────────────────────────────────────────┤
│          Audit & Verification            │
│  ┌───────────────────────────────────┐  │
│  │ • audit/artex-v0.3.15-audit.md    │  │
│  │ • ci/ smoke tests (5 scripts):    │  │
│  │   - binary e2e                     │  │
│  │   - API recon runtime              │  │
│  │   - browser MCP                    │  │
│  │   - Go tests (isolated)            │  │
│  │   - runtime smoke                  │  │
│  │ • tests/verify.sh (implant check)  │  │
│  │ • Makefile (build + verify)        │  │
│  └───────────────────────────────────┘  │
├─────────────────────────────────────────┤
│          Provenance                      │
│  ┌───────────────────────────────────┐  │
│  │ • UPSTREAM.md: tag, commit, date  │  │
│  │ • README.upstream.md preserved    │  │
│  │ • SECURITY.md: reporting, deploy  │  │
│  │   guidance, supported versions    │  │
│  │ • Change inventory with rationale │  │
│  │   for every modification          │  │
│  └───────────────────────────────────┘  │
├─────────────────────────────────────────┤
│          English Translation             │
│  ┌───────────────────────────────────┐  │
│  │ • UI, skills, docs → English       │  │
│  │ • Log/error messages: original     │  │
│  │   language preserved               │  │
│  │ • Protocol values, API fields,     │  │
│  │   parser tokens: not renamed       │  │
│  └───────────────────────────────────┘  │
├─────────────────────────────────────────┤
│          Prompt Stability               │
│  ┌───────────────────────────────────┐  │
│  │ • Per-intent artifact path +       │  │
│  │   task block after stable prompt   │  │
│  │ • Deferred host-tool names sorted  │  │
│  │ • Backported from PR #10 without   │  │
│  │   importing v0.3.30                │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

**Comparison baseline:** adds no new Go packages. Changes are within existing
files (`server/static_files.go` is new, `server/auth.go` is verified clean,
`db/db.go` has MCP changes, `agent/prompt.go` has cache fix). New non-Go
artifacts: `audit/`, `ci/`, `tests/`, `Dockerfile.safe`, `Makefile`, docs.
Primarily an **integrity-first** fork: stays on an older, fully audited codebase
and adds verified hardening rather than new features.

---

## Cross-Cutting Concern Comparison

### Authentication & Authorization

| Concern | `ARTEX/` | Go Forks |
|---|---|---|
| Setup | None | One-time setup token (printed at startup, required for admin account creation) |
| Session | None | JWT (HS256), 7-day TTL, bcrypt password hash |
| Key storage | N/A | `jwt.key` file in project dir (separate from data dir) |
| Password policy | N/A | Min 8 runes, max 72 bytes (bcrypt limit) |

### Concurrency Model

| Concern | `ARTEX/` | Go Forks |
|---|---|---|
| Scan/task execution | `threading.Thread` (1:1) | Goroutine pool (N workers per task) |
| Worker limit | N/A (single thread) | Configurable per task (default 2, adjustable in Settings) |
| Planner concurrency | N/A | Single planner per task (debounced wake-ups) |
| Global concurrency | N/A | `concMu` mutex serializes admission decisions |
| BaaRai addition | — | Per-host + global concurrency caps in `egress/` governor |

### LLM Integration

| Concern | `ARTEX/` | Go Forks |
|---|---|---|
| Provider model | Single: Groq (hardcoded) | Multi-provider: Anthropic, OpenAI, Ollama, any compatible endpoint |
| Configuration | API key in source | Database-stored profiles (LLM Profiles page) |
| Connection management | Per-request `requests.post()` | Connection pool with health checks, rate limiting, failover |
| Multi-model | No | Profile chains, worker rotation (BaaRai) |
| Streaming | No | Streaming (SSE) + non-streaming fallback |
| Capture/replay | No | `llmrec/` — full LLM interaction logging |
| Thinking/reasoning | No | Configurable per profile (ThinkingType, ReasoningEffort) |

### Storage Comparison

| Concern | `ARTEX/` | Go Forks |
|---|---|---|
| Primary store | Python dicts (module-level) | PostgreSQL |
| Secondary store | None | SQLite (traffic index) + file tree (traffic bodies) |
| Schema management | None | `schema.sql` (idempotent: IF NOT EXISTS, OR REPLACE) |
| Migration strategy | None | Additive ALTER TABLE with IF NOT EXISTS; trigger drops before recreates |
| Transaction safety | None | `pgx` connection pool; `serializable` isolation for critical paths |
| Backup | None (ephemeral) | PostgreSQL dump; traffic archive export/import |

### Error Handling

| Concern | `ARTEX/` | Go Forks |
|---|---|---|
| Scan/task errors | Single `try/except` → total loss | Granular: per-intent error states, retry (model errors get 2 extra retries), partial progress preserved |
| Recovery | Manual restart | Task restart recovery, crash-safe SQLite WAL, PostgreSQL transactions |
| Reporting | `scan_status.error` string | Structured activity stream per task, error catalogs, FK violation classification |

---

## Dependency Graph (Go Module)

All three Go forks share the same module path and core dependencies:

```
github.com/Autumn-27/artex
  ├── github.com/Autumn-27/norma          (agent framework)
  │     ├── agentcore, compaction, harness, llm, permission, tool, transcript
  ├── github.com/jackc/pgx/v5             (PostgreSQL driver)
  ├── github.com/lqqyt2423/go-mitmproxy   (MITM proxy for traffic capture)
  ├── github.com/miekg/dns                (DNS library)
  ├── github.com/projectdiscovery/dnsx    (DNS toolkit)
  ├── golang.org/x/crypto                 (bcrypt, SSH)
  ├── golang.org/x/net                    (networking)
  ├── golang.org/x/text                   (i18n text processing)
  ├── modernc.org/sqlite                  (SQLite for traffic index)
  ├── github.com/google/uuid              (UUID generation)
  ├── github.com/golang-jwt/jwt/v5        (JWT auth)
  ├── github.com/klauspost/compress       (compression)

  BaaRai additions:
  ├── github.com/gorilla/websocket        (WebSocket)
  ├── mvdan.cc/sh/v3                      (shell parsing)
  └── replace norma => github.com/BaaRai/Norma v0.4.11
                                          (forked agent framework)

  failsafe addition:
  └── github.com/andybalholm/brotli       (Brotli compression for static files)
```

---

## Summary: Fork Philosophy

```
  Feature Advancement ──────────────────────────────▶
  (newer dependencies, more capabilities)

  BaaRai/ARTEX                      artex-global/
  │ normA v0.4.11 (forked:          │ normA v0.4.4
  │   BaaRai/Norma)                 │ Go 1.26.3
  │ Go 1.26.10                      │ i18n x5, selfupdate (enabled),
  │ egress, extension, RSI,         │   detections
  │   bbot_ingest, coverage_ledger  │ "breadth first"
  │ "depth first"
  │                                 │
  └────────────┬────────────────────┘
               │
        Autumn-27/ARTEX
        (Go rewrite, now unreachable)
               │
        RuoJi6/ARTEX v0.3.15
        (last clean source tag)
               │
        failsafe/artex/
        │ normA v0.4.3 (oldest)
        │ Go 1.26.3
        │ No new features
        │ "integrity first"
        │
        ▼
  Supply-Chain Integrity ───────────────────────────▶
  (older audited codebase, additive hardening only)
```

`artex-global` optimized for **reach** — anyone in the world can use it.
`BaaRai` optimized for **depth** — more control, more capability, more safety at
the network level. `failsafe` optimized for **trust** — every byte of the
runtime is traceable to an audited source, and nothing new is added without
verification.