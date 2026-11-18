# Greenfield Python framework for web application security testing

> Status: development plan, revised scope. No code yet. The validation experiments in §13 are
> proposed and have not been run. **Revision note:** this revision replaces the earlier
> offline-only defensive-review scope with the full offensive scope of the original Artex
> lineage (authorized live-target testing, active checks, exploit verification, agent loops).
> What is preserved from the earlier sketch: no dependency on any Artex fork, skills stay
> outside the engine as data, findings are always evidence-backed and survive every failure
> mode, and the validation suite runs credential-free against local fixture targets.

## 1. Scope

Build a new Python package, `artex-web` (import name `artex_web`), from scratch using the local
Pydantic AI and CLAI2 checkout. Use Artex as a reference for workflow patterns — engagement
lifecycle, evidence-linked findings, exploit verification, skill playbooks, and reporting — and
for its skill content format. The package has no dependency on any Artex fork, service, schema,
or runtime.

### Goals

- **Authorized offensive testing of live web applications**: reconnaissance, active probing,
  and exploit verification against targets declared in an engagement file, inside a hard scope
  boundary enforced in code.
- **Evidence-backed findings**: every persisted finding links to captured request/response
  evidence. A finding the engine cannot tie to evidence is never persisted. Verified findings
  additionally carry a replayable verification record.
- **Findings that always survive**: persisted before any model-backed stage, readable after a
  failed, timed-out, or cancelled summary, verification, agent loop, or chat turn. Evidence is
  persisted **at capture time** (each capture commits immediately), so even a mid-run crash
  discards nothing already sent or received.
- **Two execution modes**:
  - *Passive*: deterministic review of offline evidence bundles (imported captures, config
    excerpts) or of traffic captured during earlier active runs. Passive findings are a pure
    function of (evidence, selected checks, engine version); the model is never in the passive
    findings path.
  - *Active*: scoped live testing — active checks send probes through the target client, and
    verification replays minimal PoC requests to confirm exploitability. Active findings carry
    full evidence snapshots so they are auditable and replayable even though target state may
    drift. Live evidence commits at capture time (see §6.1), so a crash mid-run never loses
    exchanges already paid for in requests.
- **An agent layer** over the run, built on the local pydantic-ai agent stack: an interactive
  operator-driven mode embedded in the CLAI2 `chat()` terminal client, and a `--auto`
  autonomous loop (planner → tool calls → evidence-gated findings) that drives the same agent
  directly via `agent.run()`/`agent.iter()` — not through `chat()`, which is a TUI-only
  conversation API returning `None`. Both are confined to the engagement scope by the tool
  layer, not by the prompt.

### Non-goals (v1)

- No multi-user, no server, no web UI beyond the terminal. One operator, one machine.
- No MITM proxy: live evidence comes from the package's own scoped HTTP client, not from
  intercepting a browser or external tools (see §17).
- No exploit payload development beyond verification: verification proves a finding with the
  minimal request set (an error triggered, a boundary crossed, a version-confirmed CVE
  signature); it does not build shells, persistence, or post-exploitation tooling (see §17).
- No write-back to findings from chat or the agent loop: the model proposes, the engine
  validates evidence and disposes (§9).
- No HAR import, no diffing between runs (see §17).

### Constraints

- Dependent `pydantic-*` packages import from the local checkout (`pydantic-ai-slim`,
  `pydantic-ai-harness`, `pydantic-clai2`), never from PyPI. Given the November 2026
  prebuilt-image backdoor in the Artex lineage (see `README.md`), the package installs its
  `pydantic-*` dependencies only from audited local paths and publishes no prebuilt artifacts;
  non-`pydantic` third-party dependencies (`httpx`, `rich`, `prompt-toolkit`, etc.) resolve from
  the pinned lockfile as normal.
- **Authorization is a hard gate, not a convention.** Every live run requires an engagement
  file containing an explicit authorization attestation, and every outbound request passes a
  scope check in the target client (§4.2). There is no code path that sends traffic without
  both. This mirrors the standing rule of every shipped Artex skill ("authorized engagements
  only") and bbot's program-policy gates, but enforced in code.
- **Secrets are first-class.** Live testing needs real credentials; they enter via engagement
  credential references (environment variables), are marked secret at capture, and are redacted
  in exports by default (§5).
- Model-backed stages (summary, agent, chat) are opt-in and injectable with test models. The
  validation suite never needs credentials or a network beyond localhost (§13).
- Skill content is data (Markdown), including offensive playbooks. It is never executed,
  imported, or interpreted by the engine. Check code loads only from installed distributions
  via entry points (§10).
- Evidence bytes are attacker-controlled input wherever they reach a prompt: they are framed
  as untrusted data, and no model-facing tool can mutate run state (§9).

## 2. Architecture

```text
┌──────────────────────────── artex-web CLI ────────────────────────────────┐
│ engage   review <bundle>   test <eng>   verify <run-id> <finding-id>      │
│ runs   show <run-id>   summarize <run-id>   checks   agent <eng>          │
│ chat <run-id>                                                              │
└──────┬──────────────────────────────────────────────┬───────────────────┘
       │                                              │
┌──────▼───────────────────────────────┐   ┌──────────▼──────────────────┐
│  Engine                              │   │  Agent adapter              │
│  bundle/engagement load + validate   │   │  Pydantic AI agent + scoped │
│  evidence registry                   │   │  tools (http, findings,     │
│  passive checks (deterministic)      │   │  verify) over CLAI2 chat()  │
│  active checks via target client     │   │  interactive + --auto loop  │
│  verification runner (PoC replay)    │   │  load_plugins=False         │
│  findings commit (single writer)     │   └──────────┬──────────────────┘
└──────┬───────────────────────────────┘              │
       │                                             │
┌──────▼─────────────────────────────────────────────▼───────────────────┐
│  RunStore: SQLite (engagements, runs, evidence, findings,              │
│  verifications, tool_calls, summaries) + JSON export                    │
└────────────────────────────────────────────────────────────────────────┘
       ▲                    ▲                            ▲
┌──────┴───────────┐ ┌──────┴──────────────┐ ┌───────────┴───────────┐
│  Skill registry  │ │  Target client      │ │  pydantic-ai core     │
│  skill dirs      │ │  scoped HTTP client │ │  Agent, TestModel,    │
│  (data) + entry- │ │  scope gate, capture│ │  FunctionModel,       │
│  point checks    │ │  rate limiting      │ │  pydantic_clai2       │
└──────────────────┘ └─────────────────────┘ └───────────────────────┘
```

Layer rules:

| Layer | Owns | Never does |
|---|---|---|
| Engine | validation, evidence registration, check execution, verification orchestration, persistence, export | import or execute skill content; build prompts |
| Registry | discover checks (entry points) and skills (directories), join by `check_id` | contain testing logic |
| Target client | scope enforcement, request execution, evidence capture, rate limiting | decide what to request; bypass scope for any caller |
| Agent adapter | agent construction, scoped tools, CLAI2 wiring, `--auto` loop | mutate run state; construct raw HTTP outside the scoped tool |
| Checks (passive) | deterministic review logic over validated evidence | I/O, network, model calls, storage access |
| Checks (active) | probe logic expressed through the target client | construct their own HTTP stack; write storage |

The scope gate lives **only** in the target client, and the target client is the **only** module
that opens sockets. Checks, the verification runner, and the agent's HTTP tool all receive a
client handle scoped to one engagement; a request that fails scope is a hard error before it
reaches the network.

## 3. Package layout

New standalone package at `artex-web/` beside the checkouts (not inside the `pydantic-ai` uv
workspace; see §3.1):

```text
artex-web/
  pyproject.toml
  README.md
  src/artex_web/
    __init__.py            # version, public re-exports
    __main__.py            # console entry point
    cli.py                 # argparse surface (engage/review/test/verify/runs/show/summarize/checks/agent/chat)
    models.py              # Engagement, Scope, ReviewBundle, Evidence, HttpExchange,
                           # ConfigExcerpt, Finding, Verification, ReviewSummary
    bundle.py              # bundle load + validation (passive mode input)
    engagement.py          # engagement load + validation, authorization attestation
    scope.py               # Scope model + matching (hosts, path prefixes, exclusions, ports)
    ids.py                 # content-hash IDs, canonical JSON encoding (sorted keys,
                           #   ensure_ascii, compact separators)
    registry.py            # check/skill discovery and join
    checks/
      __init__.py          # PassiveCheck / ActiveCheck protocols, draft validation
      builtin.py           # header-security (passive), version-disclosure (active probe)
    target.py              # scoped HTTP client (the only socket-opening module), capture
                           #   (httpx, follow_redirects=False, pinned resolver + SNI)
    verify.py              # verification runner: minimal PoC replay, verdict, evidence
    engine.py              # run lifecycle, ordered execution, failure policy, single writer
    storage.py             # SQLite RunStore, schema, migrations
    export.py              # JSON export with default secret redaction
    summarize.py           # model-backed ReviewSummary generation + reference validation
    agent_adapter.py       # agent, AgentDeps, scoped tools, CLAI2 chat() wiring (interactive)
                           # + --auto loop via agent.run()/agent.iter()
    skills/
      header-review/
        SKILL.md           # frontmatter: name, description, checks: [header-security]
        reference/*.md
      version-disclosure/
        SKILL.md
  fixtures/
    bundles/valid/         # valid passive fixture bundle
    bundles/malformed/     # one dir per failure mode (§13)
    target_app/            # deliberately vulnerable fixture app (stdlib http.server, localhost)
    skills/banner-leak/    # fixture skill
  tests/
    conftest.py            # model-call blocking, non-localhost network blocking, tmp stores
    test_bundle.py  test_engagement.py  test_scope.py  test_ids.py  test_registry.py
    test_target.py         # scope gate: in-scope allowed, out-of-scope refused, redirect handling
    test_verify.py         # verdicts, replay, evidence capture against fixture app
    test_engine.py  test_storage.py  test_export.py  test_summarize.py
    test_agent_adapter.py  # tools scoped to engagement+run, out-of-scope tool calls refused,
                           #   tool_calls audit rows recorded
    test_agent_terminal.py # chat() integration: TestModel, Console(StringIO), cancellation
```

### 3.1 Environment and dependencies

- Python `>= 3.11`, matching the checkout's floor. Managed with `uv` (0.12.x, available locally).
- A standalone uv project. `[tool.uv.sources]` maps every `pydantic-*` dependency to the local
  checkout paths so **no `pydantic-*` resolves from PyPI**:
  `pydantic-ai-slim -> pydantic-ai/pydantic_ai_slim`, `pydantic-ai-harness ->
  pydantic-ai/src/pydantic_ai_harness`, `pydantic-clai2 -> pydantic-ai/src/pydantic_clai2`.
  Non-`pydantic` third-party dependencies resolve from the pinned lockfile as normal. The exact
  transitive member list is settled in M0 (§15) by the greenfield dependency check.
- **M0 packaging note**: `pydantic-clai2` declares its `pydantic-ai-slim`/`pydantic-ai-harness`
  deps as `{ workspace = true }` and pins their exact versions via hatch metadata hooks. Because
  `artex-web` is *outside* that workspace, the path sources above must also be accompanied by
  `[tool.uv.overrides]` entries so clai2's workspace references and exact-version pins resolve to
  the local paths. Settling the precise `sources` + `overrides` shape is part of M0, and is a
  known risk (not a surprise) going in.
- Other runtime dependencies: the target client uses **httpx** (pinned via the lockfile; it is
  already a direct dependency of `pydantic-clai2`, so it is present regardless). The
  DNS-rebinding guard and correct SNI + hostname cert verification on a pre-resolved address
  are security-critical; httpx's `follow_redirects=False` and custom transport provide them
  without hand-rolling sockets/`ssl`. No other HTTP library is introduced; anything beyond
  httpx must come from the audited local source set, not PyPI. Dev dependencies: `pytest`,
  `anyio`, `ruff`, `pyright`, `inline-snapshot`.
- Tooling conventions mirror the checkout: ruff with single quotes and 120-column lines, pyright
  strict, `anyio_mode = "auto"`, coverage target 100% branch with narrow pragmas on true I/O
  edges.

## 4. Inputs: engagements and bundles

The package has two input shapes. An **engagement** declares a live target and the authority to
test it; a **bundle** is offline evidence for passive review. One run consumes exactly one
input; an engagement run may later export a bundle (§7) for passive re-review.

### 4.1 Engagement format

```text
engagement/
  engagement.json      # manifest
  credentials.env      # optional; referenced by name, never inlined into the manifest
```

`engagement.json`:

```json
{
  "schema_version": 1,
  "target": {"name": "example-app", "base_url": "https://staging.example.test"},
  "scope": {
    "hosts": ["staging.example.test"],
    "path_prefixes": ["/"],
    "exclusions": ["/admin/shutdown", "/logout"],
    "ports": [443],
    "max_rps": 5,
    "max_requests": 2000
  },
  "authorization": {
    "attestation": "Written authorization from Example Corp, ref SOW-2026-114, expires 2026-12-31.",
    "operator": "j.operator"
  },
  "credentials": {"session": "ARTEX_WEB_CRED_SESSION"},
  "suggested_checks": ["header-security", "version-disclosure"]
}
```

Validation rules (all enforced before any network call, before any model call, before any run
row is finalized):

| # | Rule | Failure mode |
|---|---|---|
| E1 | manifest parses, `schema_version` is exactly `1` | `engagement-version` |
| E2 | `authorization.attestation` is present and non-empty; the CLI additionally requires `--authorized` on every live command, and the stored run records both | `unauthorized` |
| E3 | scope is non-empty: at least one host; every host parses; `exclusions` are within `path_prefixes`; `max_rps` and `max_requests` are positive with hard ceilings (64 rps, 100k requests) | `scope-invalid` |
| E4 | `credentials` values are environment variable **names** matching `[A-Z0-9_]+`; inline values are rejected. Referenced variables must be set at run start | `credential-invalid` / `credential-missing` |
| E5 | `base_url` host must be inside `scope.hosts` | `scope-invalid` |
| E6 | `suggested_checks` entries that are not registered are dropped with a warning | - |

### 4.2 Scope enforcement (target client)

Every outbound request — from an active check, the verification runner, or the agent's HTTP
tool — is validated immediately before send:

1. **Scheme and port**: `http`/`https` only; the effective port must be in `scope.ports`.
2. **Host**: exact match against `scope.hosts` (no suffix matching; `evil-example.test` does
   not match `example.test`). DNS rebinding guard: resolution happens once per run through a
   pinned resolver result, and the client connects to the resolved address while keeping the
   original `Host` header and SNI (and cert verification against the original hostname, not the
   IP) — via httpx's transport, never hand-rolled sockets.
3. **Path**: must start with an allowed `path_prefix` and match no `exclusions` prefix
   (exclusions win).
4. **Redirects**: never followed automatically; a redirect response is captured as evidence,
   and the new location is re-validated from rule 1 if the caller chooses to follow it.
5. **Budgets**: a token-bucket limiter enforces `max_rps`; a run-level counter enforces
   `max_requests`. Exhaustion ends active work cleanly (`checks_complete` with what is
   committed), it is not an error.

A scope violation raises `ScopeViolation` before any bytes hit the wire, is recorded on the
run, and — when triggered by the agent — is returned to the model as a typed tool error. The
client has no API that skips validation; tests assert there is no escape hatch (§13.4).

### 4.3 Bundle format (passive input)

Unchanged from the earlier design, minus the mandatory redaction rule:

```text
bundle/
  bundle.json            # manifest: schema_version, target, evidence_files, suggested_checks
  evidence/NNNN.json     # one HttpExchange or ConfigExcerpt record per file
```

Validation V1–V4 and V6 are as before (parse/version, per-file model validation, deterministic
dedup, size caps, unknown-check warnings). The old V5 (mandatory `<redacted>` markers) is
**dropped**: bundles exported from live runs legitimately contain credentials, which are
handled by the secret-marking and export-redaction machinery (§5) instead. Producers shipping
sanitized bundles may still use the `<redacted>` marker convention; it is accepted, not
required. Sanitization-before-sharing remains the producer's responsibility and is documented;
absence of evidence is not evidence of absence.

Evidence model (v1 kinds) is unchanged: `HttpExchange` (request/response with headers and
optional text bodies) and `ConfigExcerpt` (path, format, content). Response capture sends
`Accept-Encoding: gzip` and transparently decodes `Content-Encoding` before storage; a decoded
body that is not valid UTF-8 (or is dominated by non-printable bytes) is captured as headers
plus a `body_refused` marker — binary bytes are never stored, and `Content-Type` is a hint, not
the arbiter.

## 5. Data contracts

All Pydantic models, `extra='forbid'`, validated at every boundary (input load, check output,
storage round-trip, export).

```python
Severity = Literal['info', 'low', 'medium', 'high', 'critical']

class Evidence(BaseModel):
    id: str                  # "ev_" + sha256(canonical_json)[:16]  (§12)
    kind: EvidenceKind       # http_exchange | config_excerpt
    source: str              # bundle-relative file, or "capture:<run-seq>" for live captures
    http: HttpExchange | None
    config: ConfigExcerpt | None
    secret_fields: list[str] # JSON paths marked secret (credential headers/bodies), redacted on export

class Finding(BaseModel):
    id: str                  # "fn_" + sha256(check_id + '\0' + title + '\0' + sorted evidence_ids)[:16]
    check_id: str
    check_version: str
    severity: Severity
    title: str
    description: str
    evidence_ids: list[str]  # >= 1, each must exist in the run's evidence
    remediation: str
    status: Literal['reported', 'verified', 'verification_failed']
    verification_id: str | None

class Verification(BaseModel):
    id: str                  # "vf_" + sha256(finding_id + '\0' + canonical request set)[:16]
    finding_id: str
    check_id: str
    requests: list[str]      # evidence IDs of the PoC exchanges (scoped, captured)
    verdict: Literal['confirmed', 'not_reproduced', 'inconclusive']
    replayable: bool         # True when verdict came from a deterministic replay recipe
    detail: str              # why the verdict holds: matched error, crossed boundary, etc.

class ReviewSummary(BaseModel):
    narrative: str
    finding_ids: list[str]   # references validated against the saved run (§11)
```

Contract rules:

- A `Finding` is produced by a check as a **draft**; the engine validates drafts (known check
  ID, valid severity, evidence IDs resolve to the run's registered evidence, `evidence_ids`
  non-empty) and only then assigns final IDs and persists. A check can never write storage
  directly. The model is never a draft source: agent-proposed findings enter only as tool
  calls that invoke a registered check or the verification runner, never as free-form text
  (§9).
- New findings start `reported`. The verification runner transitions them to `verified` or
  `verification_failed` and attaches the `Verification` record; both transitions commit with
  the verification's evidence in the same transaction. Verification never deletes a finding.
- A check returning more than 1,000 drafts is rejected as a check failure (`checks_failed`).
- `ReviewSummary.finding_ids` must be a subset of the saved run's finding IDs; duplicates
  rejected; empty list with a non-empty run rejected.
- **Secrets**: at capture time the target client marks fields sourced from engagement
  credentials (matched header names and body tokens) in `secret_fields`. Exports redact those
  fields to `<redacted>` by default; `--include-secrets` emits them and prints a warning.
  Storage holds cleartext (single-operator machine, replay needs it); the export boundary is
  where redaction is enforced.
- Models round-trip: storage writes serialized models and re-validates on read, so a schema
  drift between engine versions is a load error, never silent data loss.

## 6. Engine and run lifecycle

Two entry pipelines share one lifecycle core:

- `run_review(bundle)` — passive: load bundle → validate → register evidence → run passive
  checks → commit findings.
- `run_test(engagement)` — live: load engagement → validate (incl. `--authorized`) → open
  scoped target client → capture baseline exchanges (each committed at capture time) → run
  passive checks over captures → run active checks (probes) → run verification on eligible
  findings → commit findings incrementally per stage (§6.1) → optionally summarize.

```text
load + validate ─▶ register evidence ─▶ checks (passive then active, local workers §7.1)
     │                                          │
  invalid                       findings committed per stage (§6.1) ─▶ checks_complete
  (exit 1)                                          │
                       ┌────────────────────────────┼─────────────────────────────┐
                  --no-summary                 summarize (§11)          failure / timeout /
                       │                           │                       Ctrl-C
                       ▼                           ▼                           ▼
                     done                      complete              stays checks_complete
                                                                   (retry: summarize <run-id>)
```

Run states (stored, monotonic):

| State | Meaning | Findings readable? |
|---|---|---|
| `created` | run row opened, input path recorded | no |
| `invalid` | input failed validation; diagnostic stored | no |
| `checks_complete` | all selected checks finished; findings committed | **yes** |
| `checks_failed` | a check raised; error stored | partial (see §6.1) |
| `complete` | summary generated and reference-validated | yes |

### 6.1 Failure and commit policy

The earlier design committed all findings in one transaction and discarded everything when any
check raised. That stays right for **passive** runs (determinism: a failed passive run
publishes nothing). For **live** runs it is wrong: a crashing check late in a long engagement
must not discard evidence already paid for in requests. Policy:

- *Passive runs*: unchanged — one transaction at the end, `checks_failed` publishes nothing.
- *Live runs*: **evidence commits at capture time** — the target client persists each captured
  exchange as its own small transaction before the check that triggered it proceeds. Findings
  commit **per check**, in selection order, referencing evidence already persisted. A raising
  check aborts the run (`checks_failed`, exit 1, remaining workers cancelled) but earlier
  stages' findings — and every exchange captured up to the failure — stay readable. The run row
  records which check failed (for audit and forensics); there is no `--resume` command in v1
  (see §17 Q1).
- Validation failure aborts **before any network or model call** (exit 1; run row kept in
  `invalid` for audit).
- Summarization failure, timeout (default 60 s, `--summary-timeout`), or Ctrl-C leaves the run
  `checks_complete`; `artex-web summarize <run-id>` retries.
- Without a `--model`, summarize is skipped; the run ends `checks_complete`.
- Budget exhaustion (`max_requests`) ends active stages cleanly and transitions to
  `checks_complete`, not failure.
- A second run on the same input creates a new run row; runs are immutable once
  `checks_complete` except finding `status` transitions from `verify` (§8).

Exit codes: `0` completed, no findings; `3` completed, findings present; `2` usage error
(argparse's default — kept distinct so a malformed invocation is never mistaken for "findings
present"); `1` fatal (invalid input, unauthorized, scope error at startup, storage error, check
crash); `130` interrupted.

## 7. Storage and export

Single SQLite file, stdlib `sqlite3`, WAL mode. Default path: `$XDG_DATA_HOME/artex-web/artex-web.db`
(fallback `~/.local/share/artex-web/`), overridable with `--db PATH` / `ARTEX_WEB_DB`. One
operator, one machine: work runs on local workers inside one process (§7.1). The database must
live on a local filesystem (WAL is unreliable on network mounts); documented, not detected.

### 7.1 Local workers and the single-writer rule

Workers are anyio tasks inside the `test`/`review` process. No worker processes, no remote
workers, no database-backed job queue in v1.

- **The engine is the only writer.** Workers receive validated evidence (passive) or a scoped
  target-client handle (active) and return drafts; they never hold a write handle. The engine
  validates every draft and commits. For live runs the engine also persists each captured
  exchange at capture time (a small transaction per capture) so evidence survives a mid-run
  crash. Worker count never changes the number of SQLite writers.
- **Dispatch, not claiming.** Bounded pool (`--workers N`, default `min(4, os.cpu_count())`;
  `--workers 1` serial) via anyio task group + `CapacityLimiter`. No claim table, no polling.
- **Order independence.** Passive results are assembled in selection order regardless of
  completion order; live runs commit per check in selection order. Which worker finishes first
  never affects storage or export.
- **Shared budget.** The target client's rate limiter and request counter are process-wide, so
  `--workers N` parallelizes latency, never exceeds the engagement's rps.
- **Connections.** One writer connection; readers open their own `mode=ro` connections.
  Blocking calls via `anyio.to_thread.run_sync`. Pragmas: `journal_mode=WAL`,
  `busy_timeout=5000`, `foreign_keys=ON`, `synchronous=NORMAL`.
- **Other processes read, never write, concurrently.** `chat`, `show`, `runs` read committed
  state while a run writes. Two concurrent writers serialize on `BEGIN IMMEDIATE` +
  `busy_timeout`; lock timeout exits 1 with a clear message.

```sql
CREATE TABLE engagements (
  id TEXT PRIMARY KEY,            -- "eng_" + sha256(canonical engagement.json)[:16]
  name TEXT NOT NULL,
  base_url TEXT NOT NULL,
  scope TEXT NOT NULL,            -- serialized Scope
  attestation TEXT NOT NULL,
  operator TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE runs (
  id TEXT PRIMARY KEY,            -- "run_" + uuid4
  created_at TEXT NOT NULL,
  state TEXT NOT NULL,
  input_kind TEXT NOT NULL,       -- 'bundle' | 'engagement'
  input_ref TEXT NOT NULL,        -- bundle path or engagement id
  input_sha256 TEXT NOT NULL,     -- fingerprint over sorted (file, sha256(file))
  engine_version TEXT NOT NULL,
  selected_checks TEXT NOT NULL,  -- JSON array, selection order
  authorized_flag INTEGER NOT NULL DEFAULT 0,  -- --authorized was passed (live runs)
  model TEXT,
  requests_spent INTEGER NOT NULL DEFAULT 0,   -- live runs: outbound requests consumed
  scope_snapshot TEXT,            -- serialized Scope (live runs), for cross-run coverage comparison
  error TEXT,                     -- check/validation failure diagnostic
  summary_error TEXT              -- summary generation/validation failure diagnostic
);
CREATE TABLE evidence (
  run_id TEXT NOT NULL REFERENCES runs,
  evidence_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  content TEXT NOT NULL,          -- serialized Evidence (incl. secret_fields)
  PRIMARY KEY (run_id, evidence_id)
);
CREATE TABLE findings (
  run_id TEXT NOT NULL REFERENCES runs,
  finding_id TEXT NOT NULL,
  check_id TEXT NOT NULL,
  check_version TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  evidence_ids TEXT NOT NULL,     -- JSON array
  remediation TEXT NOT NULL,
  status TEXT NOT NULL,           -- reported | verified | verification_failed
  PRIMARY KEY (run_id, finding_id)
);
CREATE TABLE verifications (
  run_id TEXT NOT NULL REFERENCES runs,
  verification_id TEXT NOT NULL,
  finding_id TEXT NOT NULL,
  verdict TEXT NOT NULL,
  content TEXT NOT NULL,          -- serialized Verification
  created_at TEXT NOT NULL,
  PRIMARY KEY (run_id, verification_id)
);
CREATE TABLE tool_calls (
  run_id TEXT NOT NULL REFERENCES runs,
  call_id TEXT NOT NULL,          -- "tc_" + uuid4
  tool TEXT NOT NULL,             -- http_request | run_check | request_verification | ...
  args TEXT NOT NULL,             -- JSON, secret values redacted at capture
  result TEXT NOT NULL,           -- JSON summary (typed error or committed-effect reference)
  created_at TEXT NOT NULL,
  PRIMARY KEY (run_id, call_id)
);
CREATE TABLE summaries (
  run_id TEXT PRIMARY KEY REFERENCES runs,
  content TEXT NOT NULL,
  model TEXT NOT NULL,
  generated_at TEXT NOT NULL
);
```

Schema versioning: `PRAGMA user_version`; a store with an unknown version is refused with a
clear error, never migrated destructively (§17).

Export (`artex-web show <run-id> --format json [--out FILE]`) emits the run, its evidence, its
findings, its verifications, its tool calls, and its summary (or `null`), with sorted keys and
stable field order. **`secret_fields` are redacted to `<redacted>` by default**; `--include-secrets` opts
out and warns. Export excludes `created_at`, run IDs, and timestamps, so the repeatability
experiment compares passive exports byte-for-byte (§13). Findings order: (severity rank desc,
check_id, finding_id); evidence by registration order. `artex-web export-bundle <run-id>`
emits a passive-reviewable bundle from a live run's captures (redacted by default).

## 8. CLI surface

| Command | Purpose | Key flags |
|---|---|---|
| `artex-web engage init <dir>` | scaffold an engagement file | `--target`, `--scope-host` |
| `artex-web engage check <dir>` | validate engagement + scope + credentials, no traffic | `--json` |
| `artex-web review <bundle>` | passive review of an offline bundle | `--checks a,b` / `--all`, `--workers N`, `--db`, `--no-summary`, `--model`, `--out` |
| `artex-web test <engagement>` | live run: capture, passive + active checks, verify | `--authorized` (required), `--checks`, `--workers`, `--no-verify`, `--no-summary`, `--model`, `--db` |
| `artex-web verify <run-id> <finding-id>` | (re)run verification for one finding in one run | `--authorized`, `--db` |
| `artex-web export-bundle <run-id>` | write a passive bundle from a live run's captures | `--out DIR`, `--include-secrets` |
| `artex-web runs` | list runs (id, state, input, findings count) | `--db`, `--json` |
| `artex-web show <run-id>` | export a run | `--format json\|text`, `--include-secrets`, `--out`, `--db` |
| `artex-web summarize <run-id>` | (re)generate the summary | `--model`, `--summary-timeout`, `--db` |
| `artex-web checks` | list registered checks (kind, scope needs) and their skills | `--json` |
| `artex-web agent <engagement>` | deterministic `test` pipeline, then interactive agent or autonomous `--auto` loop | `--authorized` (required), `--model`, `--agent-max-requests`, `--db` |
| `artex-web chat <run-id>` | read-only review chat over a saved run | `--model`, `--db`, `--skill-dir` |

Selection semantics unchanged: `--checks` is an explicit, ordered, de-duplicated list; unknown
ID exits 1 listing available IDs; `--all` runs registration order; empty selection is a usage
error. `--no-verify` skips verification (findings stay `reported`); verification can always be
run later per finding.

The `test` command prints a compact summary to stdout (run id, requests spent, checks run,
findings by severity and status) and writes the full export when `--out` is given. Output is
JSON when stdout is not a TTY.

## 9. Agent and CLAI2 integration

Two model surfaces, both built on the local pydantic-ai agent stack. Interactive mode embeds
the agent in the CLAI2 [`chat()` terminal client](pydantic-ai/src/pydantic_clai2/pydantic_clai2/app.py#L165)
(`chat()` is a TUI conversation API that returns `None`); `--auto` drives the agent directly
via `agent.run()`/`agent.iter()` with `UsageLimits`, never through the terminal:

**`chat <run-id>` — read-only reviewer** (unchanged from the earlier design): three run-scoped
read tools (`list_findings`, `get_finding`, `lookup_evidence`), `load_plugins=False`, skill
content injected at agent build time, evidence framed as attacker-controlled data, no write
tools, cross-run IDs return typed not-found errors.

**`agent <engagement>` — operator in the loop or `--auto`**: an agent with tools over the live
engagement. `agent` runs the **same deterministic pipeline as `test`** first — baseline capture
+ passive checks + active checks + verification — producing a `checks_complete` run with
model-free findings, and *then* hands control to the model for the operator or `--auto` loop on
top of that evidence baseline. The model augments the run via tools; it never replaces the
deterministic pass:

```python
@dataclass
class AgentDeps:
    engagement_id: str
    run_id: str
    client: ScopedHttpClient   # target client handle; scope enforced inside (§4.2)
    engine: EngineHandle       # submit drafts, request verification — never raw storage

def build_agent(model: Model | str) -> Agent[AgentDeps, str]:
    agent = Agent(model, deps_type=AgentDeps, output_type=str, system_prompt=TESTER_SYSTEM_PROMPT)

    @agent.tool
    def http_request(ctx, method: str, path: str, headers: dict[str, str] | None,
                     body: str | None, host: str | None = None) -> Evidence: ...
        # sends via deps.client; `host` defaults to base_url's host and is validated against
        # scope.hosts (so the agent can address any in-scope host, incl. cross-host redirects);
        # ScopeViolation → typed tool error; exchange auto-captured

    @agent.tool
    def run_check(ctx, check_id: str) -> list[Finding]: ...
        # invokes a registered check through the engine; engine validates + commits drafts

    @agent.tool
    def request_verification(ctx, finding_id: str) -> Verification: ...

    @agent.tool
    def list_findings(ctx) -> list[Finding]: ...

    @agent.tool
    def lookup_evidence(ctx, evidence_id: str) -> Evidence: ...
```

Design rules:

- **No plugins**: `load_plugins=False`; no coding tools, no filesystem access, no network
  except the scoped `http_request` tool.
- **Scope is enforced in the tool layer.** `http_request` is the only network door and it goes
  through the engagement-scoped client (§4.2). The system prompt states the rules, but the
  design never relies on the model obeying them: out-of-scope requests fail as typed errors.
- **The model never writes findings.** It can only invoke `run_check` / `request_verification`;
  the engine validates drafts and evidence and commits. A model-invented finding with no
  evidence cannot enter the store by construction.
- **`--auto` loop**: the agent runs a bounded planner loop (recon → hypothesize → `run_check` →
  `request_verification` → report) driven directly through `agent.run()`/`agent.iter()` under
  `UsageLimits` and the engagement's `max_requests` budget. The budget is the hard stop; the
  loop also stops when a full planner pass yields no new actions. The optional
  `--agent-max-requests` flag sets a tighter agent-loop budget that can only lower the
  engagement ceiling, never raise it. Every tool call is recorded in the `tool_calls` table
  (§7), so an `--auto` run is fully auditable after the fact.
- **Skill content is injected at construction**: the adapter reads the run's `SKILL.md` bodies
  and `reference/*.md` once at build time (including offensive playbooks such as an
  `api-security`-style skill) and renders them into the system prompt. No tool reads files.
- **Terminal behavior**: Esc cancels the current turn; failed/cancelled turns retain history
  (CLAI2 semantics); committed findings are unaffected by construction.
- The agent adapter module is the only file that imports `pydantic_clai2`. Tests drive both
  surfaces with `TestModel` / `FunctionModel` and `Console(file=StringIO())`, plus one manual
  tmux pass per release (§14).

## 10. Skill boundary and registry

Skills are packaged testing knowledge (Artex-style `SKILL.md` directories, now including
offensive playbooks); checks are code. They stay outside the engine and are joined by
`check_id`.

**Skill directory** (data only, never executed):

```text
skills/<name>/
  SKILL.md        # YAML frontmatter: name, description, checks: [...]
  reference/*.md  # optional deeper content; injected into agent prompts at build time
```

**Check discovery** (code, installed only). Two protocols:

```python
class PassiveCheck(Protocol):
    check_id: str
    version: str
    title: str
    description: str
    def applies_to(self, evidence: Sequence[Evidence]) -> bool: ...
    def review(self, evidence: Sequence[Evidence]) -> Sequence[FindingDraft]: ...

class ActiveCheck(Protocol):
    check_id: str
    version: str
    title: str
    description: str
    def applies_to(self, evidence: Sequence[Evidence]) -> bool: ...
    def probe(self, evidence: Sequence[Evidence],
              client: ScopedHttpClient) -> Sequence[FindingDraft]: ...
    def verify_recipe(self, finding: Finding) -> VerificationRecipe | None: ...
```

- `verify_recipe` returns the minimal request set that confirms the finding (the replay the
  verification runner executes); checks without a recipe produce `reported`-only findings.
- Third-party checks register via the entry-point group `artex_web.checks`. Check code loads
  **only** from installed distributions; extra skill roots load via `--skill-dir` (data). That
  is the trust boundary: arbitrary paths can add Markdown, never code.
- A skill naming an unregistered check is a warning at `artex-web checks` time; a check with
  no skill is fine; a skill with no check is fine (agent playbook only).

**Fixtures**:

1. `header-review` skill + `header-security` passive check (built-in): missing
   HSTS/CSP/`X-Content-Type-Options`, cookie attribute gaps, CORS `*` with credentials, on
   captured or bundled HTML responses.
2. `version-disclosure` skill + active check (built-in): probe `/`, `/robots.txt`, a
   deliberately unknown path; flag `Server`/`X-Powered-By` version banners and verbose error
   pages; `verify_recipe` replays the single banner-bearing request.
3. `banner-leak` skill + check (fixture only, §13 experiment 2): passive equivalent for the
   registry-separation test.

The header-review fixture exercises the whole passive contract; the version-disclosure fixture
exercises capture → active probe → verify → replay → export against the local fixture app.

## 11. Summarization

Unchanged in shape from the earlier design:

```python
async def summarize_run(run_id: str, store: RunStore, model: Model) -> ReviewSummary
```

- `output_type=ReviewSummary` agent over the run's findings (id, severity, status, title,
  description, remediation). Raw evidence stays out of the summarizer prompt in v1.
- Two-layer reference validation: output validator raises `ModelRetry` listing valid finding
  IDs on hallucination (bounded retries, default 2); final failure records `runs.summary_error`
  and leaves the run `checks_complete`. Engine-side validation repeats the check before
  persisting.
- Timeout via `anyio.fail_after` (default 60 s) and Ctrl-C behave like validation failure.
- The narrative must distinguish `verified` from `reported` findings; the prompt includes
  status, and the output schema keeps it via `finding_ids` referencing findings whose status is
  stored.

## 12. Determinism and reproducibility

The scope change splits the guarantee in two:

- **Canonical JSON** (defined once, in `ids.py`) is the encoding every hash and byte-determinism
  claim below depends on: objects with keys sorted lexicographically, strings UTF-8 encoded with
  `ensure_ascii=True`, separators `(',', ':')`, no trailing whitespace, `\n` at end of file
  where applicable.
- **Passive mode keeps full determinism.** Evidence ID = `ev_` + sha256 of the canonical JSON of
  `kind` + `http`/`config` **only** (excluding `id`, `source`, and `secret_fields`, so an
  exchange hashes the same whether captured live or re-imported from a bundle); finding ID =
  `fn_` + sha256 of `check_id + '\0' + title + '\0' + '\0'.join(sorted evidence_ids)`. Checks
  may run concurrently but assemble in selection order; exports are canonical JSON. Given the
  same bundle and selection, passive exports are byte-identical across runs, machines, and
  restarts.
- **Live mode guarantees auditability, not byte-identity.** Target state drifts, so findings
  from live runs cannot be byte-reproducible. Instead: every request and response the engine
  sends or receives is captured as evidence; every finding links its evidence; every
  verification links the exact PoC exchanges and a replay recipe; input fingerprint +
  `engine_version` + `check_version` are stored per run. `artex-web verify <run-id> <finding-id>`
  re-executes the recipe against the target to test whether the finding still reproduces.
- Live runs record `requests_spent` and the scope snapshot (`runs.scope_snapshot`), so two live
  runs over the same engagement can be compared for coverage even when their findings differ.

## 13. Validation experiments

Each experiment is scripted and credential-free: live tests run against the bundled fixture
target app on localhost; all fixtures live in `artex-web/fixtures/`. Experiments gate the
milestones (§15).

**Fixture target app** (`fixtures/target_app/`): a deliberately vulnerable stdlib
`http.server` app bound to `127.0.0.1` on an ephemeral port, serving: version-leaking
`Server` header, an error page with a stack trace, an endpoint missing security headers, a
reflected-parameter endpoint, and an out-of-scope-decoy route. A fixture engagement points at
it; a second fixture engagement deliberately omits the app's host for scope-gate tests.

### 13.1 Greenfield dependency check

As before: fresh venv, local path sources, run `artex-web review fixtures/bundles/valid
--checks header-security --no-summary` from outside any checkout; assert no `artex`/`strix`
distribution, no Artex-fork modules in `sys.modules`, no PyPI `pydantic-*` (non-`pydantic`
deps may come from PyPI).

### 13.2 Skill separation

As before: register `banner-leak` via a tiny entry-point distribution (or the public registry
API), run the same passive review, confirm findings persist and export with **no edits** to
`engine.py`, `storage.py`, `models.py`, `agent_adapter.py`.

### 13.3 Engine repeatability and failure policy

(a) Passive: two fresh stores, byte-identical exports. (b) Every malformed bundle and every
invalid engagement (missing attestation, inline credential, empty scope, base URL outside
scope) exits 1 with a diagnostic naming the rule, with a model factory and a socket factory
that raise if ever called. (c) `--workers 1` vs `--workers 8` with reverse-order completion:
passive exports byte-identical. (d) Concurrent readers during a live run; second writer
serializes or exits 1 with the lock message; `PRAGMA integrity_check` passes. (e) Live
failure policy: a fixture check that raises after two earlier checks committed leaves those
findings readable in `checks_failed`.

### 13.4 Scope gate, capture, and verification

All against the fixture app on localhost; a `conftest.py` fixture blocks every non-localhost
socket.

- *Scope gate*: requests to an out-of-scope host, an excluded path, a disallowed port, and a
  redirect to an out-of-scope location are each refused before sending (assert no bytes hit
  the wire via a socket-level spy); the refusals are recorded on the run.
- *Authorization*: `test` without `--authorized` exits 1 before any network or model call.
- *Capture*: a live `test` against the fixture app records every exchange as evidence;
  `export-bundle` round-trips into a passive `review` that reproduces the passive findings.
- *Verification*: `version-disclosure` finds the banner, `verify` confirms it (verdict
  `confirmed`, evidence attached, finding transitions to `verified`); a fixture app variant
  without the banner yields `not_reproduced` and `verification_failed`; both transitions keep
  the finding readable.
- *Budgets*: `max_requests: 3` ends the run cleanly in `checks_complete` with exactly three
  captured requests.
- *Redaction*: with a credential env var set, captured evidence marks `secret_fields`; default
  export shows `<redacted>`; `--include-secrets` shows the value and warns.
- *Agent*: `TestModel` (calls every tool) drives `agent` against the fixture engagement:
  `http_request` in scope succeeds and is captured; out-of-scope calls return typed errors;
  `run_check` commits evidence-backed findings; a scripted model turn that tries to emit a
  free-form finding cannot (no such tool). Every tool invocation lands in `tool_calls` (with
  secret args redacted). `--auto` terminates within `max_requests`.

### 13.5 Model and terminal integration

As before: hallucinated summary references trigger `ModelRetry` then persist; always-invalid
summary leaves `checks_complete` with `runs.summary_error` set; run-scoped chat tools reject
cross-run IDs; cancellation mid-turn keeps findings readable and retains history; summary
timeout is retryable. All with `TestModel`/`FunctionModel`; real model calls blocked globally.

## 14. Test strategy

- **Stack**: pytest + anyio pytest plugin (`anyio_mode = "auto"`), inline-snapshot, ruff +
  pyright strict, 100% branch coverage target with audited pragmas.
- **Network blocking**: a session fixture fails any socket connect to a non-loopback address,
  so the suite is hermetic by construction; the fixture target app binds `127.0.0.1` only.
- **Model blocking**: session fixture fails any model that is not `TestModel`/`FunctionModel`.
- **Isolation**: fresh temporary SQLite store per test; no test touches `$XDG_DATA_HOME`; no
  test needs real credentials (fixture engagement credentials point at dummy env vars set by
  the fixture).
- **Priority**: integration over unit — full `run_review`/`run_test` calls with test models,
  real SQLite on tmp paths, real cancel scopes, the real fixture app.
- **Terminal**: headless in CI (`Console(file=StringIO())`); interactive behavior (Esc,
  prompt, transcript) verified manually in tmux before each release, per the CLAI2 project's
  own testing rule.

## 15. Milestones

Each milestone ends with its experiments run and documented in this file's results table (§13
gains a "result" column as experiments land).

| # | Milestone | Delivers | Gated by |
|---|---|---|---|
| M0 | Environment | package skeleton, uv project with local path sources, CI stub, network + model blocking fixtures | 13.1 |
| M1 | Passive core | `models.py`, `bundle.py`, `ids.py`, `storage.py`, `export.py`, `engine.py` (passive path), header-security check, bundle fixtures, `review`/`runs`/`show`/`checks` CLI | 13.3 (a–d) |
| M2 | Registry and skill separation | `registry.py`, skills as data, entry-point loading, `banner-leak` fixture distribution, `--skill-dir` | 13.2 |
| M3 | Live testing | `engagement.py`, `scope.py`, `target.py`, `verify.py`, live engine path, per-check commits, fixture target app, `engage`/`test`/`verify`/`export-bundle` CLI, version-disclosure check | 13.3 (e), 13.4 (scope, authorization, capture, verification, budgets, redaction) |
| M4 | Summarization | `summarize.py`, `summarize` CLI, retry/validation/timeout policy | 13.5 (references, timeout) |
| M5 | Agent and chat | `agent_adapter.py`, `chat` (read-only) + `agent` (interactive via `chat()` and `--auto` via `agent.run()`/`agent.iter()`), headless + cancellation tests, tmux checklist | 13.4 (agent), 13.5 (retrieval, cancellation) |
| M6 | Hardening | coverage to target, README, engagement author docs (scope, authorization, credential handling), experiment results recorded | all |

## 16. Risks

| Risk | Mitigation |
|---|---|
| The tool is used outside authorized engagements | Hard gates: attestation + `--authorized` required before any traffic; scope enforced in the one module that opens sockets; README and `engage init` template make the authorization requirement unmissable. (This deters accidents and casual misuse, not a determined operator — same posture as the original Artex skills' standing rules.) |
| Scope bypass (redirect, DNS rebinding, URL parsing edge) | No automatic redirects; pinned per-run resolution; canonicalization tested with hostile URL fixtures; 13.4 asserts nothing reaches the wire on violation |
| CLAI2 `chat()` is a local checkout API that moves | Adapter is one module + one integration test; checkout is path-pinned; seam exercised by 13.4/13.5 rather than assumed |
| Terminal tests flaky in CI | Headless-only in CI; interactive checks are manual tmux gates |
| Live mode's non-determinism hides regressions | Passive mode keeps byte-determinism; live findings always carry evidence + replay recipe; `verify` re-tests reproducibility on demand |
| Secrets leak through exports, logs, or prompts | Secret marking at capture; export redaction by default; summarizer sees findings only; chat/agent evidence framing; 13.4 tests redaction |
| Runaway agent loop spends unbounded requests | Engagement `max_requests` is a hard budget in the client; `--auto` additionally bounded by `UsageLimits`; every tool call captured for audit |
| Entry-point checks add supply-chain surface | Code loads only from installed distributions, never paths; skills are data-only; no prebuilt artifacts published |
| Prompt injection through captured responses steers the agent | Evidence framed as untrusted data; model has no write path to findings; scope gate is code, not prompt; the worst a hostile response can do is waste budget |
| Active checks harm a fragile target | Conservative defaults: rps ceiling, exclusion list, minimal-request verification recipes; no fuzzing payloads in v1 checks beyond error-triggering inputs (§17) |
| SQLite becomes a multi-operator tool by accretion | v1 documents one operator, one machine; store refuses unknown `user_version` |
| Workers write to the store directly as features accrete | Single-writer rule; test asserts `RunReader` connections open `mode=ro` and check code cannot import `storage` |
| `database is locked` under concurrent processes | WAL + `busy_timeout`; one writer connection per process; `BEGIN IMMEDIATE`; lock timeout exits 1 clearly |

## 17. Open questions

1. **Resume policy for live runs (deferred out of v1)**: when `--resume` is added, should it
   re-run from the failed check, or from the failed check *plus* re-verification of earlier
   findings (target may have changed mid-run)? The failed-check marker is recorded in v1; the
   resume command itself is future work. Re-verification is available per-finding today via
   `verify <run-id> <finding-id>`.
2. **Verification depth**: where exactly is the v1 line between "minimal confirmation" and
   exploitation proper? Proposal: verification may trigger errors, cross an auth boundary with
   provided credentials, or match a known-vulnerable signature — and stops there. Too tight?
3. **Exit code for findings (decided)**: `3` = completed with findings, `2` = usage error, `0`
   = completed with no findings. This departs from strix's `2` because argparse already owns `2`
   for usage errors; see §6.
4. **Migration policy**: additive `ALTER TABLE` with `user_version` bumps (Go forks' approach)
   vs. refuse-and-export/import for v1 only?
5. **HAR / proxy ingestion**: the Go forks capture via MITM proxy; is `artex-web import-har`
   worth shipping as a passive-bundle producer, or does the scoped client stay the only
   live-capture path?
6. **Chat annotation**: should `chat` gain append-only operator notes (never findings
   mutation), needing a notes table and a read-only-plus-notes store handle?
7. **CLAI2 session reuse**: should the run record store the agent/chat `session_id` so
   re-invocation resumes the conversation?
8. **Post-M6 skill port**: which BaaRai offensive playbooks (`api-security`, `patch-diff`,
   `codeaudit`) port first as data-only skills, and which need new check protocols (e.g. a
   `SourceCheck` for white-box audit) the engine does not yet have?

## 18. Defaults

One local operator, one machine, authorized engagements only, and a credential-free validation
suite against a local fixture target. SQLite (WAL) in the user data directory, checks on
in-process local workers, the engine as the only writer, and the target client as the only
network door with scope enforced inside it. `--no-summary` is the only model-free mode and the
default for CI; summary, agent, and chat require an explicit `--model`. Passive review of
offline bundles is a first-class mode with full determinism; live runs trade byte-determinism
for evidence-backed auditability and replayable verification. The shipped skill set is the
header-review and version-disclosure fixtures until the experiments pass end to end; broader
skill content — including offensive playbooks from the BaaRai inventory — is integrated only
after M6, one skill at a time, each with its own fixture.
