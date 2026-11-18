# Greenfield Python framework for web application review

> Status: development plan, deepened from the initial sketch. No code yet. The validation
> experiments in §13 are proposed and have not been run. The initial sketch's constraints are
> preserved: no dependency on any Artex fork, skills stay outside the engine, and the validation
> suite runs credential-free.

## 1. Scope

Build a new Python package, `artex-web` (import name `artex_web`), from scratch using the local
Pydantic AI and CLAI2 checkout. Use Artex as a reference for workflow patterns such as run
lifecycle, evidence-linked findings, and reporting. Keep applicable defensive review skills as
standalone content outside the engine. The package has no dependency on any Artex fork, service,
schema, or runtime.

### Goals

- Review a web application's **defensive security posture from offline evidence**: sanitized HTTP
  captures and configuration excerpts. The package never sends traffic to a target; everything it
  needs is in a bundle on disk.
- Deterministic findings: a run is a pure function of (bundle, selected checks, engine version).
  The model is never in the findings path.
- Findings that always survive: persisted before any model-backed stage, readable after a failed,
  timed-out, or cancelled summary and after a cancelled chat turn.
- An interactive reviewer over a completed run, built on the local CLAI2 `chat()` API, with a
  read-only evidence lookup scoped to the selected run.

### Non-goals (v1)

- No exploitation, no live scanning, no autonomous agent loops. Checks are deterministic code over
  validated evidence; the model reads, it does not decide findings.
- No multi-user, no server, no UI beyond the terminal.
- No HAR import, no proxy capture, no diffing between runs (see §17).
- No write-back from chat: the interactive review cannot create or modify findings (see §17).

### Constraints

- Dependent packages import from the local checkout (`pydantic-ai-slim`, `pydantic-ai-harness`,
  `pydantic-clai2`), not from PyPI. Given the November 2026 prebuilt-image backdoor in the Artex
  lineage (see `README.md`), the package installs only from audited local paths and publishes no
  prebuilt artifacts.
- The engine makes **no network calls**. Model-backed stages (summary, chat) are opt-in and
  injectable with test models.
- Skill content is data (Markdown). It is never executed, imported, or interpreted. Check code
  loads only from installed distributions via entry points (§10).
- Evidence bytes are attacker-controlled input wherever they reach a prompt: they are framed as
  untrusted data, and no tool can write (§9).

## 2. Architecture

```text
┌────────────────────────── artex-web CLI ───────────────────────────┐
│  review <bundle>   runs           show <run-id>   summarize <id>   │
│  checks            chat <run-id>                                │
└──────┬─────────────────────────────────────────────────┬─────────┘
       │                                                  │
┌──────▼───────────┐                            ┌─────────▼──────────┐
│  Review engine   │                            │  Chat adapter      │
│  bundle load     │                            │  custom Pydantic   │
│  + validate      │                            │  AI agent + read-  │
│  evidence reg.   │                            │  only run tools    │
│  checks (ordered)│                            │  over CLAI2 chat() │
│  findings commit │                            │  load_plugins=False│
│  summarize       │                            └─────────┬──────────┘
└──────┬───────────┘                                      │
       │                                                  │
┌──────▼─────────────────────────────────────────────────▼──────────┐
│  RunStore: SQLite (runs, evidence, findings, summaries, checks)   │
│  JSON export (artex-web show)                                    │
└──────────────────────────────────────────────────────────────────┘
       ▲                                    ▲
┌───────┴────────────┐            ┌─────────┴───────────┐
│  Skill registry    │            │  pydantic-ai core   │
│  skill dirs (data) │            │  Agent, TestModel,  │
│  + entry-point     │            │  FunctionModel      │
│    checks (code)   │            │  pydantic_clai2     │
└────────────────────┘            └─────────────────────┘
```

Layer rules:

| Layer | Owns | Never does |
|---|---|---|
| Engine | bundle validation, evidence registration, check execution, persistence, export | import or execute skill content |
| Registry | discover checks (entry points) and skills (directories), join by `check_id` | contain review logic |
| Chat adapter | agent construction, run-scoped read tools, CLAI2 wiring | mutate run state |
| Checks | deterministic review logic over validated evidence | I/O, network, model calls, storage access |

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
    cli.py                 # argparse surface (review/runs/show/summarize/checks/chat)
    models.py              # ReviewBundle, Evidence, HttpExchange, ConfigExcerpt, Finding, ReviewSummary
    bundle.py              # on-disk load + validation + sanitization rules
    ids.py                 # content-hash IDs, canonical JSON encoding
    registry.py            # check/skill discovery and join
    checks/
      __init__.py          # ReviewCheck protocol, draft validation
      builtin.py           # header-security check (fixture #1)
    engine.py              # run lifecycle, ordered execution, failure policy
    storage.py             # SQLite RunStore, schema, migrations
    export.py              # deterministic JSON export
    summarize.py           # model-backed ReviewSummary generation + reference validation
    chat_adapter.py        # agent, ChatDeps, read-only tools, CLAI2 chat() wiring
    skills/
      header-review/
        SKILL.md           # frontmatter: name, description, checks: [header-security]
        reference/*.md     # defensive review content (data only)
  fixtures/
    bundles/valid/         # valid fixture bundle (see §4)
    bundles/malformed/     # one dir per failure mode (§13, experiment 3)
    skills/banner-leak/    # fixture skill #2 (§13, experiment 2)
  tests/
    conftest.py            # model-call blocking, tmp stores, fixture paths
    test_bundle.py  test_ids.py  test_registry.py  test_engine.py
    test_storage.py  test_export.py  test_summarize.py
    test_chat_agent.py     # tools scoped to one run, invalid IDs rejected
    test_chat_terminal.py  # chat() integration: TestModel, Console(StringIO), cancellation
```

### 3.1 Environment and dependencies

- Python `>= 3.11`, matching the checkout's floor. Managed with `uv` (0.12.x, available locally).
- A standalone uv project. `[tool.uv.sources]` maps every `pydantic-*` dependency to the local
  checkout paths so nothing resolves from PyPI:
  `pydantic-ai-slim -> pydantic-ai/pydantic_ai_slim`, `pydantic-ai-harness ->
  pydantic-ai/src/pydantic_ai_harness`, `pydantic-clai2 -> pydantic-ai/src/pydantic_clai2`.
  The exact transitive member list is settled in M0 (§15) by the greenfield dependency check.
- Other runtime dependencies: none expected beyond stdlib (`sqlite3`, `argparse`, `hashlib`,
  `json`). Dev dependencies: `pytest`, `pytest-anyio`, `ruff`, `pyright`, `inline-snapshot`.
- Tooling conventions mirror the checkout so the codebase reads as a sibling: ruff with single
  quotes and 120-column lines, pyright strict, `anyio_mode = "auto"`, coverage target 100% branch
  with narrow `# pragma: no cover` on true I/O edges.

## 4. Bundle format

A bundle is a directory:

```text
bundle/
  bundle.json            # manifest
  evidence/
    0001.json            # one HttpExchange or ConfigExcerpt record per file
    ...
```

`bundle.json`:

```json
{
  "schema_version": 1,
  "target": {"name": "example-app", "base_url": "https://example.test", "notes": "staging capture, sanitized"},
  "evidence_files": ["evidence/0001.json"],
  "suggested_checks": ["header-security"]
}
```

### Validation rules (all enforced before any model call, before any run row is finalized)

| # | Rule | Failure mode |
|---|---|---|
| V1 | manifest parses, `schema_version` is exactly `1` | `bundle-version` |
| V2 | every `evidence_files` entry exists, parses, and passes its Pydantic model | `evidence-invalid:<file>` |
| V3 | evidence IDs are unique (engine derives IDs, so this means content is deduplicated deterministically) | dedup, not failure |
| V4 | caps: <= 500 evidence files, <= 256 KiB per body/excerpt, <= 100 headers per message, <= 64 KiB per URL | `bundle-too-large:<file>` |
| V5 | sanitization: `authorization`, `cookie`, `set-cookie`, `proxy-authorization`, `x-api-key` headers must be exactly the marker `<redacted>` | `unsanitized:<file>:<header>` |
| V6 | `suggested_checks` entries that are not registered are dropped with a warning, not an error | - |

Sanitization is the producer's responsibility; the validator enforces the marker convention on the
sensitive headers it knows (V5) and documents that absence of evidence is not evidence of
absence. Binary bodies are refused: captures carry text bodies only in v1 (bodies are UTF-8
decoded or the file is rejected).

Evidence model (v1 kinds):

```python
class EvidenceKind(StrEnum):
    http_exchange = 'http_exchange'
    config_excerpt = 'config_excerpt'

class HttpExchange(BaseModel):
    request: HttpRequest     # method, url, headers, body?
    response: HttpResponse   # status, headers, body?

class ConfigExcerpt(BaseModel):
    path: str                # e.g. "nginx/server.conf"
    format: Literal['ini', 'json', 'yaml', 'text']
    content: str
```

## 5. Data contracts

All Pydantic models, `extra='forbid'`, validated at every boundary (bundle load, check output,
storage round-trip, export).

```python
Severity = Literal['info', 'low', 'medium', 'high', 'critical']

class Evidence(BaseModel):
    id: str                  # "ev_" + sha256(canonical_json)[:16]  (§12)
    kind: EvidenceKind
    source: str              # bundle-relative file it came from
    http: HttpExchange | None
    config: ConfigExcerpt | None

class ReviewBundle(BaseModel):
    schema_version: int
    target: TargetInfo       # name, base_url?, notes?
    evidence: list[Evidence] # stable order: manifest file order, then record order

class Finding(BaseModel):
    id: str                  # "fn_" + sha256(check_id + '\0' + sorted evidence_ids)[:16]  (§12)
    check_id: str
    check_version: str
    severity: Severity
    title: str
    description: str
    evidence_ids: list[str]  # >= 1, each must exist in the run's evidence
    remediation: str

class ReviewSummary(BaseModel):
    narrative: str           # structured remediation summary
    finding_ids: list[str]   # references validated against the saved run (§11)
```

Contract rules:

- A `Finding` is produced by a check as a **draft**; the engine validates drafts (known check ID,
  valid severity, evidence IDs resolve to the run's registered evidence, `evidence_ids` non-empty)
  and only then assigns final IDs and persists. A check can never write storage directly.
- `ReviewSummary.finding_ids` is the set of findings the narrative covers; it must be a subset of
  the saved run's finding IDs. Duplicates are rejected; an empty list with a non-empty run is
  rejected.
- Models round-trip: storage writes serialized models and re-validates on read, so a schema drift
  between engine versions is a load error, never silent data loss.

## 6. Engine and run lifecycle

`run_review` pipeline:

```text
load bundle ─▶ validate (§4) ─▶ register evidence ─▶ execute checks in selection order
     │                                                        │
  invalid                 findings committed in one transaction ─▶ checks_complete
  (exit 1)                                                   │
                                  ┌──────────────────────────┼────────────────────────┐
                             --no-summary              summarize (§11)        failure / timeout /
                                  │                        │                    Ctrl-C
                                  ▼                        ▼                        ▼
                                done                   complete          stays checks_complete
                                                                        (retry: summarize <run-id>)
```

Run states (stored, monotonic):

| State | Meaning | Findings readable? |
|---|---|---|
| `created` | run row opened, bundle path recorded | no |
| `invalid` | bundle failed validation; diagnostic stored | no |
| `checks_complete` | all selected checks finished; findings committed | **yes** |
| `checks_failed` | a check raised; error stored; nothing half-persisted | no |
| `complete` | summary generated and reference-validated | yes |

Failure policy:

- Validation failure aborts **before any model call** (exit 1, diagnostic to stderr, run row kept
  in `invalid` for audit).
- A raising check aborts the whole run (`checks_failed`, exit 1). Half-finished runs never publish
  findings: the findings transaction commits only after every selected check returned.
- Summarization failure, timeout (default 60 s, `--summary-timeout`), or Ctrl-C leaves the run in
  `checks_complete` with the error recorded; `artex-web summarize <run-id>` retries.
- Without a `--model`, the summarize step is skipped (the run row keeps `model = NULL` and no
  `summaries` row is written): the run ends `checks_complete`, ready for a later `summarize`.
  `--no-summary` is the explicit form of the same outcome.
- A second run on the same bundle creates a new run row; runs are immutable once `checks_complete`.

Exit codes (strix convention): `0` review completed, no findings; `2` review completed, findings
present (also with `--no-summary`); `1` fatal (invalid bundle, unknown check ID, storage error,
check crash); `130` interrupted.

## 7. Storage and export

Single SQLite file, stdlib `sqlite3`, WAL mode. Default path: `$XDG_DATA_HOME/artex-web/artex-web.db`
(fallback `~/.local/share/artex-web/`), overridable with `--db PATH` / `ARTEX_WEB_DB`. One
operator, one review at a time: the store takes a process-local connection and serializes writes;
no cross-process concurrency in v1.

```sql
CREATE TABLE runs (
  id TEXT PRIMARY KEY,            -- "run_" + uuid4, created at open
  created_at TEXT NOT NULL,
  state TEXT NOT NULL,
  bundle_path TEXT NOT NULL,
  bundle_sha256 TEXT NOT NULL,    -- fingerprint: sha256 over sorted (file, sha256(file))
  engine_version TEXT NOT NULL,
  selected_checks TEXT NOT NULL,  -- JSON array, execution order
  model TEXT,                    -- model id used for summary, null if none
  error TEXT
);
CREATE TABLE evidence (
  run_id TEXT NOT NULL REFERENCES runs,
  evidence_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  content TEXT NOT NULL,          -- serialized Evidence model
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
  PRIMARY KEY (run_id, finding_id)
);
CREATE TABLE summaries (
  run_id TEXT PRIMARY KEY REFERENCES runs,
  content TEXT NOT NULL,          -- serialized ReviewSummary
  model TEXT NOT NULL,
  generated_at TEXT NOT NULL
);
```

Schema versioning: `PRAGMA user_version`; a store with an unknown version is refused with a clear
error, never migrated destructively (§17 for migration policy).

Export (`artex-web show <run-id> --format json [--out FILE]`) emits the run, its evidence, its
findings, and its summary (or `null`), with sorted keys and stable field order. Export **excludes**
`created_at`, run IDs, and summary timestamps, so the repeatability experiment can compare exports
byte-for-byte (§13). Findings are ordered by (severity rank desc, check_id, finding_id); evidence
by registration order.

## 8. CLI surface

| Command | Purpose | Key flags |
|---|---|---|
| `artex-web review <bundle>` | validate, run checks, persist, summarize | `--checks a,b` (ordered) / `--all`, `--db`, `--no-summary`, `--model`, `--summary-timeout`, `--out report.json` |
| `artex-web runs` | list runs (id, state, created, findings count) | `--db`, `--json` |
| `artex-web show <run-id>` | export a run | `--format json\|text`, `--out`, `--db` |
| `artex-web summarize <run-id>` | (re)generate the summary for a `checks_complete` run | `--model`, `--timeout`, `--db` |
| `artex-web checks` | list registered checks and their skills | `--db` unused; `--json` |
| `artex-web chat <run-id>` | interactive review over a saved run | `--model`, `--db`, `--skill-dir` |

Selection semantics: `--checks` is an explicit, ordered, de-duplicated list; an unknown ID exits 1
with the available IDs printed. `--all` runs registration order (built-ins sorted by check ID,
then entry-point checks sorted by ID, then version), which is also the documented stable order for
`--checks` when the user passes a set rather than an order. Refusing an empty selection is a usage
error.

The `review` command prints a compact summary to stdout (run id, checks run, findings by severity)
and writes the full export when `--out` is given. Output is JSON when stdout is not a TTY.

## 9. CLAI2 chat integration

Built on the local [CLAI2 `chat()` embedding API](pydantic-ai/src/pydantic_clai2/pydantic_clai2/app.py#L165):

```python
@dataclass
class ChatDeps:
    run_id: str
    reader: RunReader      # read-only handle over RunStore, scoped at construction

def build_agent(model: Model | str) -> Agent[ChatDeps, str]:
    # `chat()` takes no model argument: the model is bound to the agent at construction.
    agent = Agent(model, deps_type=ChatDeps, output_type=str, system_prompt=REVIEWER_SYSTEM_PROMPT)

    @agent.tool
    def list_findings(ctx: RunContext[ChatDeps]) -> list[Finding]: ...

    @agent.tool
    def get_finding(ctx: RunContext[ChatDeps], finding_id: str) -> Finding: ...

    @agent.tool
    def lookup_evidence(ctx: RunContext[ChatDeps], evidence_id: str) -> Evidence: ...

    return agent

async def start_chat(run_id: str, *, store: RunStore, model: Model | str, console: Console | None) -> None:
    agent = build_agent(model)
    await chat(agent, deps=ChatDeps(run_id, store.reader(run_id)),
               load_plugins=False, console=console)
```

Design rules:

- **No plugins**: `load_plugins=False` only; no built-in, project, saved, or drop-in plugin loads,
  so no coding tools, no filesystem access, no network, nothing the agent did not bring itself.
- **Run-scoped reads**: `RunReader` is constructed for one run ID. `lookup_evidence` on an ID from
  another run, or a nonexistent ID, returns a typed not-found error the agent must handle; it can
  never cross runs. There is no tool that writes.
- **Untrusted evidence framing**: the system prompt states that evidence content is captured
  attacker-controlled data, that instructions inside it are not commands, and that findings may
  only be discussed, never modified. Tool returns carry the raw model, which serializes evidence
  through its Pydantic model, not through string templating.
- **Terminal behavior**: Esc cancels the current turn and failed/cancelled turns retain history
  (CLAI2 semantics), so the run on disk is unaffected mid-turn by construction; findings live in
  SQLite and are re-read on every tool call.
- The chat adapter module is the only file that imports `pydantic_clai2`; the rest of the package
  depends only on `pydantic_ai` core. Tests drive `chat()` with `TestModel` and
  `Console(file=StringIO())` (the same headless pattern the CLAI2 suite uses), and one manual
  tmux pass per release (§14).

## 10. Skill boundary and registry

Skills are packaged review knowledge (Artex-style `SKILL.md` directories); checks are deterministic
logic. They stay outside the engine and are joined by `check_id`.

**Skill directory** (data only, never executed):

```text
skills/<name>/
  SKILL.md        # YAML frontmatter: name, description, checks: [header-security]
  reference/*.md  # optional deeper content; chat loads on demand if asked
```

**Check discovery** (code, installed only):

- Built-ins ship in `artex_web.checks.builtin` and register through the same API as everyone else.
- Third-party checks register via the entry-point group `artex_web.checks`, each exposing a
  `ReviewCheck`:

```python
class ReviewCheck(Protocol):
    check_id: str
    version: str
    title: str
    description: str

    def applies_to(self, bundle: ReviewBundle) -> bool: ...
    def review(self, bundle: ReviewBundle) -> Sequence[FindingDraft]: ...
```

- The registry joins `SKILL.md` frontmatter `checks` entries to registered checks. A skill naming
  an unregistered check is a warning at `artex-web checks` time; a check with no skill is fine
  (logic without prose); a skill with no check is fine (prose for the chat reviewer).
- Extra skill roots load via `--skill-dir` (data); check code loads **only** via installed entry
  points. That is the trust boundary: arbitrary paths can add Markdown, never code.

**Fixtures**:

1. `header-review` skill + `header-security` check (built-in): on HTML responses, flag missing
   `Strict-Transport-Security`, missing `Content-Security-Policy`, missing
   `X-Content-Type-Options`, cookie `Secure`/`HttpOnly`/`SameSite` gaps, and
   `Access-Control-Allow-Origin: *` with credentials enabled. One evidence-linked finding per
   distinct response-exchange cluster.
2. `banner-leak` skill + check (fixture only, used by experiment 2): flag `Server` /
   `X-Powered-By` version disclosure. Distinct logic, same contract.

The single header-review fixture exercises the whole contract (bundle -> evidence -> check ->
finding -> storage -> export -> summary -> chat) before any broader skill set is integrated.

## 11. Summarization

The only model stage in the `review` path:

```python
async def summarize_run(run_id: str, store: RunStore, model: Model) -> ReviewSummary
```

- A Pydantic AI agent with `output_type=ReviewSummary` and the run's findings (id, severity,
  title, description, remediation) rendered into the prompt. **Raw evidence stays out of the
  summarizer prompt** in v1: the narrative summarizes findings, and findings already carry the
  remediation text.
- Reference validation is two-layered: an output validator raises `ModelRetry` listing the valid
  finding IDs when the model hallucinates one (bounded retries, default 2); after a final
  failure, the engine records `summary_error` and leaves the run `checks_complete`.
- Engine-side validation repeats the check against the saved run before persisting; the stored
  summary is authoritative only after passing.
- Timeout via `anyio.fail_after` (default 60 s) and Ctrl-C behave like validation failure:
  findings stay readable, `summarize` retries, and a previously stored summary is only replaced by
  a new validated one.
- The summarizer module is the only consumer of `--model` in `review`; `TestModel` and
  `FunctionModel` from the local checkout drive it in tests (§13, experiment 4).

## 12. Determinism guarantees

- **IDs**: evidence ID = `ev_` + sha256 of the canonical JSON encoding (sorted keys, UTF-8,
  no whitespace) of the validated record; finding ID = `fn_` + sha256 of
  `check_id + '\0' + '\0'.join(sorted(evidence_ids))`. Identical content in two runs yields
  identical IDs and references.
- **Order**: checks execute in the requested order; findings persist sorted by (severity rank,
  check_id, finding_id); exports are canonical JSON. No wall-clock, random, or hash-order values
  appear in exports.
- **No model in the findings path**: given the same bundle and selection, the findings section of
  the export is byte-identical across runs, machines, and engine restarts. Engine and check
  versions are stored on the run so a changed finding can be attributed.
- Bundle fingerprint (`bundle_sha256`) lets a caller verify that two runs really reviewed the same
  bytes.

## 13. Validation experiments

Each experiment is a scripted, credential-free test or command run; all fixtures live in
`artex-web/fixtures/`. The experiments gate the milestones (§15).

### 13.1 Greenfield dependency check

**Procedure.** In a fresh venv: install `artex-web` with `[tool.uv.sources]` pointing at the local
checkout members (M0 settles the exact member list); `uv sync` the checkout so the local packages
are importable; run `artex-web review fixtures/bundles/valid --checks header-security --no-summary`
from a directory outside any checkout; assert that `pip list` shows no `artex`/`strix` distribution
and that no module of the Artex forks, `strix`, or `communitytools` appears in `sys.modules`
after the run — only `artex_web`, the local pydantic packages, and stdlib.

**Pass.** The review completes against the fixture bundle; imports resolve only to
`artex_web`, the local pydantic packages, and stdlib; no PyPI `pydantic-*` copy is installed.

### 13.2 Skill separation

**Procedure.** Register fixture #2 in one of the two supported ways, then run the same review:
(a) *entry-point case* — package `banner-leak` (skill directory + check) as a tiny separate
distribution exposing the `artex_web.checks` entry point, install it into the venv, and run
`artex-web review fixtures/bundles/valid --checks banner-leak --skill-dir fixtures/skills/banner-leak`
from the CLI; or (b) *API case* — from test code, register the same check through the public
registry API and call `run_review` in process. Then run `artex-web checks` and confirm the join.

**Pass.** The second check runs and its findings persist and export, with **no edits** to
`engine.py`, `storage.py`, `models.py`, or `chat_adapter.py` (verified by diffing those files
against the M1 tree).

### 13.3 Engine repeatability

**Procedure.**
(a) Run the fixture review twice into two fresh temporary stores; export both; compare
byte-for-byte.
(b) For each malformed fixture (missing manifest, wrong `schema_version`, truncated JSON, missing
evidence file, oversized body, unredacted `Authorization`), run `review` with a model factory that
raises if ever called.

**Pass.** (a) The two exports are identical, including finding IDs and evidence references.
(b) Every malformed bundle exits 1 with a diagnostic naming the file and rule, and the model
factory is never invoked.

### 13.4 Model and terminal integration

**Procedure.** All with the local checkout's test models; real model calls are blocked globally by
a `conftest.py` fixture.
- *References.* `FunctionModel` scripted to emit a summary referencing an unknown finding ID:
  `ModelRetry` fires, the second attempt validates, and the persisted summary's `finding_ids`
  resolve against the saved run. A scripted always-invalid summary leaves the run
  `checks_complete` with `summary_error` set.
- *Retrieval.* An agent run (`TestModel`, which calls every tool) over a saved run:
  `lookup_evidence` with a valid ID returns the record; an ID from a different run returns
  not-found; `list_findings` matches the store.
- *Cancellation.* Drive `chat()` with `TestModel` and `Console(file=StringIO())`; cancel a turn
  with a real `anyio` cancel scope ordered by `Event`s (no sleeps); after cancellation, re-open
  the store and assert findings are readable, and assert the failed turn retained its history.
- *Summary timeout.* `FunctionModel` whose function outlives `--summary-timeout` (tiny value):
  run ends `checks_complete`, findings readable, `summarize <run-id>` with a fast model succeeds
  afterward.

**Pass.** Every case above holds; no case leaves findings unreadable or a run row in a state the
state machine does not define.

## 14. Test strategy

- **Stack**: pytest + pytest-anyio (auto mode), inline-snapshot for exports and storage rows,
  ruff + pyright strict in CI, 100% branch coverage target with audited pragmas.
- **Model blocking**: a session fixture that fails any model that is not `TestModel` or
  `FunctionModel`, so a credential-free suite is enforced by the harness, not by convention
  (mirroring the checkout's global block).
- **Isolation**: every test gets a fresh temporary SQLite store and a fixture bundle path; no test
  touches `$XDG_DATA_HOME`.
- **Priority**: integration over unit where possible — full `run_review` calls with `TestModel`
  injection, real `sqlite3` files on tmp paths, real `anyio` cancel scopes.
- **Terminal**: automated `chat()` tests stay headless (`Console(file=StringIO())`); interactive
  behavior (Esc cancel, prompt, transcript) is verified manually in a fresh tmux window before
  each release, per the CLAI2 project's own testing rule, and is out of CI scope.

## 15. Milestones

Each milestone ends with its experiments run and documented in this file's results table (§13
gains a "result" column as experiments land).

| # | Milestone | Delivers | Gated by |
|---|---|---|---|
| M0 | Environment | package skeleton, uv project with local path sources, CI stub, model blocking fixture | 13.1 |
| M1 | Contracts and engine | `models.py`, `bundle.py`, `ids.py`, `storage.py`, `export.py`, `engine.py`, header-security check, valid + malformed bundle fixtures, `review`/`runs`/`show`/`checks` CLI | 13.3 |
| M2 | Registry and skill separation | `registry.py`, skills shipped as data, entry-point loading, `banner-leak` fixture distribution, `--skill-dir` | 13.2 |
| M3 | Summarization | `summarize.py`, `summarize` CLI, retry/validation/timeout policy, `--model` resolution | 13.4 (references, timeout) |
| M4 | Chat | `chat_adapter.py`, run-scoped tools, `chat` CLI, headless + cancellation tests, tmux checklist | 13.4 (retrieval, cancellation) |
| M5 | Hardening | coverage to target, README, docs for the bundle producer (sanitization), experiment results recorded in this file | all |

## 16. Risks

| Risk | Mitigation |
|---|---|
| CLAI2 `chat()` is a local checkout API that moves | The adapter is one module and one integration test; the checkout is path-pinned, and the seam (agent + deps + `load_plugins=False`) is exercised by 13.4 rather than assumed |
| Terminal tests are flaky in CI | Headless-only in CI (`Console(file=StringIO())`); interactive checks are manual tmux gates, not CI assertions |
| Determinism silently depends on the model | The model never touches findings; repeatability (13.3) runs with `--no-summary` |
| Bundle producers ship unsanitized captures anyway | V5 marker check + documented producer contract + caps (V4); refused loudly, never partially accepted |
| Entry-point checks add supply-chain surface | Checks load only from installed distributions, never from paths; skill dirs are data-only; no prebuilt artifacts are published, mirroring the failsafe posture |
| Prompt injection through captured evidence reaches chat or summary | Findings path has no model; summarizer sees findings, not raw evidence; chat frames evidence as untrusted data and has no write tools |
| SQLite becomes a multi-operator tool by accretion | v1 documents one operator, one review; store refuses an unknown `user_version` instead of migrating in place |

## 17. Open questions

1. **DB default**: user data dir (proposed) vs. a `.artex-web/` directory next to the bundle
   (better for offline handoff, worse for shared machines)?
2. **Exit code for findings**: keep strix's `2`, or follow the Go Artex forks' conventions if this
   package ever needs script compatibility with them?
3. **Migration policy**: additive `ALTER TABLE` with `user_version` bumps (Go forks' approach) vs.
   refuse-and-export/import for v1 only?
4. **HAR ingestion**: is a `artex-web import-har` producer command worth shipping, or does the
   custom sanitized format stay the only door, keeping sanitization an explicit producer step?
5. **Chat annotation**: should `chat` ever gain append-only operator notes (never findings
   mutation), and if so, does that need a fifth table and a read-only-plus-notes store handle?
6. **CLAI2 session reuse**: v1 starts a fresh session per `chat <run-id>`; should the run record
   store the CLAI2 `session_id` so a re-invocation resumes the same conversation?
7. **Usage limits**: wire `UsageLimits` (request/turn caps) into `chat` as a `--max-requests`
   flag, or leave spend control entirely to CLAI2's own settings?

## 18. Defaults

One local operator, one review at a time, offline artifacts, and a credential-free validation
suite. SQLite in the user data directory. `--no-summary` is the only model-free review mode and
the default mode for CI; summary and chat require an explicit `--model`. The shipped skill set is
the single header-review fixture until the experiments pass end to end; broader defensive skill
content is integrated only after M5, one skill at a time, each with its own fixture bundle.
