# Usage & Operator Guide

This guide covers installing `partex`, running offline reviews and authorized live probes, configuring model providers and native web search, scoping targets, governing budgets and state-changing writes, and managing local state. For project positioning, deliberate non-goals, and architecture, see [README.md](README.md); for internal specs, see [PLAN.md](PLAN.md) and [RUNTIME.md](RUNTIME.md).

## Installation & offline review

From the repository root, use Python 3.14 or newer and `uv`:

```sh
uv sync --frozen
uv run partex review fixtures/bundles/valid --all
```

This reviews the bundled offline HTTP traffic without a model or network connection, prints sample findings, and exits with code `3`.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Completed with no findings |
| `2` | CLI usage or argument error |
| `3` | Completed with findings |
| `1` | Validation, scope, storage, or operational failure |

### HAR import and bundle export

To review captured browser traffic offline without a MITM proxy, export a HAR from your browser and convert it into a passive bundle:

```sh
uv run partex import-har capture.har --out ./my-bundle --target https://example.com
uv run partex review ./my-bundle --all
```

To export a previously captured run from `partex.db` back into a passive-reviewable bundle (redacting `secret_fields` by default; pass `--include-secrets` to emit cleartext):

```sh
uv run partex export-bundle RUN_ID --out ./exported-bundle
```

## Active probes & local fixture target

Live checks send HTTP requests and require explicit authorization. To try one against the bundled deliberately vulnerable test app, start the fixture server from the repository root:

```sh
uv run python fixtures/target_app/app.py
```

In a second terminal, run the interactive launcher in model-free `--no-tui` mode against the local URL. The launcher prompts you to record an authorization attestation:

```sh
./partex.sh --no-tui http://127.0.0.1:8765/
```

The `version-disclosure` check probes for evidence such as:

| Request | Example evidence |
| --- | --- |
| `GET /robots.txt` | A response header reveals the software version, such as `Server: FixtureTarget/2.3.1`. |
| `GET /partex-nonexistent-probe-0` | A `404` response includes internal details, such as a stack trace. |

### Listing, inspecting, and resuming runs

- `./partex.sh list` (or `./partex.sh -l`) lists saved runs from the default database along with detected host sandboxes.
- `uv run partex show RUN_ID --format text` prints saved evidence, findings, coverage gaps, and `llm_usage`.
- `uv run partex reports RUN_ID` lists Markdown reports saved by the agent's `save_report` tool; `uv run partex reports RUN_ID NAME` prints one report (both accept `--db PATH` and `--json`).
- `./partex.sh --read-only [RUN_ID]` opens a read-only CLAI2 chat session over a saved run with no network traffic (defaults to the most recent usable run if `RUN_ID` is omitted).
- `./partex.sh --resume [RUN_ID]` continues testing: opens a new live session on the earlier run's recorded target, scope, and authorization (leaving the earlier run unchanged); `-n`, `-R`, `-k`, `-M`/`-w`/`-W`, and model flags apply as usual.

## Multi-model configuration: analyst, search, and decision models

`partex review` and `partex test` are model-free by default. `partex chat`, `partex agent`, and the interactive `./partex.sh` launcher split LLM configuration into up to three independent roles:

- **Analyst / reviewer model (`--model` / `-m`, plus optional `--gateway-route` / `-r`):** Drives investigation, tool calls, Monty `run_code` evidence correlation, and read-only chat. Accepts any Pydantic AI `provider:model` string or Pydantic AI Gateway route. Because runs live in `partex.db`, you can probe live with one model, review the saved run read-only with another (`--read-only`), or continue live testing with a different model (`--resume`).
- **Web search model (`--search-model` / `-S`):** Optional and off by default. Backs only the `web_search` tool in an isolated zero-tool agent using provider-native search, so you can give an open-weights or Gateway-routed analyst access to live public reference lookups — or omit it for zero search egress.
- **Decision model (`--decision-model` / `-D` / `PARTEX_DECISION_MODEL`):** Optional and off by default. Backs closed-set single-pass judgements (`google-decisions:gemini-decision-1` or `openai-decisions:gpt-6-luna` returning calibrated probabilities with zero output tokens, or degraded uncalibrated `anthropic:claude-haiku-5-5` via `NativeOutput` with `calibrated=False`, `top_p=None`). Turning `-D` on enables no feature by itself (individual features have their own switches).

### Mixing analyst and search models

You can combine providers freely per session or across stages of a run:

```sh
# Open-weights / Gateway analyst + fast direct Gemini web search
./partex.sh -m zai-org/GLM-5.3 -r doubleword -S google:gemini-3.8-flash http://127.0.0.1:8765/

# OpenRouter analyst + Anthropic Haiku web search
./partex.sh -m openrouter:deepseek/deepseek-v4.1-flash-1017 -S anthropic:claude-haiku-4-5 http://127.0.0.1:8765/

# Direct Gemini for both roles (or omit -S to leave web search off)
./partex.sh -m google:gemini-3.8-flash -S google:gemini-3.8-flash http://127.0.0.1:8765/

# Switch analyst models later when reviewing a saved run in read-only chat
./partex.sh -m anthropic:claude-sonnet-5-5 --read-only

# Or continue live testing a saved run with another model and overridden limits
./partex.sh -m anthropic:claude-sonnet-5-5 --resume RUN_ID -k -n 0
```

### OpenRouter

Set `OPENROUTER_API_KEY` and pass an `openrouter:` model string:

```sh
./partex.sh -m openrouter:deepseek/deepseek-v4.1-flash-1017 --read-only
```

### Pydantic AI Gateway (Doubleword)

To use a model served via Pydantic AI Gateway (such as `zai-org/GLM-5.3` on the `doubleword` route), set `PYDANTIC_AI_GATEWAY_API_KEY`. If the Gateway region cannot be inferred or you need a specific endpoint, set `PYDANTIC_AI_GATEWAY_BASE_URL` to the URL from your Gateway Connect page (a trailing `/doubleword` is handled automatically):

```sh
./partex.sh -m zai-org/GLM-5.3 -r doubleword --read-only
```

### Direct Google Gemini & safety settings

Set `GEMINI_API_KEY` (or `GOOGLE_API_KEY`) and use the `google:` prefix for the main model (`-m`) and/or native `web_search` (`-S`). No Gateway key is needed for direct `google:` strings; omit `-S` to keep web search off (or pass `--read-only` without `-S` for chat only):

```sh
./partex.sh -m google:gemini-3.8-flash -S google:gemini-3.8-flash http://127.0.0.1:8765/
```

Because authorized security testing discusses exploit and payload evidence that Gemini's `"dangerous content"` filter can flag (`finishReason: SAFETY`), `partex` **disables configurable content filters by default** for `google:` and `google-cloud:` model roles. Startup prints the effective thresholds, while Google's non-configurable CSAM and PII filters remain on. Set `PARTEX_GOOGLE_SAFETY_SETTINGS` to a preset (`off`, `high`) or a JSON `[{"category": "HARM_CATEGORY_…", "threshold": "BLOCK_…"}]` list to override it (setting this variable with a non-Google model refuses to start):

```sh
PARTEX_GOOGLE_SAFETY_SETTINGS=off ./partex.sh -m google:gemini-3.8-flash http://127.0.0.1:8765/
```

### Optional web search (`--search-model` / `-S`)

Web search is off unless `--search-model` (or `-S` in `partex.sh`, or `PARTEX_SEARCH_MODEL`) is set. When enabled, `web_search` runs in a separate one-shot `Agent` with `WebSearch(local=None)` and zero host tools, DB handles, target-client access, or filesystem mounts:

- **Supported providers (never Gateway):**
  - `anthropic:<model>` (`ANTHROPIC_API_KEY`) — pins `allowed_callers=['direct']` (disables server-side code execution so citations stay intact and Zero Data Retention applies) and caps server-side tool invocations at `max_uses=3` per query.
  - `google:<model>` (`GOOGLE_API_KEY` or `GEMINI_API_KEY`).
  - `google-cloud:<model>` (Application Default Credentials and `GOOGLE_CLOUD_PROJECT`; defaults to `global` location, overridable via `GOOGLE_CLOUD_LOCATION`).
  - `openai:<model>` (`OPENAI_API_KEY`, Responses API) — sets `openai_include_web_search_sources=True` so citations are returned (`openai-chat:` is rejected at startup); has no per-query search limit and costs more per query than the others, so prefer a small model.
- **Startup validation:** Fails fast at startup on bare model names, `gateway/...` prefixes, `openai-chat:`, or missing credentials/Vertex ADC (without echoing credential or token contents).
- **Outbound query & budget guardrails:** Search queries leave this machine directly to the provider and never pass through Pydantic AI Gateway. Before a query is sent, `validate_search_query` enforces a 200-character limit and blocks URLs, internal `ev_`/`fn_` IDs, and known engagement secrets. Sessions are capped at 20 `web_search` calls and 20 sources per query (recording `sources_total` if trimmed); results return framed as untrusted data and persist in `web_research`.

### Optional decision model (`--decision-model` / `-D`)

Closed-set decision scoring is off unless `--decision-model` (or `-D` in `partex.sh`, or `PARTEX_DECISION_MODEL`) is set. Each call runs in an isolated zero-tool `DecisionRunner` with per-call timeout and session call caps:

- **Supported providers (never Gateway):**
  - `google-decisions:<model>` (e.g. `google-decisions:gemini-decision-1`, requires `GOOGLE_API_KEY` or `GEMINI_API_KEY`).
  - `openai-decisions:<model>` (e.g. `openai-decisions:gpt-6-luna`, requires `OPENAI_API_KEY`).
  - `anthropic:<model>` (e.g. `anthropic:claude-haiku-5-5`, requires `ANTHROPIC_API_KEY`) — degraded uncalibrated option using `NativeOutput` (`calibrated=False`, `top_p=None`; never fakes `p=1.0`, and callers must explicitly opt into uncalibrated responses with `allow_uncalibrated=True`).
- **Excluded paths:** `gateway/...` and bare names are rejected because Pydantic AI Gateway proxies generative endpoints rather than dedicated `/decisions` endpoints. `google-cloud-decisions:` (Vertex ADC is not supported by Gemini Decisions) and `PARTEX_GOOGLE_SAFETY_SETTINGS` (no `safetySettings` field on Decisions) are rejected at startup.
- **Egress & privacy:** Decision calls send bounded, secret-redacted evidence excerpts framed in `<partex_untrusted_data>` directly to the configured provider — the same data class the analyst (`-m`) already sees, sent to one additional provider. Local spans record metadata only by default (`--logfire-content` is required to include prompt/answer content).
- **Security eval harness (opt-in, never in CI):** Benchmark a provider on the bundled security + adversarial spoofing fixture (`fixtures/decisions/cases.json`) with:

```sh
uv run python scripts/eval_decisions.py -D google-decisions:gemini-decision-1 --ab-unsure --check-order-invariance
```

## Target scoping: URL lists & `nmap` imports

Every live run enforces scope in code inside `ScopedHttpClient` (`src/partex/target.py`) rather than via prompts.

### Exact URL allowlists (`-u` / `--urls-file`)

Restrict a session to exact URLs listed in a file (one per line, `#` comments, trailing `/*` for a path prefix):

```sh
./partex.sh -u urls.txt http://127.0.0.1:8765/
```

- `<target-url>` is optional with `-u`: the first URL in the file becomes the baseline target (an explicit `<target-url>` must be listed in the file).
- A URL without an explicit port covers both `80` and `443`; add `:port` to pin one.
- Anything unlisted is refused by the scope gate before touching the wire.
- Add `--recursive` (`PARTEX_RECURSIVE=1`) to treat every listed URL as a path prefix (so `http://foo/` allows everything under `foo`).

### Importing `nmap -oX` scans (`-N` / `partex nmap`)

Import authorized HTTP(S) targets directly from `nmap -oX` XML scan output:

```sh
./partex.sh -N scan.xml
```

- Each open HTTP(S) port on an up host becomes a `scheme://host:port/*` entry in the session's URL allowlist; ports running other services (SSH, databases, TLS-wrapped non-HTTP) are reported and skipped, never guessed.
- The session opens with one initial `GET` per imported target, captured as evidence and shown live on a terminal; `partex.sh` automatically raises `--max-requests` when the import needs room.
- `<target-url>` is optional with `-N`, and `-N` can be combined with `-u` (or passed via `PARTEX_NMAP_FILE`).

To inspect or edit the converted target list before starting a session, run the standalone converter:

```sh
uv run partex nmap scan.xml [--use-hostnames] [--out targets.txt]
```

`partex nmap` accepts multiple scan files (for example, a discovery sweep plus a `-sV` pass), writes `# source:` lines recording each scan file and its SHA-256 hash, and defaults to scanned IPs (pass `--use-hostnames` to use scan PTR hostnames instead).

## Budgets, write policy, turn limits, thinking & telemetry

| Setting | `partex.sh` flag / env | Direct CLI flag | Behavior |
| --- | --- | --- | --- |
| Request budget | `-n N` / `PARTEX_MAX_REQUESTS` (default `50`) | `scope.max_requests` in `engagement.json` | Hard ceiling (`100000` max); `0` means unlimited requests (still paced by `max_rps`; booleans like `false` are rejected) |
| Rate limit | `-R N` / `PARTEX_MAX_RPS` (default `2`) | `scope.max_rps` in `engagement.json` | Requests per second ceiling (`64` max) |
| Write methods | `-M read\|write\|delete`, `-w METHOD`, `-W N` | `--allow-method METHOD`, `--max-writes N` (`test` / `agent`) | `read` = `GET`/`HEAD`/`OPTIONS` only (default); `write` adds `POST`/`PUT`/`PATCH`; `delete` adds `DELETE`. Every write waits for terminal approval; `--no-tui` / headless sessions deny all writes |
| Model turn limit | `-L N` / `PARTEX_REQUEST_LIMIT` (default `40`) | `--request-limit N` (`agent` / `chat`, default `200`) | Caps model turns per prompt before pausing for the operator |
| Reasoning effort | `-T LEVEL` / `PARTEX_THINKING` | `--thinking minimal\|low\|medium\|high\|xhigh\|max` (`agent`) | Controls tester model reasoning effort; lower values reduce latency and spend |
| TLS verification | `-k` / `PARTEX_INSECURE=1` | `--insecure` (`test` / `agent`) | Accepts invalid target certs; recorded on run/evidence and announced on `/scope add` confirmations |
| Local trace log | `--log-file PATH\|off` / `PARTEX_LOG_FILE` | `--log-file PATH\|off` | Written as mode-`0600` JSONL under `logs/` by default for `review`/`test`/`verify`/`chat`/`agent` |
| Remote Logfire | `--logfire` / `PARTEX_LOGFIRE=1` | `--logfire` | Opt-in remote span export (requires `LOGFIRE_TOKEN`); off by default |
| Unscrubbed spans | `--logfire-content` / `PARTEX_LOGFIRE_CONTENT=1` | `--logfire-content` | Keeps model and tool content out of Logfire's default scrubber (use on non-sensitive targets only) |

## Interactive operator commands & agent tools

### Operator-only slash commands (CLAI2 plugins)

Slash commands are intercepted by the CLAI2 terminal host and never exposed to the model:

| Command | Availability | What it does |
| --- | --- | --- |
| `/targets [host \| --all \| --findings]` | `agent`, `chat`, standalone CLAI2 | Deterministic, secret-redacted rollup of discovered targets, paths, banners, findings, and coverage gaps across the current run or saved runs. Usable standalone in CLAI2 via `partex.agent_adapter.targets_plugin:TargetsPlugin`. |
| `/scope` | `agent` | Shows the current scope and engagement limits. |
| `/scope add <host[:port]\|url>` | `agent` | Stages a scope extension (and announces `-k` insecure TLS status if active); takes effect only after `/scope confirm`. |
| `/scope nmap <scan.xml>` | `agent` | Stages an `nmap -oX` import batch; `/scope confirm` applies it atomically and records the scan path and SHA-256 hash. |
| `/report [path]` | `agent` | Writes a secret-redacted Markdown report of the active run to disk. |
| `/secrets [path]` | `agent` | Writes captured secret values to a mode-`0600` file on disk without echoing them to chat. |

### Agent tools

| Tools | What they do |
| --- | --- |
| `list_runs`, `list_findings`, `get_finding`, `list_evidence`, `lookup_evidence`, `list_coverage` | Inspect saved runs, findings, redacted evidence, and check coverage. Inside `partex agent`, these run inside the Monty `run_code` sandbox. |
| `http_request`, `http_request_batch`, `download_asset`, `discover_js_assets`, `run_check` | Send scoped requests (individually or as a concurrent batch with per-item audit), download in-scope assets, discover JS bundles, and execute installed checks. Non-safe methods require `scope.allowed_methods`, `scope.max_write_requests`, and interactive terminal approval. |
| `run_code`, `save_report` | Analyze evidence and read-only `/artifacts` downloads inside the Monty sandbox, or persist a Markdown report from the live session. |
| `list_research`, `lookup_research` | Inspect web research saved by `web_search` for the current run or a chosen run. |
| `list_reports`, `read_report` | Retrieve Markdown reports saved by `save_report` for the current run or the live session's `--from` run. |
| `load_capability` | Load a skill playbook from the deferred capability catalog on demand. |
| `web_search` | Optional (`--search-model` / `-S`). Queries public references via an isolated zero-tool `anthropic:`, `google:`, `google-cloud:`, or `openai:` agent. |

## CLI subcommands

Run `uv run partex --help` or `uv run partex <command> --help` for full options:

| Command | Mode | Purpose |
| --- | --- | --- |
| `partex review <bundle>` | Offline, model-free | Run deterministic passive checks (`--checks` or `--all`) over an offline bundle |
| `partex test <engagement>` | Live, model-free | Run baseline/active/passive checks against an authorized target (`--authorized` required) |
| `partex verify <run-id> <finding-id>` | Live, model-free | Replay a finding's verification recipe to test reproducibility (`--authorized` required) |
| `partex agent <engagement>` | Live, interactive TUI | Open a scoped CLAI2 live testing session (`--authorized` and `--model` required) |
| `partex chat <run-id>` | Offline, interactive TUI | Open a read-only CLAI2 reviewer over a saved run (`--model` required) |
| `partex runs` | Offline | List runs stored in the database (`--json` supported) |
| `partex show <run-id>` | Offline | Export or display a saved run (`--format text\|json`, `--include-secrets`, `--out`) |
| `partex report` | Offline | Cross-run rollup of findings, model spend, and tool calls |
| `partex reports <run-id> [name]` | Offline | List or print saved Markdown reports |
| `partex import-har <file.har>` | Offline | Convert an operator-exported HAR into a scope-filtered passive bundle |
| `partex export-bundle <run-id>` | Offline | Export a run's captured evidence as a passive-reviewable bundle |
| `partex nmap <scan.xml...>` | Offline | Convert `nmap -oX` scan files into authorized URL-list entries with skip report |
| `partex checks` | Offline | List installed `partex.checks` entry points and joined skills (`--skill-dir`) |
| `partex sandboxes` | Offline | Detect available host sandboxes (`monty`, `docker`, `podman`, `bubblewrap`) |

## Local state & cleanup

Set `PARTEX_STATE_DIR` to choose where `partex` stores all persistent local state (relative paths resolve from your current working directory):

```sh
export PARTEX_STATE_DIR="$HOME/partex-state"
```

When unset, `partex` uses `$XDG_STATE_HOME/partex` (or `~/.local/state/partex` if `XDG_STATE_HOME` is unset, empty, or relative):

| Path within the state directory | Contents |
| --- | --- |
| `partex.db` | Saved engagement runs, evidence, findings, verifications, tool calls, coverage, research, and usage totals (SQLite WAL, schema v5) |
| `partex.db.artifacts/` | Downloaded per-run artifacts (mode `0600`) |
| `partex.db.reports/` | Saved Markdown reports by run |
| `partex.db.exports/` | Operator exports from `/report` and `/secrets` |
| `logs/` | Local JSONL diagnostic trace logs (mode `0600`) |
| `partex.db.clai2/` | Read-only chat history and terminal settings for this database |

Use `--db PATH` or `PARTEX_DB` to target a different database (its sibling `.artifacts/`, `.reports/`, `.exports/`, and `.clai2/` directories sit alongside it; live `agent` sessions use temporary terminal storage). Use `--log-file PATH` or `PARTEX_LOG_FILE` to override the trace log path.

### Pre-1.0 schema rule & cleaning old state

Before 1.0, `partex` does not run database schema migrations: if an older database's `user_version` does not match the current schema (v5), export any needed data first (`partex export-bundle` or `partex show --format json`), then remove stale databases and trace logs interactively with:

```sh
scripts/clean-state.sh [--older-than DAYS] [--db-only] [--logs-only] [--dry-run]
```

Every deletion requires typing `y` at a terminal (there is no `--yes` flag). To inspect legacy databases from earlier versions, pass `--db` explicitly (for example `./partex-probe.db` or `${XDG_DATA_HOME:-$HOME/.local/share}/partex/partex.db`).
