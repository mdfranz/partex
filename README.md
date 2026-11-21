# partex

`partex` checks web and API traffic for security issues and links findings to the evidence behind them. Review saved traffic offline or run checks against systems you have permission to test.

The project grew out of a review of ARTEX and other open-source security testing projects. Their workflows inspired how `partex` organizes assessments, keeps evidence with findings, and packages testing guidance. The engine is a standalone Python implementation. [Project background](docs/lineage/SOURCES.md)

## Quick start

From the repository root, use Python 3.14 or newer and `uv`:

```sh
uv sync --frozen
uv run partex review fixtures/bundles/valid --all
```

This example reviews bundled HTTP traffic offline. It prints sample findings and exits with code `3` when it finds issues.

## What you can do

- **Review captured traffic.** Import a browser's HTTP archive (HAR) and check saved responses for issues such as missing security headers or insecure cookie settings. Offline checks run without a model.
- **Run authorized live checks.** Capture responses within a defined target scope and request budget, then save the evidence alongside the findings.
- **Work with saved results.** List past runs, export reports or captured traffic, and use read-only chat to review findings and their evidence.

## Skills, checks, and plugins

Skills are Markdown guides that the interactive session can consult. The bundled guides cover headers and cookies, version disclosure, JavaScript review, API inventory, authorization, and session controls.

The built-in executable checks are `header-security`, `js-analysis`, and `version-disclosure`. Additional checks can register through the Python `partex.checks` entry point. Run `uv run partex checks` to see installed checks and their linked skills. [Skill guides](docs/skills/README.md)

| Tools | What they do |
| --- | --- |
| `list_runs`, `list_findings`, `get_finding`, `list_evidence`, `lookup_evidence`, `list_coverage` | Inspect saved runs, findings, evidence, and check coverage. |
| `http_request`, `download_asset`, `discover_js_assets`, `run_check` | Make scoped requests, save assets, find JavaScript files, and run installed checks during a live session. |
| `run_code`, `save_report` | Analyze evidence and downloaded artifacts in the Monty sandbox, or save a report from the live session. |
| `list_reports`, `read_report` | Retrieve Markdown saved by `save_report` for the current run or the live session’s `--from` run. |
| `web_search` | Optional. Look up public references through a separate `anthropic:`, `google:`, `google-cloud:`, or `openai:` model's native web search (`--search-model`, or `-S` in `partex.sh`). Queries leave this machine. |

`--search-model` takes `anthropic:<model>` (`ANTHROPIC_API_KEY`), `google:<model>` (`GOOGLE_API_KEY` or `GEMINI_API_KEY`), `google-cloud:<model>` (Application Default Credentials and `GOOGLE_CLOUD_PROJECT`), or `openai:<model>` (`OPENAI_API_KEY`, Responses API). OpenAI search has no per-query search limit and costs more per query than the others, so prefer a small model. `google-cloud:` uses the `global` location by default, since newer Gemini models are only served there; set `GOOGLE_CLOUD_LOCATION` to override it.

The live terminal includes a built-in CLAI2 plugin for operator commands. `/scope` shows the current scope and requires operator confirmation for changes. `/report` writes a redacted Markdown report, and `/secrets` writes secret values to a private file.

Use `partex reports RUN_ID` to list reports saved by `save_report` and `partex reports RUN_ID NAME` to print one as Markdown. Both forms accept `--db PATH` and `--json`.

## Pydantic libraries

[Pydantic](https://github.com/pydantic/pydantic) validates inputs such as assessment settings and captured traffic. [Pydantic AI](https://pydantic.dev/docs/ai/overview/) connects models to the tools they can use, and its [CLAI2](https://pypi.org/project/pydantic-clai2/) package provides the interactive terminal. [Monty](https://pydantic.dev/docs/monty/get-started/) runs model-generated Python in a sandbox when the interactive session needs to work with saved evidence. [Runtime](RUNTIME.md) · [Dependencies](DEPS.md)

## Active probe examples

Live checks send HTTP requests and require authorization. To try one against the bundled local test app, start it from the repository root:

```sh
uv run python fixtures/target_app/app.py
```

In a second terminal, run the launcher against the local URL. The launcher asks you to confirm authorization. This example needs no model API key.

```sh
./partex.sh --no-tui http://127.0.0.1:8765/
```

The version-disclosure check looks for evidence like this:

| Request | Example evidence |
| --- | --- |
| `GET /robots.txt` | A response header reveals the software version, such as `Server: FixtureTarget/2.3.1`. |
| `GET /partex-nonexistent-probe-0` | A `404` response includes internal details, such as a stack trace. |

To review that run with a model, resume the latest saved run in read-only chat. This example uses OpenRouter and requires `OPENROUTER_API_KEY`.

```sh
./partex.sh -m openrouter:deepseek/deepseek-v4.1-flash-1017 --resume
```

To use Z.ai's GLM-5.3 through Pydantic AI Gateway, set `PYDANTIC_AI_GATEWAY_API_KEY` and select the `doubleword` route. If the key's region cannot be inferred or you need a specific endpoint, set `PYDANTIC_AI_GATEWAY_BASE_URL` to the URL from your Gateway Connect page. The launcher accepts a URL that already ends in `/doubleword`.

```sh
./partex.sh -m zai-org/GLM-5.3 -r doubleword --resume
```

## Commands and documentation

- `./partex.sh --help` shows options for the interactive testing launcher.
- `./partex.sh -u urls.txt <target-url>` restricts the session to the URLs in `urls.txt` (one per line, `#` comments, a trailing `/*` allows a path prefix). The target URL is optional with `-u`: the first listed URL is used (an explicit one must be listed). A URL without a port covers both 80 and 443; add `:port` to pin one. Anything unlisted is refused by the scope gate. Add `--recursive` to treat every listed URL as a path prefix, so a file containing `http://foo/` allows everything under `foo`.
- `./partex.sh list` lists saved runs from the default database.
- `uv run partex --help` lists the available CLI commands.

To inspect a saved run, copy its ID from `./partex.sh list` and substitute it below.

```sh
uv run partex show RUN_ID --format text
```

This prints the saved evidence and findings. To open a particular run in chat, pass its ID after `--resume`.

## Local state

Set `PARTEX_STATE_DIR` to choose a directory for all local Partex state. The CLI and launcher interpret relative values from the directory you run them in.

```sh
export PARTEX_STATE_DIR="$HOME/partex-state"
```

Without this override, the CLI and launcher store local state under `$XDG_STATE_HOME/partex`. If `XDG_STATE_HOME` is unset, empty, or relative, they use `~/.local/state/partex`.

| Path within the state directory | Contents |
| --- | --- |
| `partex.db` | Saved runs, evidence, findings, and audit records |
| `partex.db.artifacts/` | Downloaded artifacts by run |
| `partex.db.reports/` | Saved Markdown reports by run |
| `partex.db.exports/` | Operator exports from `/report` and `/secrets` |
| `logs/` | Local JSONL traces |
| `clai2/` | Read-only chat history and terminal settings |

Use `--db PATH` or `PARTEX_DB` to select a different database. Its artifacts, reports, and operator exports are stored alongside it. Use `--log-file PATH` or `PARTEX_LOG_FILE` to select a different trace file. Commands that accept `--out` write to the path you provide.

Existing data stays where it is. To open previous runs, point `--db` at the original database, such as `./partex-probe.db` for the launcher or `${XDG_DATA_HOME:-$HOME/.local/share}/partex/partex.db` for the CLI.

[Design](PLAN.md)
