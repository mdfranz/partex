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

## Pydantic libraries

Pydantic validates inputs such as assessment settings and captured traffic. Pydantic AI connects models to the tools they can use, and its CLAI2 package provides the interactive terminal. Monty runs model-generated Python in a sandbox when the interactive session needs to work with saved evidence. [Runtime](RUNTIME.md) · [Dependencies](DEPS.md)

## Active probe examples

Live checks send HTTP requests and require authorization. The bundled local test app shows what these checks look for.

| Request | Example evidence |
| --- | --- |
| `GET /robots.txt` | A response header reveals the software version, such as `Server: FixtureTarget/2.3.1`. |
| `GET /partex-nonexistent-probe-0` | A `404` response includes internal details, such as a stack trace. |

## Commands and documentation

- `./partex.sh --help` shows options for the interactive testing launcher.
- `./partex.sh list` lists saved runs from the launcher's database.
- `uv run partex --help` lists the available CLI commands.

[Design](PLAN.md)
