# ParTEx

ParTEx checks web and API traffic for security issues and links findings to the HTTP responses that support them. Review saved traffic offline or run checks against systems you have permission to test.

## Quick start

From the repository root, use Python 3.14 or newer and `uv`:

```sh
uv sync --frozen
uv run partex review fixtures/bundles/valid --all
```

This example reviews bundled HTTP traffic offline. It prints sample findings and exits with code `3` when it finds issues.

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

[Design](PLAN.md) · [Runtime](RUNTIME.md) · [Dependencies](DEPS.md) · [Project background](docs/lineage/SOURCES.md)
