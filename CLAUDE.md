# partex — agent working agreement

Minimal rules for every agent (human-run or autonomous) working in this repo. Iterate here as
conventions settle. The spec is [PLAN.md](PLAN.md) (with [RUNTIME.md](RUNTIME.md) and
[DEPS.md](DEPS.md)); when this file and PLAN.md disagree on design, PLAN.md wins.

## Picking up an issue

Several agents work in parallel, often on different machines. Before starting:

1. `git pull` on `main`.
2. Read the issue, its comments, and its **blocked by** links
   (`gh api repos/mdfranz/partex/issues/<n>/dependencies/blocked_by`). Don't start a blocked issue.
3. Check nobody else has it: assignees, recent comments, `gh pr list`, and remote branches
   (`gh api repos/mdfranz/partex/branches`).
4. Claim it: assign yourself and comment `Agent hostname: <output of hostname>` and `Agent Name: <Claude/codex/opencode/agy>`

While working:

- Prefix every issue/PR comment with your hostname line, so the team can tell agents apart.
- Comment on the issue when you are blocked, when scope changes, or when you find a plan
  contradiction. Ask there instead of guessing; don't silently redesign.
- One issue = one branch `issue-<n>-<slug>` (a git worktree is fine) = one PR whose body says
  `Closes #<n>`. Never commit directly to `main`.
- Exception: small, unrelated issues may share one branch (`issue-<n>-<m>-<slug>`) and one PR. Claim
  each issue, put a `Closes #<n>` line per issue in the PR body, and say the PR bundles them. Large or
  risky issues stay in their own PR.
- Touch only the files the issue lists under **Owns**. If you must edit a shared file
  (`pyproject.toml`, `tests/conftest.py`, `cli.py`), keep the hunk minimal and say so in the PR.
- Unassign yourself and comment if you stop before finishing.

## Environment

- Use **uv** for everything: `uv sync`, `uv run pytest`, `uv run ruff check`,
  `uv run ruff format`, `uv run pyright`. No `pip install`, no ad-hoc venvs in the repo.
- `pydantic-*` and `pydantic-monty*` resolve from PyPI through `uv.lock` (PLAN §3.1, issue #13);
  never add `[tool.uv.sources]` path overrides, and bump them only as an explicit `uv.lock` change.
- uv enforces a **2-day cool-off** (`[tool.uv] exclude-newer = "2 days"` in `pyproject.toml`):
  nothing uploaded to PyPI in the last 48 hours can enter `uv.lock`. Don't remove it or set a
  global override; an urgent fix gets a reviewed per-package `exclude-newer-package` entry.
- Python floor is **3.14**: use modern syntax (PEP 695 `type` aliases and generics); never add
  `from __future__ import annotations`.
- Style: ruff, single quotes, 120 columns; pyright strict.

## Definition of done

- `uv run ruff check`, `uv run ruff format --check`, `uv run pyright`, `uv run pytest` all green.
- Issue acceptance checklist ticked; PR description lists anything skipped.

## Non-negotiables

- Tests are hermetic: no non-loopback network, no real model calls, no real credentials.
- Engagement credentials are env var **names**, never values; never commit secrets.
- Only `target.py` opens sockets for engine traffic (M7 `browser.py` is the one sanctioned
  exception); only `agent_adapter/` imports `pydantic_ai_pax`; the engine is the only DB writer.
- Skills under `skills/` are data: never import or execute them.

## Git notes

- Commits in this repo are **not** signed: set `git config --local commit.gpgsign false` in
  your clone (global signing settings stay as they are). Don't block on a signing prompt.
- If SSH push/fetch fails, use the gh credential helper over HTTPS:
  `git -c credential.helper= -c credential.helper='!gh auth git-credential' push https://github.com/mdfranz/partex.git <branch>`
