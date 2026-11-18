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
- Touch only the files the issue lists under **Owns**. If you must edit a shared file
  (`pyproject.toml`, `tests/conftest.py`, `cli.py`), keep the hunk minimal and say so in the PR.
- Unassign yourself and comment if you stop before finishing.

## Environment

- Use **uv** for everything: `uv sync`, `uv run pytest`, `uv run ruff check`,
  `uv run ruff format`, `uv run pyright`. No `pip install`, no ad-hoc venvs in the repo.
- `pydantic-*` and `pydantic-monty*` come only from sibling checkouts `../pydantic-ai` and
  `../monty` (PLAN §3.1), at the revisions pinned in DEPS.md (pins land with #1). Never add them from PyPI and
  never point `pyproject.toml` at another path — symlink the checkouts instead.
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
  exception); only `agent_adapter/` imports `pydantic_clai2`; the engine is the only DB writer.
- Skills under `skills/` are data: never import or execute them.

## Git notes

- Commits may be SSH-signed; if signing prompts for a passphrase you can't supply, stop and
  ask the operator. Never disable signing.
- If SSH push/fetch fails, use the gh credential helper over HTTPS:
  `git -c credential.helper= -c credential.helper='!gh auth git-credential' push https://github.com/mdfranz/partex.git <branch>`
