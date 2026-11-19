"""Agent adapter — the only package that imports ``pydantic_clai2`` (PLAN §2, §9).

``run_chat`` opens one run read-only, prints an opening briefing from the reviewer, then hands the
reviewer to the CLAI2 terminal with every plugin off: no coding tools, no filesystem, no shell, no
network beyond the model provider.
"""

from pathlib import Path

import anyio.to_thread
from pydantic_ai.exceptions import AgentRunError
from pydantic_ai.models import Model

# Imported at module level, before any tool frames text: CLAI2 registers its own framing tags at
# import time, and a tag registered after escaping has started changes how earlier text renders.
from pydantic_clai2 import chat  # pyright: ignore[reportMissingTypeStubs, reportUnknownVariableType]
from pydantic_clai2.config import Settings  # pyright: ignore[reportMissingTypeStubs]
from rich.console import Console
from rich.markdown import Markdown
from rich.rule import Rule

from ..storage import RunReader
from .reviewer import BRIEFING_PROMPT, build_reviewer_agent
from .tools import ReviewDeps

# Explicit CLAI2 settings, so the operator's saved CLAI2 preferences cannot change what the reviewer is:
# model=None keeps the agent's model (CLAI2's default model would otherwise override it), and Code Mode
# stays off so the model calls partex's tools natively instead of through a run_code sandbox (RUNTIME.md M5).
CHAT_SETTINGS = Settings(model=None, code_mode=False, speculative_code_mode=False)

__all__ = ['BRIEFING_PROMPT', 'ReviewDeps', 'brief', 'build_reviewer_agent', 'run_chat']


async def brief(model: Model | str, deps: ReviewDeps, console: Console) -> str | None:
    """Run the reviewer once on :data:`BRIEFING_PROMPT` and print the result; ``None`` if the model failed.

    A failed briefing is reported and the chat still opens: the operator can ask directly.
    """
    with console.status(f'Reviewing {deps.run_id} …'):
        try:
            result = await build_reviewer_agent(model).run(BRIEFING_PROMPT, deps=deps)
        except AgentRunError as exc:
            console.print(f'[yellow]briefing unavailable:[/] {exc}')
            return None
    console.print(Rule(f'briefing · {deps.run_id}'))
    console.print(Markdown(result.output))
    console.print(Rule())
    return result.output


async def run_chat(
    run_id: str, db_path: Path, model: Model | str, *, briefing: bool = True, console: Console | None = None
) -> None:
    """Open *run_id* in *db_path* read-only, print a briefing (unless disabled), then start the chat."""
    console = console or Console()
    async with await RunReader.open(db_path) as reader:
        await reader.get_run(run_id)  # unknown run → StoreError(run-not-found) before any model call or UI
        deps = ReviewDeps(run_id=run_id, reader=reader)
        summary = await brief(model, deps, console) if briefing else None
        if summary is not None and console.is_terminal:
            # CLAI2 takes over the screen and shows only its own transcript; let the operator read the
            # briefing first. It stays in the terminal's scrollback above the session.
            await anyio.to_thread.run_sync(lambda: console.input('[dim]Press Enter to open the chat…[/]'))
        agent = build_reviewer_agent(model, briefing=summary)
        await chat(agent, deps=deps, load_plugins=False, console=console, settings=CHAT_SETTINGS)
