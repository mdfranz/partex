"""Agent adapter — the only package that imports ``pydantic_clai2`` (PLAN §2, §9).

``run_chat`` opens one run read-only and hands the reviewer to the CLAI2 terminal with every plugin
off: no coding tools, no filesystem, no shell, no network beyond the model provider.
"""

from pathlib import Path

from pydantic_ai.models import Model

# Imported at module level, before any tool frames text: CLAI2 registers its own framing tags at
# import time, and a tag registered after escaping has started changes how earlier text renders.
from pydantic_clai2 import chat  # pyright: ignore[reportMissingTypeStubs, reportUnknownVariableType]

from ..storage import RunReader
from .reviewer import build_reviewer_agent
from .tools import ReviewDeps

__all__ = ['ReviewDeps', 'build_reviewer_agent', 'run_chat']


async def run_chat(run_id: str, db_path: Path, model: Model | str) -> None:
    """Open *run_id* in *db_path* read-only and start the interactive reviewer (returns on /exit)."""
    async with await RunReader.open(db_path) as reader:
        await reader.get_run(run_id)  # unknown run → StoreError(run-not-found) before any terminal UI
        agent = build_reviewer_agent(model)
        await chat(agent, deps=ReviewDeps(run_id=run_id, reader=reader), load_plugins=False)
