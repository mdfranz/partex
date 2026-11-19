"""Agent adapter — the only package that imports ``pydantic_clai2`` (PLAN §2, §9).

``run_chat`` opens one run read-only, prints an opening briefing from the reviewer, then hands the
reviewer to the CLAI2 terminal with every plugin off: no coding tools, no filesystem, no shell, no
network beyond the model provider. ``run_agent`` does the same over a new live session, with the
tester's scoped ``http_request`` and ``run_check`` added (#54).
"""

import tempfile
from pathlib import Path

import anyio.to_thread
from pydantic_ai.exceptions import AgentRunError
from pydantic_ai.models import Model

# Imported at module level, before any tool frames text: CLAI2 registers its own framing tags at
# import time, and a tag registered after escaping has started changes how earlier text renders.
from pydantic_clai2 import chat  # pyright: ignore[reportMissingTypeStubs, reportUnknownVariableType]
from pydantic_clai2.config import PluginSettings, Settings  # pyright: ignore[reportMissingTypeStubs]
from pydantic_clai2.config.settings_store import SettingsStore  # pyright: ignore[reportMissingTypeStubs]
from rich.console import Console
from rich.markdown import Markdown
from rich.rule import Rule

from .. import engine
from ..storage import RunReader, RunStore
from .reviewer import BRIEFING_PROMPT, build_reviewer_agent
from .scope_plugin import SCOPE_PLUGIN_FACTORY, SCOPE_PLUGIN_ID, ScopeControl, current_control
from .tester import TesterDeps, build_tester_agent
from .tools import ReviewDeps
from .usage import UsageRecordingModel

# Explicit CLAI2 settings, so the operator's saved CLAI2 preferences cannot change what the reviewer is:
# model=None keeps the agent's model (CLAI2's default model would otherwise override it), and Code Mode
# stays off so the model calls partex's tools natively instead of through a run_code sandbox (RUNTIME.md M5).
CHAT_SETTINGS = Settings(model=None, code_mode=False, speculative_code_mode=False)

__all__ = [
    'BRIEFING_PROMPT',
    'ReviewDeps',
    'TesterDeps',
    'brief',
    'build_reviewer_agent',
    'build_tester_agent',
    'run_agent',
    'run_chat',
]


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


async def _pause_on(summary: str | None, console: Console) -> None:
    """CLAI2 takes over the screen and shows only its own transcript; let the operator read the briefing
    first. It stays in the terminal's scrollback above the session."""
    if summary is not None and console.is_terminal:
        await anyio.to_thread.run_sync(lambda: console.input('[dim]Press Enter to open the chat…[/]'))


async def run_chat(
    run_id: str, db_path: Path, model: Model | str, *, briefing: bool = True, console: Console | None = None
) -> None:
    """Open *run_id* in *db_path* read-only, print a briefing (unless disabled), then start the chat."""
    console = console or Console()
    async with await RunReader.open(db_path) as reader:
        await reader.get_run(run_id)  # unknown run → StoreError(run-not-found) before any model call or UI
        deps = ReviewDeps(run_id=run_id, reader=reader)
        summary = await brief(model, deps, console) if briefing else None
        await _pause_on(summary, console)
        agent = build_reviewer_agent(model, briefing=summary)
        await chat(agent, deps=deps, load_plugins=False, console=console, settings=CHAT_SETTINGS)


async def run_agent(
    engagement_path: Path,
    db_path: Path,
    model: Model | str,
    *,
    authorized: bool,
    checks: tuple[str, ...] = ('version-disclosure',),
    from_run: str | None = None,
    briefing: bool = True,
    console: Console | None = None,
) -> str:
    """Open a new live session on *engagement_path*, brief, then let the operator direct probes in CLAI2.

    The engine does the gates (``--authorized``, E1–E7, credentials) before any socket, the baseline
    capture, and the selected active *checks*; the session's run is finalized when the chat ends.
    Returns the session's run ID.
    """
    console = console or Console()
    async with await RunStore.open(db_path) as store:
        if from_run is not None:
            await store.get_run(from_run)  # unknown run → StoreError(run-not-found) before any socket
        async with engine.live_session(engagement_path, store, authorized=authorized, checks=checks) as session:
            # Record every model turn (briefing, chat) and every read-tool call to this run (§7, #54),
            # so the run is auditable offline, not only through the gateway/Logfire.
            recorded = UsageRecordingModel(model, store=store, run_id=session.run_id, role='tester')

            async def audit(tool: str, args: dict[str, object], result: dict[str, object]) -> None:
                await store.record_tool_call(session.run_id, tool, args, result)

            deps = TesterDeps(
                run_id=session.run_id,
                reader=store,
                previous_run_id=from_run,
                audit=audit,
                session=session,
                store=store,
            )
            summary = await brief(recorded, deps, console) if briefing else None
            await _pause_on(summary, console)
            agent = build_tester_agent(recorded, briefing=summary)
            # The operator-only /scope command is a CLAI2 plugin (slash commands exist only as plugins). A
            # private, empty settings store keeps the operator's saved and drop-in CLAI2 plugins out, and
            # only the partex plugin is declared, so the session loads nothing else (#64).
            with tempfile.TemporaryDirectory(prefix='partex-clai2-') as config_dir:
                token = current_control.set(ScopeControl(session))
                try:
                    await chat(
                        agent,
                        deps=deps,
                        load_plugins=True,
                        store=SettingsStore(Path(config_dir) / 'config.db'),
                        builtin_plugins=(PluginSettings(id=SCOPE_PLUGIN_ID, factory=SCOPE_PLUGIN_FACTORY),),
                        console=console,
                        settings=CHAT_SETTINGS,
                    )
                finally:
                    current_control.reset(token)
        return session.run_id
