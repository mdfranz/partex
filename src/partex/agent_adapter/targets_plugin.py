"""Operator-only ``/targets`` command and status badge as a CLAI2 plugin.

Supports three modes:
- live ``partex agent`` session (reads current session's store + live scope, updates status row live);
- read-only ``partex chat`` session (reads through ``RunReader`` without writing anything);
- standalone ``clai2`` (reads from ``TargetsPluginSettings.db`` / ``$PARTEX_DB`` / default ``partex.db``).

``get_capabilities()`` always returns ``()`` so cross-target discoveries never reach any model context.
"""

import os
from collections.abc import Sequence
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict
from pydantic_clai2.commands import Command  # pyright: ignore[reportMissingTypeStubs]
from pydantic_clai2.plugins import Plugin  # pyright: ignore[reportMissingTypeStubs]
from pydantic_clai2.ui.rendering.status import StatusSegment  # pyright: ignore[reportMissingTypeStubs]

from ..engine import LiveSession
from ..errors import PartexError
from ..models import ArtifactEvidence, HttpEvidence
from ..paths import state_dir
from ..scope import entry_url
from ..storage import RunReader, StoreError
from ..targets import (
    DiscoveryRollup,
    OriginKey,
    canonical_origin,
    format_origin,
    format_status_badge,
    gather_all_targets,
    gather_run_targets,
    render_target_detail,
    render_targets_overview,
)

TARGETS_PLUGIN_ID = 'partex_targets'
TARGETS_PLUGIN_FACTORY = 'partex.agent_adapter.targets_plugin:TargetsPlugin'
FLAGS = ('--all', '--findings', '--help')

_USAGE = 'Usage: /targets [host | --all | --findings]'
_HELP = (
    'Usage: /targets [host | --all | --findings]\n'
    '  /targets             Succinct overview of discovered targets\n'
    '  /targets <host>      Paths, banners, findings, and coverage gaps for one target\n'
    '  /targets --findings  Show only targets with findings\n'
    '  /targets --all       Aggregate across all saved runs in the database'
)


class TargetsPluginSettings(BaseModel):
    """Optional settings for standalone CLAI2 use; empty when loaded inside partex."""

    model_config = ConfigDict(extra='forbid', frozen=True)

    db: str | None = None


def _resolve_standalone_db(configured: str | None) -> Path:
    if configured:
        return Path(configured).expanduser()
    if env_db := os.environ.get('PARTEX_DB'):
        return Path(env_db).expanduser()
    return state_dir() / 'partex.db'


@dataclass(slots=True)
class TargetsControl:
    """Operator-only ``/targets`` handler and status state across live, chat, and standalone modes."""

    session: LiveSession | None = None
    reader: RunReader | None = None
    run_id: str | None = None
    db_path: Path | None = None
    _cached_rollup: DiscoveryRollup | None = field(default=None)

    @property
    def standalone(self) -> bool:
        return self.session is None and self.reader is None

    @classmethod
    def for_session(cls, session: LiveSession) -> TargetsControl:
        """Bind to an active ``partex agent`` :class:`LiveSession`."""
        return cls(session=session)

    @classmethod
    async def for_reader(cls, reader: RunReader, run_id: str) -> TargetsControl:
        """Bind read-only to a ``partex chat`` :class:`RunReader`, pre-loading the status badge."""
        rollup = await gather_run_targets(reader, run_id)
        return cls(reader=reader, run_id=run_id, _cached_rollup=rollup)

    @classmethod
    def for_db(cls, db_path: Path) -> TargetsControl:
        """Bind to a database path for standalone CLAI2 use."""
        return cls(db_path=db_path)

    def _live_counts(self) -> tuple[int, int, int, list[tuple[str, str]]]:
        """Fast in-memory summary for the live session's status segment and completions."""
        assert self.session is not None
        origins: dict[OriginKey, str] = {}
        up_origins: set[OriginKey] = set()
        for entry in self.session.engagement.scope.urls:
            if (key := canonical_origin(entry_url(entry))) is not None:
                origins.setdefault(key, format_origin(*key))
        for item in self.session.captured:
            url: str | None = None
            if isinstance(item, HttpEvidence):
                url = item.http.request.url
            elif isinstance(item, ArtifactEvidence):
                url = item.artifact.url
            if url is not None and (key := canonical_origin(url)) is not None:
                origins.setdefault(key, format_origin(*key))
                up_origins.add(key)
        host_origins = [(key[1], origin) for key, origin in origins.items()]
        return len(origins), len(up_origins), len(self.session.findings), host_origins

    def status_segment(self) -> str:
        """Synchronous, I/O-free status-row fragment."""
        if self.session is not None:
            total, up, findings, _ = self._live_counts()
            return format_status_badge(total, up, findings)
        if self._cached_rollup is not None:
            return format_status_badge(
                len(self._cached_rollup.targets),
                self._cached_rollup.up_count,
                self._cached_rollup.total_findings,
            )
        return ''

    def _target_completions(self) -> list[str]:
        candidates: list[str] = []
        if self.session is not None:
            _, _, _, pairs = self._live_counts()
            for host, origin in pairs:
                for token in (host, origin):
                    if token not in candidates:
                        candidates.append(token)
        elif self._cached_rollup is not None:
            for target in self._cached_rollup.targets:
                for token in (target.host, target.origin):
                    if token not in candidates:
                        candidates.append(token)
        return candidates

    def completions(self, args: list[str]) -> tuple[str, ...]:
        """Tab completions for ``/targets`` flags and known targets."""
        used = set(args[:-1])
        if '--help' in used or '-h' in used:
            return ()
        candidates = [flag for flag in FLAGS if flag not in used]
        if not any(not arg.startswith('-') for arg in used):
            candidates.extend(self._target_completions())
        return tuple(candidates)

    async def _load_rollup(self, *, show_all: bool) -> DiscoveryRollup:
        if self.session is not None:
            if show_all:
                return await gather_all_targets(
                    self.session.store,
                    current_run_id=self.session.run_id,
                    live_scope=self.session.engagement.scope,
                    live_tls_unverified=self.session.host_tls_unverified,
                )
            return await gather_run_targets(
                self.session.store,
                self.session.run_id,
                live_scope=self.session.engagement.scope,
                live_tls_unverified=self.session.host_tls_unverified,
            )
        if self.reader is not None and self.run_id is not None:
            if show_all:
                return await gather_all_targets(self.reader, current_run_id=self.run_id)
            return await gather_run_targets(self.reader, self.run_id)
        assert self.db_path is not None
        async with await RunReader.open(self.db_path) as reader:
            return await gather_all_targets(reader)

    async def handle(self, args: list[str]) -> str:
        """Handle ``/targets [host | --all | --findings | --help]``."""
        show_all = False
        findings_only = False
        query: str | None = None
        for arg in args:
            if arg in ('-h', '--help'):
                return _HELP
            if arg in ('-a', '--all'):
                show_all = True
            elif arg in ('-f', '--findings'):
                findings_only = True
            elif arg.startswith('-'):
                return _USAGE
            elif query is None:
                query = arg
            else:
                return _USAGE

        try:
            rollup = await self._load_rollup(show_all=show_all)
        except (StoreError, PartexError, OSError) as exc:
            if self.db_path is not None:
                return f'Could not read {self.db_path}: {exc}'
            return f'Could not read targets: {exc}'

        if query is not None:
            return render_target_detail(rollup, query)
        return render_targets_overview(
            rollup,
            findings_only=findings_only,
            show_all_hint=not show_all and not self.standalone,
        )


current_targets: ContextVar[TargetsControl | None] = ContextVar('partex_targets_control', default=None)
"""Set by ``run_agent`` and ``run_chat`` before the chat starts; ``None`` in standalone CLAI2."""


class TargetsPlugin(Plugin[TargetsPluginSettings]):
    """Registers the operator-only ``/targets`` command (and status segment when bound to a session)."""

    def _control(self) -> TargetsControl:
        bound = current_targets.get()
        if bound is not None:
            return bound
        return TargetsControl.for_db(_resolve_standalone_db(self.settings.db))

    def get_capabilities(self) -> Sequence[Any]:
        return ()

    def get_commands(self) -> Sequence[Command]:
        control = self._control()
        return (
            Command(
                name='targets',
                description='Describe what has been discovered across targets: /targets [host | --all | --findings]',
                handler=control.handle,
                complete=control.completions,
            ),
        )

    def get_status_segments(self) -> Sequence[StatusSegment]:
        bound = current_targets.get()
        if bound is None:
            return ()
        return (bound.status_segment,)
