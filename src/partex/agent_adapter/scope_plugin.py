"""Operator-only ``/scope`` command for a live session — PLAN §4.2, §9; issue #64.

CLAI2 slash commands are handled by the terminal shell and never reach the model, so this is a channel
only the operator can use. ``/scope add <host[:port]|url>`` *stages* a change and shows exactly what
would be added; nothing takes effect until the operator types ``/scope confirm``. The model has no tool
that changes scope; the scope gate itself stays in ``target.py``.
"""

from collections.abc import Sequence
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic_clai2.commands import Command  # pyright: ignore[reportMissingTypeStubs]
from pydantic_clai2.plugins import NoSettings, Plugin  # pyright: ignore[reportMissingTypeStubs]

from ..engine import LiveSession
from ..errors import PartexError
from ..models import Scope
from ..operator_export import exports_dir, write_report, write_secrets
from ..scope import extend_scope
from .approval import WriteGate, terminal_asker

SCOPE_PLUGIN_ID = 'partex_scope'
SCOPE_PLUGIN_FACTORY = 'partex.agent_adapter.scope_plugin:ScopePlugin'
SUBCOMMANDS = ('add', 'confirm', 'cancel')


def describe(scope: Scope) -> str:
    ports = ', '.join(map(str, scope.ports)) or '80/443 (scheme defaults)'
    text = f'hosts: {", ".join(scope.hosts)}\nports: {ports}\npaths: {", ".join(scope.path_prefixes) or "/"}'
    return text + (f'\nauthorized URLs: {len(scope.urls)} (/scope add <url> to add one)' if scope.urls else '')


@dataclass(slots=True)
class ScopeControl:
    """The operator's stage/confirm/cancel state machine over one :class:`LiveSession` (pure, testable)."""

    session: LiveSession
    pending: str | None = field(default=None)
    write_gate: WriteGate | None = field(default=None)
    """The session's write-approval gate (#65); the plugin binds the terminal picker to it."""

    def show(self) -> str:
        text = f'Current scope:\n{describe(self.session.engagement.scope)}'
        if self.pending:
            text += f'\n\nPending (not in effect): {self.pending}. /scope confirm to apply, /scope cancel to drop.'
        return text + '\n\nUsage: /scope add <host[:port]|url>, then /scope confirm.'

    def stage(self, spec: str) -> str:
        before = self.session.engagement.scope
        try:
            after = extend_scope(before, spec)
        except PartexError as exc:
            return f'Refused: {exc}'
        added_hosts = [h for h in after.hosts if h not in before.hosts]
        added_ports = [p for p in after.ports if p not in before.ports]
        added_urls = [u for u in after.urls if u not in before.urls]
        if not added_hosts and not added_ports and not added_urls:
            self.pending = None
            return 'Already in scope; nothing to add.'
        self.pending = spec
        lines = ['Would add to the engagement scope (ports apply to every host in scope):']
        lines += [f'  + host {host}{self._tls_note(host)}' for host in added_hosts]
        lines += [f'  + port {port}' for port in added_ports]
        lines += [f'  + url {url}' for url in added_urls]
        lines.append('Not in effect yet. Type /scope confirm to apply it, or /scope cancel.')
        return '\n'.join(lines)

    def _tls_note(self, host: str) -> str:
        """Flag a host whose certificates will not be verified (``-k`` / ``tls.verify=false`` covers it, #101)."""
        return ' (TLS certificates NOT verified)' if self.session.host_tls_unverified(host) else ''

    async def confirm(self) -> str:
        if self.pending is None:
            return 'Nothing pending. Use /scope add <host[:port]|url> first.'
        spec = self.pending
        operator = self.session.engagement.authorization.operator
        try:
            before, after = await self.session.extend_scope(spec, confirmed_by=operator)
        except PartexError as exc:
            if exc.rule_code == 'scope-persist':  # nothing changed; keep it staged so /scope confirm can retry
                return f'Not applied: {exc}\nThe change is still staged; /scope confirm to retry or /scope cancel.'
            self.pending = None
            return f'Refused: {exc}'
        self.pending = None
        unverified = [h for h in after.hosts if h not in before.hosts and self.session.host_tls_unverified(h)]
        warning = (
            f'\nWarning: TLS certificates will NOT be verified for {", ".join(unverified)} (-k / tls.verify=false).'
            if unverified
            else ''
        )
        return f'Scope extended and recorded on the run.\n{describe(after)}{warning}'

    def _destination(self, args: list[str], suffix: str) -> Path:
        if args:
            return Path(args[0]).expanduser().resolve()
        return exports_dir(self.session.store.path) / f'{self.session.run_id}.{suffix}.md'

    async def report(self, args: list[str]) -> str:
        """``/report [path]``: Markdown report of this run to disk (redacted). Prints the path and counts only."""
        try:
            result = await write_report(self.session.store, self.session.run_id, self._destination(args, 'report'))
        except (PartexError, OSError) as exc:
            return f'Report not written: {exc}'
        return f'Report written to {result.path} ({result.findings} findings, {result.evidence} evidence; secrets redacted).'

    async def secrets(self, args: list[str]) -> str:
        """``/secrets [path]``: unredacted secret values to a 0600 file. Prints the path and counts, never a value."""
        try:
            result = await write_secrets(self.session.store, self.session.run_id, self._destination(args, 'secrets'))
        except (PartexError, OSError) as exc:
            return f'Secrets not written: {exc}'
        return (
            f'Secrets written to {result.path} (mode 0600): {result.js_secrets} JavaScript candidate(s), '
            f'{result.evidence_secrets} secret-marked evidence field(s). Values are not shown here.'
        )

    def cancel(self) -> str:
        was, self.pending = self.pending, None
        return 'Pending change dropped.' if was else 'Nothing pending.'

    async def handle(self, args: list[str]) -> str:
        match args:
            case []:
                return self.show()
            case ['add', spec]:
                return self.stage(spec)
            case ['confirm']:
                return await self.confirm()
            case ['cancel']:
                return self.cancel()
            case _:
                return 'Usage: /scope [add <host[:port]|url> | confirm | cancel]'


current_control: ContextVar[ScopeControl | None] = ContextVar('partex_scope_control', default=None)
"""Set by ``run_agent`` before the chat starts; the plugin reads it when CLAI2 loads it."""


class ScopePlugin(Plugin[NoSettings]):
    """Registers the operator-only ``/scope``, ``/report`` and ``/secrets`` commands for the live session; with no
    session bound it contributes nothing. It also binds the terminal picker that answers write approvals (#65)."""

    def get_capabilities(self) -> Sequence[Any]:
        control = current_control.get()
        # Bind only with a real terminal: an operator's keystrokes answer, never the model. Without one, the gate
        # stays unbound and every state-changing request is denied.
        if control is not None and control.write_gate is not None and self.host.console.is_terminal:
            control.write_gate.ask = terminal_asker(self.host)
        return ()

    def get_commands(self) -> Sequence[Command]:
        control = current_control.get()
        if control is None:
            return ()
        return (
            Command(
                name='report',
                description='Write a Markdown report of this run to disk (secrets redacted): /report [path]',
                handler=control.report,
            ),
            Command(
                name='secrets',
                description='Write secret values to a 0600 file, never shown in chat: /secrets [path]',
                handler=control.secrets,
            ),
            Command(
                name='scope',
                description='Show or extend the engagement scope (operator only): /scope add <host[:port]|url>, /scope confirm',
                handler=control.handle,
                complete=lambda args: SUBCOMMANDS if len(args) <= 1 else (),
            ),
        )
