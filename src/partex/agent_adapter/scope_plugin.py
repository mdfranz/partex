"""Operator-only ``/scope`` command for a live session — PLAN §4.2, §9; issue #64.

CLAI2 slash commands are handled by the terminal shell and never reach the model, so this is a channel
only the operator can use. ``/scope add <host[:port]|url>`` *stages* a change and shows exactly what
would be added; nothing takes effect until the operator types ``/scope confirm``. The model has no tool
that changes scope; the scope gate itself stays in ``target.py``.
"""

from collections.abc import Sequence
from contextvars import ContextVar
from dataclasses import dataclass, field

from pydantic_clai2.commands import Command  # pyright: ignore[reportMissingTypeStubs]
from pydantic_clai2.plugins import NoSettings, Plugin  # pyright: ignore[reportMissingTypeStubs]

from ..engine import LiveSession
from ..errors import PartexError
from ..models import Scope
from ..scope import extend_scope

SCOPE_PLUGIN_ID = 'partex_scope'
SCOPE_PLUGIN_FACTORY = 'partex.agent_adapter.scope_plugin:ScopePlugin'
SUBCOMMANDS = ('add', 'confirm', 'cancel')


def describe(scope: Scope) -> str:
    ports = ', '.join(map(str, scope.ports)) or '80/443 (scheme defaults)'
    return f'hosts: {", ".join(scope.hosts)}\nports: {ports}\npaths: {", ".join(scope.path_prefixes) or "/"}'


@dataclass(slots=True)
class ScopeControl:
    """The operator's stage/confirm/cancel state machine over one :class:`LiveSession` (pure, testable)."""

    session: LiveSession
    pending: str | None = field(default=None)

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
        if not added_hosts and not added_ports:
            self.pending = None
            return 'Already in scope; nothing to add.'
        self.pending = spec
        lines = ['Would add to the engagement scope (ports apply to every host in scope):']
        lines += [f'  + host {host}' for host in added_hosts] + [f'  + port {port}' for port in added_ports]
        lines.append('Not in effect yet. Type /scope confirm to apply it, or /scope cancel.')
        return '\n'.join(lines)

    async def confirm(self) -> str:
        if self.pending is None:
            return 'Nothing pending. Use /scope add <host[:port]|url> first.'
        spec, self.pending = self.pending, None
        operator = self.session.engagement.authorization.operator
        try:
            _, after = await self.session.extend_scope(spec, confirmed_by=operator)
        except PartexError as exc:
            return f'Refused: {exc}'
        return f'Scope extended and recorded on the run.\n{describe(after)}'

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
    """Registers ``/scope`` for the live session; with no session bound it contributes nothing."""

    def get_commands(self) -> Sequence[Command]:
        control = current_control.get()
        if control is None:
            return ()
        return (
            Command(
                name='scope',
                description='Show or extend the engagement scope (operator only): /scope add <host[:port]|url>, /scope confirm',
                handler=control.handle,
                complete=lambda args: SUBCOMMANDS if len(args) <= 1 else (),
            ),
        )
