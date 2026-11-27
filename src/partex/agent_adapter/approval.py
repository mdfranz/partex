"""Operator approval for state-changing target requests — PLAN §4.2 (#119), issue #65.

A non-safe ``http_request`` (POST, PUT, PATCH, DELETE) is held here after the engagement, scope and budget
checks and before anything is sent. The operator answers in the terminal: **approve** (this exact method,
full URL and body), **approve for this session** (method + scheme + host + port + exact path, any body; never
a wildcard), or **deny** (a typed answer denies and is sent to the model as the reason).

The answer comes from the operator's keyboard through Pax's question picker, bound by the partex ``/scope``
plugin, never from model output, so the model cannot approve its own call. With no terminal to ask (a headless
or non-TTY session) nothing is bound, and every state-changing request is denied: nothing is sent.
"""

import hashlib
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic_ai_harness.ask_user import AskUserRequest, AskUserResponse, Question, QuestionOption
from rich.text import Text

from ..models import REDACTED

APPROVE = 'Approve'
APPROVE_SESSION = 'Approve for this session'
DENY = 'Deny'
BODY_PREVIEW_CHARS = 300
"""Characters of a (credential-scrubbed) request body shown to the operator."""

type Choice = Literal['approve', 'approve_session', 'deny']
type DecisionSource = Literal['operator', 'session', 'unattended']


@dataclass(frozen=True, slots=True)
class WriteAction:
    """One held state-changing request, as the operator sees it and as approvals are keyed."""

    method: str
    url: str
    header_names: tuple[str, ...]
    body: str | None
    body_preview: str
    """The body with engagement credentials replaced by ``<redacted>``, cut to :data:`BODY_PREVIEW_CHARS`."""

    @classmethod
    def build(
        cls, method: str, url: str, header_names: Sequence[str], body: str | None, secrets: Sequence[str]
    ) -> WriteAction:
        preview = body or ''
        for secret in sorted((s for s in secrets if s), key=len, reverse=True):
            preview = preview.replace(secret, REDACTED)
        if len(preview) > BODY_PREVIEW_CHARS:
            preview = preview[:BODY_PREVIEW_CHARS] + f'… ({len(body or "")} chars in all)'
        return cls(method, url, tuple(sorted(header_names, key=str.lower)), body, preview)

    @property
    def body_sha256(self) -> str | None:
        return None if self.body is None else hashlib.sha256(self.body.encode()).hexdigest()

    def session_key(self) -> tuple[str, str, str, int, str]:
        """``method + scheme + host + port + exact path``: what *approve for this session* covers (§4.2)."""
        parts = urlsplit(self.url)
        port = parts.port or {'http': 80, 'https': 443}.get(parts.scheme, 0)
        return (self.method, parts.scheme, (parts.hostname or '').lower(), port, parts.path or '/')

    def describe(self) -> str:
        lines = [f'{self.method} {self.url}']
        if self.header_names:
            lines.append(f'headers: {", ".join(self.header_names)}')
        lines.append(f'body: {self.body_preview}' if self.body else 'body: (none)')
        return '\n'.join(lines)

    def audit_args(self) -> dict[str, Any]:
        """What the audit row records: never the body itself, only its size and hash."""
        return {
            'method': self.method,
            'url': self.url,
            'header_names': list(self.header_names),
            'body_chars': len(self.body or ''),
            'body_sha256': self.body_sha256,
        }


@dataclass(frozen=True, slots=True)
class Decision:
    choice: Choice
    source: DecisionSource
    reason: str | None = None

    @property
    def approved(self) -> bool:
        return self.choice != 'deny'


type Asker = Callable[[WriteAction], Awaitable[Decision]]

UNATTENDED = 'no operator can be asked in this session (headless or no terminal), so state-changing requests are denied'


@dataclass(slots=True)
class WriteGate:
    """Session-scoped approval state: the bound asker (or none) and the *approve for this session* keys."""

    ask: Asker | None = None
    _session_keys: set[tuple[str, str, str, int, str]] = field(default_factory=set[tuple[str, str, str, int, str]])

    async def decide(self, action: WriteAction) -> Decision:
        if action.session_key() in self._session_keys:
            return Decision('approve', 'session')
        if self.ask is None:
            return Decision('deny', 'unattended', UNATTENDED)
        decision = await self.ask(action)
        if decision.choice == 'approve_session':
            self._session_keys.add(action.session_key())
        return decision


def approval_request(action: WriteAction, call_id: str) -> AskUserRequest:
    return AskUserRequest(
        id=call_id,
        questions=(
            Question(
                header='Approve write?',
                question=f'Send {action.method} {action.url}?',
                options=(
                    QuestionOption(label=APPROVE, description='Send this exact request once.'),
                    QuestionOption(
                        label=APPROVE_SESSION,
                        description=f'Send {action.method} to this exact path again without asking (any body).',
                    ),
                    QuestionOption(label=DENY, description='Do not send it. Type a reason instead to tell the model.'),
                ),
            ),
        ),
    )


def decision_from(response: AskUserResponse) -> Decision:
    """Map the picker's answer: only an explicit approve option approves; anything else denies."""
    if response.cancelled or not response.answers:
        return Decision('deny', 'operator', 'the operator dismissed the approval question')
    answer = response.answers[0]
    if answer.custom_answer is not None:
        return Decision('deny', 'operator', answer.custom_answer)
    selected = tuple(answer.selected)
    if selected == (APPROVE,):
        return Decision('approve', 'operator')
    if selected == (APPROVE_SESSION,):
        return Decision('approve_session', 'operator')
    return Decision('deny', 'operator', None)


def terminal_asker(host: Any) -> Asker:
    """Ask in Pax's inline terminal picker on *host* (a ``PluginHost``), printing the full action first.

    This subclasses Pax's ``TerminalAnswerer`` and calls its private ``_ask`` so a write approval reuses the same
    inline picker and terminal hand-off as ``ask_user``. ``pydantic-ai-pax`` is locked in ``uv.lock``;
    ``tests/test_write_approval.py`` fails loudly if a bump changes the API this relies on.
    """
    from pydantic_ai_pax.builtin_plugins.ask_user_menu import TerminalAnswerer  # pyright: ignore[reportMissingTypeStubs]

    class _WriteAnswerer(TerminalAnswerer):  # pyright: ignore[reportUntypedBaseClass]
        async def ask_write(self, action: WriteAction) -> AskUserResponse:
            held = Text('http_request waits for approval to send a state-changing request:\n')
            held.append(action.describe())
            return await self._ask(approval_request(action, f'write-{id(action):x}'), held=held)  # pyright: ignore[reportUnknownMemberType]

    answerer = _WriteAnswerer(full_screen=host.full_screen, console=host.console)

    async def ask(action: WriteAction) -> Decision:
        return decision_from(await answerer.ask_write(action))

    return ask
