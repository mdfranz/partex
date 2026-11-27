"""Local recording of model usage totals on ``runs`` — PLAN §7, §9 (#54, #245).

Per-turn metrics (tokens, cache hits, latency, prompts/completions) are recorded on trace spans (local
JSONL log and opt-in Logfire). ``runs`` keeps aggregate totals (``model_calls``, ``input_tokens``,
``output_tokens``) so ``partex report`` and ``partex show`` are complete even with ``--log-file off``
and without ``--logfire``. Wrapping the model, not the agent, catches every turn Pax drives internally.
"""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

from pydantic_ai import RunContext
from pydantic_ai.messages import ModelMessage, ModelResponse
from pydantic_ai.models import Model, ModelRequestParameters, StreamedResponse, infer_model
from pydantic_ai.models.wrapper import WrapperModel
from pydantic_ai.settings import ModelSettings
from pydantic_ai.usage import RequestUsage

from ..storage import LlmRole, RunStore

_PRIMARY_MODEL_ROLES: frozenset[LlmRole] = frozenset({'tester', 'reviewer'})
"""Roles allowed to claim ``runs.model`` when it is still ``NULL``.

Auxiliary roles (``'search'``, ``'decision'``, ``'judge'``) accumulate ``model_calls`` and token
totals on ``runs`` without ever setting or overwriting ``runs.model`` — critical when decision calls
fire at session startup before the analyst's first turn (#256). Post-run or passive triage callers
(#258) must not wrap their decision model in :class:`UsageRecordingModel` against a finalized
passive ``runs`` row so passive run exports (#159) stay immutable.
"""


class UsageRecordingModel(WrapperModel):
    """Wrap *wrapped* so each request accumulates call and token totals onto the run."""

    def __init__(self, wrapped: Model | str, *, store: RunStore, run_id: str, role: LlmRole = 'tester') -> None:
        super().__init__(infer_model(wrapped))
        self._store: RunStore = store
        self._run_id: str = run_id
        self._role: LlmRole = role

    async def _record(self, usage: RequestUsage | None, model_name: str | None) -> None:
        usage = usage or RequestUsage()
        primary_model = (model_name or self.model_name) if self._role in _PRIMARY_MODEL_ROLES else None
        await self._store.record_model_usage(
            self._run_id,
            model=primary_model,
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
        )

    async def request(
        self,
        messages: list[ModelMessage],
        model_settings: ModelSettings | None,
        model_request_parameters: ModelRequestParameters,
    ) -> ModelResponse:
        try:
            response = await super().request(messages, model_settings, model_request_parameters)
        except Exception:
            await self._record(None, self.model_name)
            raise
        await self._record(response.usage, response.model_name or self.model_name)
        return response

    @asynccontextmanager
    async def request_stream(
        self,
        messages: list[ModelMessage],
        model_settings: ModelSettings | None,
        model_request_parameters: ModelRequestParameters,
        run_context: RunContext[Any] | None = None,
    ) -> AsyncGenerator[StreamedResponse]:
        stream: StreamedResponse | None = None
        try:
            async with super().request_stream(
                messages, model_settings, model_request_parameters, run_context
            ) as stream:
                yield stream
        finally:
            usage = stream.usage if stream is not None else None
            model_name = stream.model_name if stream is not None else self.model_name
            await self._record(usage, model_name or self.model_name)
