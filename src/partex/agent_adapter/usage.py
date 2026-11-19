"""Local recording of model usage per turn — PLAN §7 ``llm_usage`` (#54 observability).

The gateway and Logfire see token counts and cost, but a run must be auditable offline too: whether a
model ran, how much it spent, and whether the call failed are part of the run's own record. This wraps
the resolved model so every model request (streamed or not) writes one ``llm_usage`` row to the store.
Wrapping the model, not the agent, catches every turn CLAI2 drives internally.
"""

import time
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


class UsageRecordingModel(WrapperModel):
    """Wrap *wrapped* so each request records one ``llm_usage`` row (role, model, tokens, latency, status)."""

    def __init__(self, wrapped: Model | str, *, store: RunStore, run_id: str, role: LlmRole) -> None:
        super().__init__(infer_model(wrapped))
        self._store: RunStore = store
        self._run_id: str = run_id
        self._role: LlmRole = role

    async def _record(self, usage: RequestUsage | None, model_name: str, status: str, started: float) -> None:
        usage = usage or RequestUsage()
        await self._store.record_llm_usage(
            self._run_id,
            role=self._role,
            model=model_name or self.model_name,
            status='ok' if status == 'ok' else 'error',
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            cache_read_tokens=usage.cache_read_tokens,
            cache_write_tokens=usage.cache_write_tokens,
            latency_ms=int((time.monotonic() - started) * 1000),
        )

    async def request(
        self,
        messages: list[ModelMessage],
        model_settings: ModelSettings | None,
        model_request_parameters: ModelRequestParameters,
    ) -> ModelResponse:
        started = time.monotonic()
        try:
            response = await super().request(messages, model_settings, model_request_parameters)
        except Exception:
            await self._record(None, self.model_name, 'error', started)
            raise
        await self._record(response.usage, response.model_name or self.model_name, 'ok', started)
        return response

    @asynccontextmanager
    async def request_stream(
        self,
        messages: list[ModelMessage],
        model_settings: ModelSettings | None,
        model_request_parameters: ModelRequestParameters,
        run_context: RunContext[Any] | None = None,
    ) -> AsyncGenerator[StreamedResponse]:
        started = time.monotonic()
        stream: StreamedResponse | None = None
        status = 'ok'
        try:
            async with super().request_stream(
                messages, model_settings, model_request_parameters, run_context
            ) as stream:
                yield stream
        except Exception:
            status = 'error'
            raise
        finally:
            usage = stream.usage if stream is not None else None
            model_name = stream.model_name if stream is not None else self.model_name
            await self._record(usage, model_name or self.model_name, status, started)
