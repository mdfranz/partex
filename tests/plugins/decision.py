"""Hermetic fake decision model and shared fixtures for #256–#263.

Registered through ``pytest_plugins`` in ``tests/conftest.py``. Subclasses
``FunctionModel`` so it passes ``block_real_models`` (including when wrapped in
``UsageRecordingModel`` or ``InstrumentedModel``) with zero network or API calls.
"""

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Literal

import anyio
import pytest
from pydantic_ai.exceptions import ContentFilterError, ModelAPIError, UnexpectedModelBehavior
from pydantic_ai.messages import ModelMessage, ModelResponse, TextPart, ToolCallPart, UserPromptPart
from pydantic_ai.models.decision import UnfillableRoute, UnsureRoute
from pydantic_ai.models.function import AgentInfo, FunctionModel
from pydantic_ai.usage import RequestUsage

from partex.agent_adapter.decide import DecisionRunner
from partex.models_config import DecisionModelConfig

type FakeDecisionMode = Literal[
    'answered',
    'unsure_handoff',
    'unfillable_handoff',
    'refused',
    'timeout',
    'api_error',
    'unexpected',
    'uncalibrated',
]

NO_ANSWER_FAILURE_MODES: tuple[FakeDecisionMode, ...] = (
    'unsure_handoff',
    'unfillable_handoff',
    'refused',
    'timeout',
    'api_error',
    'unexpected',
)
"""Failure modes that must always map to a non-raising "no answer" outcome (#256–#263)."""


@dataclass(frozen=True, slots=True)
class RecordedDecisionCall:
    """Captured request metadata recorded by :class:`FakeDecisionModel`."""

    prompt: str
    instructions: str | None
    options_by_field: dict[str, list[str]]
    model_settings: Mapping[str, Any] | None


def _extract_prompt_text(messages: list[ModelMessage]) -> str:
    parts: list[str] = []
    for msg in messages:
        for part in getattr(msg, 'parts', ()):
            if isinstance(part, UserPromptPart):
                if isinstance(part.content, str):
                    parts.append(part.content)
                else:
                    parts.extend(str(item) for item in part.content)
    return '\n'.join(parts)


def _options_by_field(info: AgentInfo) -> dict[str, list[str]]:
    schema: dict[str, Any] | None = None
    if info.output_tools:
        schema = info.output_tools[0].parameters_json_schema
    elif info.model_request_parameters.output_object is not None:
        schema = info.model_request_parameters.output_object.json_schema
    if schema is None:
        return {}
    properties: dict[str, Any] = schema.get('properties', {})
    out: dict[str, list[str]] = {}
    for field_name, prop in properties.items():
        if 'enum' in prop:
            out[field_name] = [str(item) for item in prop['enum']]
        elif 'anyOf' in prop:
            out[field_name] = [str(item['const']) for item in prop['anyOf'] if 'const' in item]
        else:
            out[field_name] = []
    return out


class FakeDecisionModel(FunctionModel):
    """Scripted hermetic ``FunctionModel`` simulating calibrated and failure decision outcomes."""

    def __init__(
        self,
        *,
        mode: FakeDecisionMode = 'answered',
        probs: Mapping[str, float] | None = None,
        probs_by_field: Mapping[str, Mapping[str, float]] | None = None,
        responder: Callable[[str, dict[str, list[str]]], Mapping[str, Mapping[str, float]]] | None = None,
        input_tokens: int = 24,
        sleep_seconds: float = 0.2,
        name: str = 'fake-decision-1',
    ) -> None:
        self._mode = mode
        self._probs = dict(probs) if probs is not None else None
        self._probs_by_field = {k: dict(v) for k, v in probs_by_field.items()} if probs_by_field is not None else None
        self._responder = responder
        self._input_tokens = input_tokens
        self._sleep_seconds = sleep_seconds
        self.recorded_calls: list[RecordedDecisionCall] = []
        super().__init__(self._respond, model_name=name)

    async def _respond(self, messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        prompt = _extract_prompt_text(messages)
        options_map = _options_by_field(info)
        self.recorded_calls.append(
            RecordedDecisionCall(
                prompt=prompt,
                instructions=info.instructions,
                options_by_field=options_map,
                model_settings=info.model_settings,
            )
        )

        match self._mode:
            case 'unsure_handoff':
                first_options = next(iter(options_map.values()), ['a', 'b'])
                equal_p = round(1.0 / max(1, len(first_options)), 4)
                raise UnsureRoute(
                    self.model_name,
                    first_options[0],
                    {label: equal_p for label in first_options},
                    0.75,
                )
            case 'unfillable_handoff':
                raise UnfillableRoute(self.model_name, 'free_text', 0.9)
            case 'refused':
                raise ContentFilterError('Content filter triggered by test fixture.', '{"refused": true}')
            case 'timeout':
                await anyio.sleep(self._sleep_seconds)
                raise TimeoutError('fake decision request timed out')
            case 'api_error':
                raise ModelAPIError(self.model_name, 'synthetic upstream API error')
            case 'unexpected':
                raise UnexpectedModelBehavior('synthetic malformed decision response')
            case 'uncalibrated' | 'answered':
                pass
            case _:
                raise ValueError(f'unknown fake decision mode: {self._mode!r}')

        field_probs: dict[str, dict[str, float]] = {}
        if self._responder is not None:
            computed = self._responder(prompt, options_map)
            field_probs = {k: dict(v) for k, v in computed.items()}
        else:
            for field_name, labels in options_map.items():
                if self._probs_by_field is not None and field_name in self._probs_by_field:
                    field_probs[field_name] = dict(self._probs_by_field[field_name])
                elif self._probs is not None and len(options_map) == 1:
                    field_probs[field_name] = dict(self._probs)
                else:
                    rest = round(0.15 / max(1, len(labels) - 1), 6) if len(labels) > 1 else 0.0
                    dist = {label: (0.85 if idx == 0 else rest) for idx, label in enumerate(labels)}
                    field_probs[field_name] = dist

        args = {field_name: max(dist, key=lambda key: dist[key]) for field_name, dist in field_probs.items() if dist}
        if not info.output_tools and info.model_request_parameters.output_object is not None:
            return ModelResponse(
                parts=[TextPart(json.dumps(args))],
                model_name=self.model_name,
                provider_details=None,
                usage=RequestUsage(input_tokens=self._input_tokens, output_tokens=5),
            )
        tool_name = info.output_tools[0].name if info.output_tools else 'final_result'
        details = None if self._mode == 'uncalibrated' else {'probabilities': field_probs}
        return ModelResponse(
            parts=[ToolCallPart(tool_name, args)],
            model_name=self.model_name,
            provider_details=details,
            usage=RequestUsage(input_tokens=self._input_tokens, output_tokens=0),
        )


@pytest.fixture
def fake_decision_model() -> Callable[..., FakeDecisionModel]:
    """Factory fixture building a :class:`FakeDecisionModel` for hermetic decision tests."""

    def _make(**kwargs: Any) -> FakeDecisionModel:
        return FakeDecisionModel(**kwargs)

    return _make


@pytest.fixture
def decision_runner_factory() -> Callable[..., DecisionRunner]:
    """Factory fixture returning a :class:`DecisionRunner` wired to a :class:`FakeDecisionModel`."""

    def _make(
        model: FakeDecisionModel | None = None,
        *,
        spec: str = 'google-decisions:fake-decision-1',
        provider: Literal['google-decisions', 'openai-decisions', 'anthropic'] = 'google-decisions',
        calibrated: bool | None = None,
        timeout_seconds: float = 1.0,
        max_calls: int = 20,
        include_content_in_spans: bool = False,
    ) -> DecisionRunner:
        active_model = model or FakeDecisionModel()
        is_calibrated = (provider != 'anthropic') if calibrated is None else calibrated
        config = DecisionModelConfig(
            spec=spec,
            provider=provider,
            model_name=spec.split(':', 1)[1],
            auth_mode='api_key',
            model=active_model,
            calibrated=is_calibrated,
        )
        return DecisionRunner(
            config=config,
            model=active_model,
            timeout_seconds=timeout_seconds,
            max_calls=max_calls,
            include_content_in_spans=include_content_in_spans,
        )

    return _make
