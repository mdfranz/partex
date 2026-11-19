"""Tests proving the hermetic test harness guards trip and allow safe local paths (PLAN §14)."""

import socket
from pathlib import Path
from typing import Any

import logfire
import pydantic_ai.models
import pytest
from conftest import (
    HermeticModelError,
    HermeticNetworkError,
    HermeticTelemetryError,
    pytest_plugins,
)
from logfire.testing import CaptureLogfire
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from pydantic_ai import Agent
from pydantic_ai.messages import ModelMessage, ModelResponse, TextPart
from pydantic_ai.models import Model, ModelRequestParameters, check_allow_model_requests
from pydantic_ai.models.function import AgentInfo, FunctionModel
from pydantic_ai.models.test import TestModel
from pydantic_ai.settings import ModelSettings


class _DummyExternalModel(Model):
    """Minimal non-test Model subclass that omits `check_allow_model_requests()`."""

    @property
    def model_name(self) -> str:
        return 'dummy-external'

    @property
    def system(self) -> str:
        return 'dummy'

    async def request(
        self,
        messages: list[ModelMessage],
        model_settings: ModelSettings | None,
        model_request_parameters: ModelRequestParameters,
    ) -> ModelResponse:
        return ModelResponse(parts=[TextPart('should never run')])


def test_blocks_external_ipv4_connect() -> None:
    with (
        socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock,
        pytest.raises(HermeticNetworkError, match='Non-loopback socket connect blocked'),
    ):
        sock.connect(('93.184.216.34', 80))


def test_blocks_external_ipv4_connect_ex() -> None:
    with (
        socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock,
        pytest.raises(HermeticNetworkError, match='Non-loopback socket connect_ex blocked'),
    ):
        sock.connect_ex(('1.1.1.1', 443))


def test_blocks_external_ipv6_connect() -> None:
    with (
        socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock,
        pytest.raises(HermeticNetworkError, match='Non-loopback socket connect blocked'),
    ):
        sock.connect(('2001:db8::1', 80))


def test_blocks_external_hostname_connect() -> None:
    with (
        socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock,
        pytest.raises(HermeticNetworkError, match='Non-loopback socket connect blocked'),
    ):
        sock.connect(('example.com', 80))


def test_allows_loopback_ipv4_connect() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(('127.0.0.1', 0))
        server.listen(1)
        port = server.getsockname()[1]

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.connect(('127.0.0.1', port))
            conn, _ = server.accept()
            conn.close()


def test_allows_unix_domain_socket(tmp_path: Path) -> None:
    sock_path = str(tmp_path / 'local.sock')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(sock_path)
        server.listen(1)

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(sock_path)
            conn, _ = server.accept()
            conn.close()


def test_blocks_pydantic_ai_allow_model_requests_flag() -> None:
    assert pydantic_ai.models.ALLOW_MODEL_REQUESTS is False
    with pytest.raises(RuntimeError, match='ALLOW_MODEL_REQUESTS is False'):
        check_allow_model_requests()


async def test_blocks_unoverridden_real_model() -> None:
    agent = Agent('openai:gpt-5', defer_model_check=True)
    with pytest.raises(HermeticModelError, match='Real model execution blocked'):
        await agent.run('hello')


async def test_blocks_custom_non_test_model_override() -> None:
    agent = Agent('openai:gpt-5', defer_model_check=True)
    with (
        agent.override(model=_DummyExternalModel()),
        pytest.raises(HermeticModelError, match='Real model execution blocked'),
    ):
        await agent.run('hello')


async def test_allows_test_model_override() -> None:
    agent = Agent('openai:gpt-5', defer_model_check=True)
    with agent.override(model=TestModel(custom_output_text='hermetic-ok')):
        result = await agent.run('hello')
    assert result.output == 'hermetic-ok'


async def test_allows_function_model_override() -> None:
    def respond(_messages: list[ModelMessage], _info: AgentInfo) -> ModelResponse:
        return ModelResponse(parts=[TextPart('function-ok')])

    agent = Agent('openai:gpt-5', defer_model_check=True)
    with agent.override(model=FunctionModel(respond)):
        result = await agent.run('hello')
    assert result.output == 'function-ok'


@pytest.mark.parametrize('kwargs', [{'send_to_logfire': True}, {}, {'send_to_logfire': 'if-token-present'}])
def test_blocks_remote_telemetry_export(kwargs: dict[str, Any]) -> None:
    with pytest.raises(HermeticTelemetryError, match='Remote Logfire telemetry export blocked'):
        logfire.configure(**kwargs)


def test_capfire_captures_spans_locally(capfire: CaptureLogfire) -> None:
    with logfire.span('harness-capfire-check'):
        pass
    span_names = [span['name'] for span in capfire.exporter.exported_spans_as_dict()]
    assert 'harness-capfire-check' in span_names


def test_in_memory_span_exporter_captures_spans_locally(
    in_memory_span_exporter: InMemorySpanExporter,
) -> None:
    with logfire.span('harness-otel-check'):
        pass
    span_names = [span.name for span in in_memory_span_exporter.get_finished_spans()]
    assert 'harness-otel-check' in span_names


def test_conftest_declares_pytest_plugins_list() -> None:
    assert isinstance(pytest_plugins, list)
