"""Hermetic test harness for partex (PLAN §14).

Enforces three session-wide isolation boundaries:
1. Network: blocks any IPv4/IPv6 socket connect to a non-loopback address.
2. Models: disables real provider requests and rejects any model other than
   `TestModel` / `FunctionModel`.
3. Telemetry: configures Logfire with `send_to_logfire=False`, blocks any attempt
   to re-enable remote telemetry export, and exposes `capfire` (via `logfire.testing`)
   plus `in_memory_span_exporter` for span assertions.

Later issues add fixture modules under `tests/plugins/` and register them in
`pytest_plugins` below without modifying the guard fixtures.
"""

import ipaddress
import socket
from collections.abc import Generator
from typing import Any

import logfire
import pydantic_ai.models
import pytest
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from pydantic_ai import Agent
from pydantic_ai.models.function import FunctionModel
from pydantic_ai.models.test import TestModel
from pydantic_ai.models.wrapper import WrapperModel

# Later issues append 'tests.plugins.<module>' entries here without editing fixture bodies.
pytest_plugins: list[str] = ['plugins.store']


class HermeticNetworkError(RuntimeError):
    """Raised when test code attempts to connect to a non-loopback address."""


class HermeticModelError(RuntimeError):
    """Raised when test code attempts to execute a non-test model."""


class HermeticTelemetryError(RuntimeError):
    """Raised when test code attempts to enable remote telemetry export."""


def _is_loopback_address(sock: socket.socket, address: Any) -> bool:
    """Return True if `address` is a non-IP socket or a loopback IPv4/IPv6 endpoint."""
    if sock.family not in (socket.AF_INET, socket.AF_INET6):
        return True
    if not isinstance(address, tuple) or not address:
        return False

    host: object = address[0]  # pyright: ignore[reportUnknownVariableType]
    if not isinstance(host, str):
        return False

    host_clean = host.strip()
    if host_clean.lower() in {'localhost', 'localhost.'}:
        return True

    ip_text = host_clean.split('%', 1)[0]
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return False

    if ip.is_loopback:
        return True
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped.is_loopback
    return False


def _unwrap_model(model: Any) -> Any:
    current = model
    while isinstance(current, WrapperModel):
        current = current.wrapped
    return current


@pytest.fixture(scope='session', autouse=True)
def block_non_loopback_network() -> Generator[None]:
    """Fail any IPv4/IPv6 socket connect or connect_ex targeting a non-loopback address."""
    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex

    def guarded_connect(self: socket.socket, address: Any) -> None:
        if not _is_loopback_address(self, address):
            raise HermeticNetworkError(f'Non-loopback socket connect blocked in hermetic test suite: {address!r}')
        real_connect(self, address)

    def guarded_connect_ex(self: socket.socket, address: Any) -> int:
        if not _is_loopback_address(self, address):
            raise HermeticNetworkError(f'Non-loopback socket connect_ex blocked in hermetic test suite: {address!r}')
        return real_connect_ex(self, address)

    mp = pytest.MonkeyPatch()
    mp.setattr(socket.socket, 'connect', guarded_connect)
    mp.setattr(socket.socket, 'connect_ex', guarded_connect_ex)
    try:
        yield
    finally:
        mp.undo()


@pytest.fixture(scope='session', autouse=True)
def block_real_models() -> Generator[None]:
    """Fail any model execution other than `TestModel` / `FunctionModel`."""
    real_pick_raw_model = Agent._pick_raw_model  # pyright: ignore[reportPrivateUsage]

    def guarded_pick_raw_model(self: Any, model: Any) -> Any:
        selected = real_pick_raw_model(self, model)
        unwrapped = _unwrap_model(selected)
        if not isinstance(unwrapped, (TestModel, FunctionModel)):
            raise HermeticModelError(
                'Real model execution blocked in hermetic test suite; '
                f'inject TestModel or FunctionModel via agent.override() (got {selected!r})'
            )
        return selected

    mp = pytest.MonkeyPatch()
    mp.setattr(pydantic_ai.models, 'ALLOW_MODEL_REQUESTS', False)
    mp.setattr(Agent, '_pick_raw_model', guarded_pick_raw_model)
    try:
        yield
    finally:
        mp.undo()


@pytest.fixture(scope='session', autouse=True)
def block_telemetry_export() -> Generator[None]:
    """Configure Logfire locally and block any attempt to enable remote export."""
    real_configure = logfire.configure

    def guarded_configure(*args: Any, **kwargs: Any) -> Any:
        send_to_logfire = kwargs.get('send_to_logfire')
        if send_to_logfire is not False:
            raise HermeticTelemetryError(
                'Remote Logfire telemetry export blocked in hermetic test suite; '
                f'pass send_to_logfire=False (got send_to_logfire={send_to_logfire!r})'
            )
        return real_configure(*args, **kwargs)

    mp = pytest.MonkeyPatch()
    mp.delenv('LOGFIRE_TOKEN', raising=False)
    mp.delenv('LOGFIRE_SEND_TO_LOGFIRE', raising=False)
    real_configure(send_to_logfire=False, console=False)
    mp.setattr(logfire, 'configure', guarded_configure)
    try:
        yield
    finally:
        mp.undo()


@pytest.fixture
def in_memory_span_exporter() -> Generator[InMemorySpanExporter]:
    """Configure Logfire with an OpenTelemetry `InMemorySpanExporter` for span assertions."""
    exporter = InMemorySpanExporter()
    logfire.configure(
        send_to_logfire=False,
        console=False,
        additional_span_processors=[SimpleSpanProcessor(exporter)],
    )
    try:
        yield exporter
    finally:
        exporter.clear()
