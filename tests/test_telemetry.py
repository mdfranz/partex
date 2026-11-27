"""Default local trace log (PLAN §11.1): path resolution, JSONL span export, file mode."""

import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import logfire
import pytest
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from pydantic_ai import Agent
from pydantic_ai.models.test import TestModel

from partex.telemetry import JsonlSpanExporter, configure_telemetry, resolve_log_path


def test_default_path_is_under_the_state_dir_for_logged_commands(tmp_path: Path) -> None:
    path = resolve_log_path('agent', None, {'XDG_STATE_HOME': str(tmp_path)})
    assert path is not None and path.parent == tmp_path / 'partex' / 'logs'
    assert path.name.startswith('agent-') and path.suffix == '.jsonl'


def test_default_log_uses_the_state_override(tmp_path: Path) -> None:
    state = tmp_path / 'custom state'
    env = {'PARTEX_STATE_DIR': str(state), 'XDG_STATE_HOME': str(tmp_path / 'xdg')}
    path = resolve_log_path('agent', None, env)
    assert path is not None and path.parent == state / 'logs'


@pytest.mark.parametrize('command', ['runs', 'show', 'report', 'checks'])
def test_read_only_commands_do_not_log_by_default(command: str, tmp_path: Path) -> None:
    assert resolve_log_path(command, None, {'XDG_STATE_HOME': str(tmp_path)}) is None


def test_flag_beats_env_and_off_disables(tmp_path: Path) -> None:
    env = {'PARTEX_LOG_FILE': str(tmp_path / 'env.jsonl'), 'PARTEX_STATE_DIR': str(tmp_path / 'state')}
    assert resolve_log_path('agent', str(tmp_path / 'flag.jsonl'), env) == tmp_path / 'flag.jsonl'
    assert resolve_log_path('agent', None, env) == tmp_path / 'env.jsonl'
    assert resolve_log_path('agent', 'off', env) is None
    assert resolve_log_path('agent', None, {'PARTEX_LOG_FILE': 'OFF'}) is None
    assert (
        resolve_log_path('runs', str(tmp_path / 'x.jsonl'), {}) == tmp_path / 'x.jsonl'
    )  # explicit wins for any command


def test_spans_are_appended_as_jsonl_with_private_mode(tmp_path: Path) -> None:
    state = tmp_path / 'partex'
    path = state / 'logs' / 'run.jsonl'
    exporter = JsonlSpanExporter(path)
    logfire.configure(send_to_logfire=False, console=False, additional_span_processors=[SimpleSpanProcessor(exporter)])
    with logfire.span('outer', run='r1'):
        logfire.info('inner {x}', x=1)
    lines = [json.loads(line) for line in path.read_text().splitlines()]
    names = {line['name'] for line in lines}
    assert {'outer', 'inner {x}'} <= names
    outer = next(line for line in lines if line['name'] == 'outer')
    assert outer['attributes']['run'] == 'r1' and outer['status'] == 'UNSET' and len(outer['trace_id']) == 32
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(state.stat().st_mode) == 0o700


def test_log_file_is_created_lazily_on_the_first_span(tmp_path: Path) -> None:
    """A run that exits before emitting any span (usage error, gate refusal) leaves no empty log (#126)."""
    path = tmp_path / 'logs' / 'early-exit.jsonl'
    exporter = JsonlSpanExporter(path)
    exporter.shutdown()
    assert not path.exists() and not path.parent.exists()


def _logged_attributes(path: Path, **attributes: str) -> dict[str, Any]:
    """Emit one span with *attributes* (set through the span API, not ``**kwargs``) and read it back from *path*."""
    with logfire.span('tool') as span:
        for key, value in attributes.items():
            span.set_attribute(key, value)
    return next(json.loads(line) for line in path.read_text().splitlines())['attributes']


def test_content_is_scrubbed_by_default(tmp_path: Path) -> None:
    """Raw tool I/O can carry secrets the SDK captured itself, so the default scrubber stays on (PLAN §11.1)."""
    path = tmp_path / 'scrub.jsonl'
    configure_telemetry(log_path=path, remote=False, service_version='test')
    attributes = _logged_attributes(path, **{'gen_ai.tool.call.result': 'password=hunter2'})
    assert 'hunter2' not in attributes['gen_ai.tool.call.result']


def test_content_opt_in_keeps_tool_content_but_other_attributes_still_scrubbed(tmp_path: Path) -> None:
    """With --logfire-content, tool I/O mentioning auth/password/cookie survives; other attributes stay scrubbed."""
    path = tmp_path / 'scrub.jsonl'
    configure_telemetry(log_path=path, remote=False, service_version='test', content=True)
    attributes = _logged_attributes(
        path,
        **{'gen_ai.tool.call.result': 'auth providers: password reset, Cookie: sid=abc', 'note': 'password=hunter2'},
    )
    assert attributes['gen_ai.tool.call.result'] == 'auth providers: password reset, Cookie: sid=abc'
    assert 'Scrubbed' in attributes['note'] and 'hunter2' not in attributes['note']


async def test_agent_tool_span_secret_is_scrubbed_through_real_instrumentation(tmp_path: Path) -> None:
    """The SDK's own tool-span capture of a secret argument/result is blanked by default.

    The chat spans' message history is a separate attribute that the default scrubber does not catch;
    that is the open content-capture work (#238), not covered here.
    """
    path = tmp_path / 'agent.jsonl'
    configure_telemetry(log_path=path, remote=False, service_version='test')
    agent = Agent(TestModel(call_tools=['probe']))

    @agent.tool_plain
    def probe(token: str) -> str:  # pyright: ignore[reportUnusedFunction]
        return 'password=hunter2'

    await agent.run('go')
    spans = [json.loads(line) for line in path.read_text().splitlines()]
    tool_spans = [s for s in spans if s['attributes'].get('gen_ai.tool.name') == 'probe']
    assert tool_spans
    assert all('hunter2' not in json.dumps(s['attributes']) for s in tool_spans)


def test_suppress_unconfigured_warning_silences_noop_span_in_clean_process() -> None:
    env = {k: v for k, v in os.environ.items() if k != 'LOGFIRE_IGNORE_NO_CONFIG'}
    proc = subprocess.run(
        [
            sys.executable,
            '-W',
            'default',
            '-c',
            (
                'import logfire\n'
                'from partex.telemetry import suppress_unconfigured_warning\n'
                'suppress_unconfigured_warning()\n'
                "with logfire.span('test.noop'):\n"
                '    pass\n'
            ),
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert proc.returncode == 0
    assert 'LogfireNotConfiguredWarning' not in proc.stderr
