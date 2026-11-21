"""Default local trace log (PLAN §11.1): path resolution, JSONL span export, file mode."""

import json
import stat
from pathlib import Path

import logfire
import pytest
from opentelemetry.sdk.trace.export import SimpleSpanProcessor

from partex.telemetry import JsonlSpanExporter, resolve_log_path


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
