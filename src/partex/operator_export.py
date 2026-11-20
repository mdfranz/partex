"""Operator-only exports to disk — issue #88.

``/report`` writes a Markdown report from the *redacted* export payload. ``/secrets`` writes the secret
values partex redacts everywhere else (JavaScript secret candidates re-extracted from stored artifacts, and
the ``secret_fields`` values of captured HTTP evidence) to a ``0600`` file. Neither is reachable by the model:
they run from operator slash commands, and the command results contain paths and counts, never a value.
"""

import os
import re
import warnings
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .checks.js_analysis import analyze_js_bytes, iter_js_sources
from .export import ExportStore, IncludeSecretsWarning, export_run_data
from .models import HttpEvidence, parse_secret_path
from .storage import RunStore

_HEADER_VALUE = re.compile(r'^\$\.http\.(request|response)\.headers\[(\d+)\]\[1\]$')


def exports_dir(db_path: Path) -> Path:
    """Directory beside *db_path* for operator exports (mode 0700, files 0600)."""
    return db_path.parent / f'{db_path.name}.exports'


def _write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.name.endswith('.exports'):
        os.chmod(path.parent, 0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as handle:
        handle.write(text)
    os.chmod(path, 0o600)


def _cell(value: object) -> str:
    return str(value).replace('|', '\\|').replace('\n', ' ')


def render_markdown_report(payload: dict[str, Any], run_id: str) -> str:
    """A Markdown report from an export payload (redacted unless the caller built it otherwise)."""
    run = payload['run']
    findings: list[dict[str, Any]] = payload['findings']
    lines = [
        f'# Partex report: {run_id}',
        '',
        f'- State: **{run["state"]}**   Engine: {run["engine_version"]}',
        f'- Input: `{run["input_kind"]}:{run["input_ref"]}`',
        (
            f'- Checks: {", ".join(run["selected_checks"]) or "none"}   Evidence: {len(payload["evidence"])}   '
            f'Requests spent: {run["requests_spent"]}'
        ),
    ]
    scope = run.get('scope_snapshot')
    if scope:
        lines.append(
            f'- Scope: hosts {", ".join(scope["hosts"])}; ports {", ".join(map(str, scope["ports"])) or "defaults"}'
        )
    if run['error']:
        lines.append(f'- Error: {run["error"]}')
    calls: list[dict[str, Any]] = payload['tool_calls']
    if any(call['tool'] == 'tls_verify_disabled' for call in calls):
        lines.append('- **TLS certificate verification was disabled for this run.**')
    for call in calls:
        if call['tool'] == 'scope_amend':
            lines.append(f'- Scope extended by the operator: {call["args"].get("spec", "?")}')

    lines += ['', '## Findings', '']
    if not findings:
        lines.append('No findings.')
    else:
        counts: dict[str, int] = {}
        for finding in findings:
            counts[finding['severity']] = counts.get(finding['severity'], 0) + 1
        lines.append('Severity: ' + ', '.join(f'{count} {severity}' for severity, count in counts.items()))
        lines += ['', '| Severity | Title | Subject | Status | ID | Evidence |', '|---|---|---|---|---|---|']
        for f in findings:
            lines.append(
                f'| {f["severity"]} | {_cell(f["title"])} | {_cell(f["subject"])} | {f["status"]} | {f["id"]} | '
                f'{", ".join(f["evidence_ids"])} |'
            )
        for f in findings:
            lines += ['', f'### {f["title"]} ({f["severity"]})', '', f'`{f["id"]}`  subject: {f["subject"]}', '']
            lines += [f['description'], '', f'**Remediation:** {f["remediation"]}']
    for verification in payload['verifications']:
        lines += [
            '',
            f'Verification {verification["id"]}: **{verification["verdict"]}** for {verification["finding_id"]}',
        ]

    evidence: list[dict[str, Any]] = payload['evidence']
    lines += ['', '## Evidence', '', '| ID | Kind | Detail |', '|---|---|---|']
    for item in evidence:
        if item['kind'] == 'http_exchange':
            exchange = item['http']
            detail = (
                f'{exchange["request"]["method"]} {exchange["request"]["url"]} -> {exchange["response"]["status_code"]}'
            )
        elif item['kind'] == 'artifact':
            detail = f'{item["artifact"]["url"]} ({item["artifact"]["size_bytes"]} bytes, sha256 {item["artifact"]["sha256"][:12]})'
        else:
            detail = item.get('config', {}).get('path', '')
        lines.append(f'| {item["id"]} | {item["kind"]} | {_cell(detail)} |')

    coverage: list[dict[str, Any]] = payload['coverage']
    if coverage:
        lines += ['', '## Coverage', '']
        lines += [f'- {c["surface"]} / {c["risk_area"]}: {c["status"]}' for c in coverage]
    if payload['summary'] is not None:
        lines += ['', '## Summary', '', payload['summary']['narrative']]
    lines += ['', '_Secrets are redacted in this report._', '']
    return '\n'.join(lines)


@dataclass(frozen=True, slots=True)
class ExportResult:
    path: Path
    findings: int = 0
    evidence: int = 0
    js_secrets: int = 0
    evidence_secrets: int = 0


async def write_report(store: ExportStore, run_id: str, dest: Path) -> ExportResult:
    """Write the Markdown report for *run_id* to *dest* (``0600``); returns the path and counts only."""
    payload = await export_run_data(store, run_id, include_secrets=False)
    _write_private(dest, render_markdown_report(payload, run_id))
    return ExportResult(dest, findings=len(payload['findings']), evidence=len(payload['evidence']))


def _walk(container: Any, parts: Sequence[str | int]) -> Any:
    for part in parts:
        container = container[part]
    return container


async def write_secrets(store: RunStore, run_id: str, dest: Path) -> ExportResult:
    """Write the unredacted secret values of *run_id* to *dest* (``0600``); returns the path and counts only."""
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', IncludeSecretsWarning)
        evidence = await store.evidence(run_id)

    lines = [
        f'# Secrets for {run_id}',
        '',
        (
            '**UNREDACTED. Real credentials from the target, written for the operator. Do not commit, paste into '
            'chat, or share. Handle like any credential and rotate what is real.**'
        ),
        '',
        '## Candidates found in JavaScript',
        '',
        '| Source | Key or kind | Line | Value |',
        '|---|---|---|---|',
    ]
    js_count = 0
    for evidence_id, url, data in iter_js_sources(evidence):
        seen: set[tuple[int, str]] = set()  # a key-named value that also looks like a token is one secret
        for key, line, value in analyze_js_bytes(data).secret_values:
            if (line, value) in seen:
                continue
            seen.add((line, value))
            lines.append(f'| {_cell(url)} ({evidence_id}) | {_cell(key)} | {line} | `{_cell(value)}` |')
            js_count += 1
    if not js_count:
        lines.append('| none | | | |')

    lines += [
        '',
        '## Secret-marked fields in captured HTTP evidence',
        '',
        '| Evidence | Where | Name | Value |',
        '|---|---|---|---|',
    ]
    field_count = 0
    for item in evidence:
        if not isinstance(item, HttpEvidence):
            continue
        dump = item.model_dump(mode='json')
        for path in item.secret_fields:
            try:
                value = _walk(dump, parse_secret_path(path))
            except KeyError, IndexError, TypeError, ValueError:
                continue
            if not isinstance(value, str) or not value:
                continue
            name, where = path, path
            if match := _HEADER_VALUE.match(path):
                which, index = match.group(1), int(match.group(2))
                name = str(dump['http'][which]['headers'][index][0])
                where = f'{which} header'
            lines.append(f'| {item.id} | {_cell(where)} | {_cell(name)} | `{_cell(value)}` |')
            field_count += 1
    if not field_count:
        lines.append('| none | | | |')
    lines.append('')
    _write_private(dest, '\n'.join(lines))
    return ExportResult(dest, evidence=len(evidence), js_secrets=js_count, evidence_secrets=field_count)
