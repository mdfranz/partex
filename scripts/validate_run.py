"""Read-only post-run decision-model validator and preview (#256).

Opens a saved run strictly through ``RunReader`` (never ``RunStore``, never
``UsageRecordingModel``, never sending target traffic) and previews decision-model
assessments across:

- Skill relevance (#257) via one batched ``choose_many()`` pass
- Response classification (#261) on deduplicated HTTP captures
- Advisory finding second-opinion triage (#258) on recorded findings
"""

import argparse
import json
import os
import sys
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import anyio
import logfire

from partex import engine
from partex.agent_adapter.decide import (
    ChoiceSpec,
    DecisionOutcome,
    DecisionResult,
    DecisionRunner,
    frame_decision_excerpt,
)
from partex.cli import resolve_db_path
from partex.errors import PartexError
from partex.models import ConfigEvidence, Evidence, Finding, HttpEvidence, redact
from partex.models_config import DECISION_MODEL_ENV, DecisionModelConfig, ModelConfigError, resolve_decision_model
from partex.storage import CoverageEntry, RunReader, RunRecord
from partex.telemetry import (
    LOG_FILE_ENV,
    LOGFIRE_CONTENT_ENV,
    LOGFIRE_ENV,
    configure_telemetry,
    resolve_log_path,
    suppress_unconfigured_warning,
)

SKILL_CANDIDATES: tuple[tuple[str, str], ...] = (
    ('graphql', 'Target exposes a GraphQL endpoint (/graphql, introspection, mutations, or queries).'),
    ('authorization-testing', 'Target exposes object-ID API routes or role-scoped endpoints suited for BOLA/BFLA.'),
    ('js-analysis', 'Target serves JavaScript bundles or source maps warranting AST/secret/endpoint analysis.'),
    ('openapi-spec-review', 'Target exposes an OpenAPI/Swagger specification document.'),
    ('auth-session-controls', 'Target exposes login, OAuth, token, or session-cookie endpoints.'),
    ('header-review', 'Target returns HTML/API responses missing security headers, cookies, or CORS hardening.'),
    ('privacy-review', 'Target loads third-party analytics, trackers, or session-replay scripts.'),
    ('version-disclosure', 'Target leaks server/framework version banners or verbose error pages.'),
    ('server-error', 'Target returned HTTP 5xx responses or unhandled exception traces.'),
)

RESPONSE_CLASS_OPTIONS: dict[str, str] = {
    'normal_content': 'Expected application HTML, JSON, or API data response.',
    'error_or_stacktrace': 'Unhandled server error, traceback, or internal debug disclosure.',
    'spa_catchall': 'Single-page app HTML shell served with HTTP 200 on an unknown path.',
    'soft_404': 'HTTP 200 response whose body says the page or resource was not found.',
    'auth_gate': 'Login wall, SSO redirect, or HTTP 401/403 authentication challenge.',
    'waf_block': 'Web application firewall or bot-mitigation block page.',
}

TRIAGE_OPTIONS: dict[str, str] = {
    'likely_real': 'Captured evidence directly supports a genuine security weakness or authorization flaw.',
    'likely_benign': 'Captured evidence reflects benign behavior, documentation, or a false positive.',
}


@dataclass(frozen=True, slots=True)
class RunSnapshot:
    """Read-only snapshot of one saved run."""

    run: RunRecord
    evidence: list[Evidence]
    findings: list[Finding]
    coverage: list[CoverageEntry]


def _serialize_result(result: DecisionResult, *, threshold: float) -> dict[str, Any]:
    uncertain = result.calibrated and result.top_p is not None and result.top_p < threshold
    return {
        'outcome': result.outcome,
        'top_label': result.top_label,
        'top_p': None if result.top_p is None else round(result.top_p, 4),
        'calibrated': result.calibrated,
        'uncertain': uncertain,
        'probs': {k: round(v, 4) for k, v in result.probs.items()},
        'latency_ms': result.latency_ms,
        'error': result.error,
    }


def _deduplicated_http(evidence: Sequence[Evidence], max_items: int) -> list[HttpEvidence]:
    """Deduplicate ``HttpEvidence`` by ``(method, path, status_code, content_type)``."""
    seen: set[tuple[str, str, int, str]] = set()
    selected: list[HttpEvidence] = []
    for item in evidence:
        if not isinstance(item, HttpEvidence):
            continue
        req = item.http.request
        resp = item.http.response
        path = urlsplit(req.url).path or '/'
        ctype = ''
        for name, value in resp.headers:
            if name.lower() == 'content-type':
                ctype = value.split(';', 1)[0].strip().lower()
                break
        key = (req.method.upper(), path, resp.status_code, ctype)
        if key in seen:
            continue
        seen.add(key)
        selected.append(item)
        if len(selected) >= max_items:
            break
    return selected


def _build_discovery_summary(snapshot: RunSnapshot) -> dict[str, Any]:
    """Build a bounded, redacted surface summary for skill suggestion."""
    hosts: set[str] = set()
    endpoints: list[dict[str, Any]] = []
    seen_endpoints: set[tuple[str, str, int]] = set()
    has_cookies = False
    has_openapi = False
    has_js_artifacts = False

    for item in snapshot.evidence:
        if isinstance(item, HttpEvidence):
            redacted = redact(item)
            assert isinstance(redacted, HttpEvidence)
            req = redacted.http.request
            resp = redacted.http.response
            parsed = urlsplit(req.url)
            if parsed.netloc:
                hosts.add(parsed.netloc)
            path = parsed.path or '/'
            ep_key = (req.method.upper(), path, resp.status_code)
            if ep_key not in seen_endpoints and len(endpoints) < 30:
                seen_endpoints.add(ep_key)
                endpoints.append({'method': req.method.upper(), 'path': path, 'status': resp.status_code})
            for name, _ in resp.headers:
                if name.lower() == 'set-cookie':
                    has_cookies = True
        elif isinstance(item, ConfigEvidence):
            if 'openapi' in item.config.format.lower() or 'openapi' in item.config.path.lower():
                has_openapi = True
        else:
            if (item.artifact.content_type and 'javascript' in item.artifact.content_type.lower()) or (
                item.artifact.url.endswith('.js')
            ):
                has_js_artifacts = True

    return {
        'run_id': snapshot.run.id,
        'selected_checks': list(snapshot.run.selected_checks),
        'hosts': sorted(hosts),
        'endpoints': endpoints,
        'signals': {
            'has_set_cookie': has_cookies,
            'has_openapi_config': has_openapi,
            'has_js_artifacts': has_js_artifacts,
            'findings_count': len(snapshot.findings),
            'coverage_gaps': sum(
                1 for entry in snapshot.coverage if entry.outcome in ('not_applicable', 'needs_follow_up')
            ),
        },
    }


def _finding_context_payload(finding: Finding, evidence_by_id: dict[str, Evidence]) -> dict[str, Any]:
    """Assemble redacted finding metadata and bounded linked evidence excerpts."""
    linked: list[dict[str, Any]] = []
    for ev_id in finding.evidence_ids[:3]:
        ev = evidence_by_id.get(ev_id)
        if ev is None:
            continue
        redacted = redact(ev)
        if isinstance(redacted, HttpEvidence):
            linked.append(
                {
                    'id': redacted.id,
                    'method': redacted.http.request.method,
                    'url': redacted.http.request.url,
                    'status': redacted.http.response.status_code,
                    'headers': redacted.http.response.headers[:12],
                    'body_excerpt': (redacted.http.response.body or '')[:800],
                }
            )
        elif isinstance(redacted, ConfigEvidence):
            linked.append(
                {
                    'id': redacted.id,
                    'path': redacted.config.path,
                    'format': redacted.config.format,
                    'content_excerpt': redacted.config.content[:800],
                }
            )
        else:
            linked.append(
                {
                    'id': redacted.id,
                    'url': redacted.artifact.url,
                    'status': redacted.artifact.status_code,
                    'content_type': redacted.artifact.content_type,
                }
            )
    return {
        'id': finding.id,
        'check_id': finding.check_id,
        'severity': finding.severity,
        'subject': finding.subject,
        'title': finding.title,
        'description': finding.description[:800],
        'evidence': linked,
    }


async def load_run_snapshot(db_path: Path, run_id: str | None) -> RunSnapshot:
    """Open *db_path* read-only and load the chosen (or latest usable) run snapshot."""
    async with await RunReader.open(db_path) as reader:
        target_id = run_id
        if target_id is None:
            usable = [item for item in await reader.list_runs() if item.state != 'invalid']
            if not usable:
                raise PartexError(f'no usable runs found in {db_path}', rule_code='run-not-found')
            target_id = usable[-1].id
        run = await reader.get_run(target_id)
        evidence = await reader.evidence(target_id)
        findings = await reader.findings(target_id)
        coverage = await reader.coverage(target_id)
    return RunSnapshot(run=run, evidence=evidence, findings=findings, coverage=coverage)


async def evaluate_run_with_model(
    snapshot: RunSnapshot,
    config: DecisionModelConfig,
    *,
    threshold: float,
    max_evidence: int,
    max_findings: int,
    timeout_seconds: float,
    include_content_in_spans: bool = False,
) -> dict[str, Any]:
    """Preview skill suggestions, response classification, and finding triage for *snapshot*."""
    http_items = _deduplicated_http(snapshot.evidence, max_evidence)
    findings = snapshot.findings[:max_findings]
    max_calls = max(20, len(http_items) + len(findings) + 5)
    runner = DecisionRunner(
        config=config,
        model=config.model,
        timeout_seconds=timeout_seconds,
        max_calls=max_calls,
        include_content_in_spans=include_content_in_spans,
    )
    allow_uncalibrated = not config.calibrated

    suppress_unconfigured_warning()
    with logfire.span(
        'partex.validate',
        run_id=snapshot.run.id,
        model=config.spec,
        provider=config.provider,
        calibrated=config.calibrated,
        threshold=threshold,
        evidence_count=len(http_items),
        findings_count=len(findings),
    ):
        # 1. Skill suggestions (#257 preview) in one batched prefill pass.
        key_to_skill: dict[str, str] = {}
        skill_questions: dict[str, ChoiceSpec] = {}
        for skill_name, desc in SKILL_CANDIDATES:
            key = skill_name.replace('-', '_')
            key_to_skill[key] = skill_name
            skill_questions[key] = ChoiceSpec(
                question=f'Does the observed target surface warrant the {skill_name} playbook?',
                options={
                    'yes': f'Relevant: {desc}',
                    'no': f'Not supported by the captured surface ({skill_name} is not indicated).',
                },
            )
        discovery_context = frame_decision_excerpt(
            'discovery_summary', _build_discovery_summary(snapshot), max_chars=3000
        )
        skill_raw = await runner.choose_many(
            skill_questions,
            context=discovery_context,
            allow_uncalibrated=allow_uncalibrated,
        )
        skill_suggestions: list[dict[str, Any]] = []
        for key, res in skill_raw.items():
            skill_name = key_to_skill[key]
            p_yes = res.prob('yes')
            skill_suggestions.append(
                {
                    'skill': skill_name,
                    'p_yes': None if p_yes is None else round(p_yes, 4),
                    **_serialize_result(res, threshold=threshold),
                }
            )
        skill_suggestions.sort(
            key=lambda row: row['p_yes'] if row['p_yes'] is not None else (1.0 if row['top_label'] == 'yes' else 0.0),
            reverse=True,
        )

        # 2. Response classification (#261 preview).
        response_classes: list[dict[str, Any]] = []
        for item in http_items:
            res = await runner.choose(
                question='Which HTTP response category describes this captured exchange?',
                options=RESPONSE_CLASS_OPTIONS,
                context=frame_decision_excerpt('http_exchange', item, max_chars=2000),
                allow_uncalibrated=allow_uncalibrated,
            )
            response_classes.append(
                {
                    'evidence_id': item.id,
                    'method': item.http.request.method,
                    'url': item.http.request.url,
                    'status': item.http.response.status_code,
                    **_serialize_result(res, threshold=threshold),
                }
            )

        # 3. Finding second-opinion triage (#258 preview).
        evidence_by_id = {item.id: item for item in snapshot.evidence}
        finding_triage: list[dict[str, Any]] = []
        for finding in findings:
            payload = _finding_context_payload(finding, evidence_by_id)
            res = await runner.choose(
                question='Which triage assessment applies to this finding and its captured evidence?',
                options=TRIAGE_OPTIONS,
                context=frame_decision_excerpt('finding_evidence', payload, max_chars=3000),
                allow_uncalibrated=allow_uncalibrated,
            )
            finding_triage.append(
                {
                    'finding_id': finding.id,
                    'check_id': finding.check_id,
                    'severity': finding.severity,
                    'title': finding.title,
                    **_serialize_result(res, threshold=threshold),
                }
            )

    all_outcomes: list[DecisionOutcome] = [
        *(row['outcome'] for row in skill_suggestions),
        *(row['outcome'] for row in response_classes),
        *(row['outcome'] for row in finding_triage),
    ]
    return {
        'model': config.spec,
        'provider': config.provider,
        'calibrated': config.calibrated,
        'calls_used': runner.calls_used,
        'refusals': sum(1 for item in all_outcomes if item == 'refused'),
        'errors': sum(1 for item in all_outcomes if item in ('error', 'timeout', 'handoff')),
        'skill_suggestions': skill_suggestions,
        'response_classifications': response_classes,
        'finding_triage': finding_triage,
    }


async def validate_run(
    db_path: Path,
    run_id: str | None,
    configs: Sequence[DecisionModelConfig],
    *,
    threshold: float,
    max_evidence: int,
    max_findings: int,
    timeout_seconds: float,
    include_content_in_spans: bool = False,
) -> dict[str, Any]:
    """Load *run_id* read-only and run every configured decision model against it."""
    snapshot = await load_run_snapshot(db_path, run_id)
    run = snapshot.run
    model_intact = run.model is None or not run.model.startswith(('google-decisions:', 'openai-decisions:'))
    evaluations: list[dict[str, Any]] = []
    for cfg in configs:
        evaluations.append(
            await evaluate_run_with_model(
                snapshot,
                cfg,
                threshold=threshold,
                max_evidence=max_evidence,
                max_findings=max_findings,
                timeout_seconds=timeout_seconds,
                include_content_in_spans=include_content_in_spans,
            )
        )
    return {
        'db_path': str(db_path),
        'threshold': threshold,
        'run': {
            'id': run.id,
            'state': run.state,
            'created_at': run.created_at,
            'input_kind': run.input_kind,
            'input_ref': run.input_ref,
            'model': run.model,
            'runs_model_intact': model_intact,
            'model_calls': run.model_calls,
            'input_tokens': run.input_tokens,
            'output_tokens': run.output_tokens,
            'evidence_count': len(snapshot.evidence),
            'findings_count': len(snapshot.findings),
            'coverage_count': len(snapshot.coverage),
        },
        'evaluations': evaluations,
    }


def _fmt_prob(value: float | None, *, calibrated: bool) -> str:
    if not calibrated or value is None:
        return 'uncalibrated'
    return f'{value:.3f}'


def render_text(report: dict[str, Any]) -> str:
    """Render *report* as human-readable terminal text."""
    run = report['run']
    threshold = float(report['threshold'])
    lines = [
        f'run: {run["id"]}  state: {run["state"]}  input: {run["input_kind"]}:{run["input_ref"]}',
        (
            f'analyst model: {run["model"] or "(none)"} (runs.model intact: {run["runs_model_intact"]})  '
            f'calls={run["model_calls"]}  tokens in/out={run["input_tokens"]}/{run["output_tokens"]}'
        ),
        (
            f'saved: {run["evidence_count"]} evidence, {run["findings_count"]} findings, '
            f'{run["coverage_count"]} coverage  (read-only preview; DB unmodified)'
        ),
    ]
    for ev in report['evaluations']:
        calibrated = bool(ev['calibrated'])
        lines.append('')
        lines.append(
            f'=== {ev["model"]} (calibrated={calibrated}, calls={ev["calls_used"]}, '
            f'refusals={ev["refusals"]}, errors={ev["errors"]}) ==='
        )
        lines.append('  skill suggestions (#257 preview):')
        for row in ev['skill_suggestions']:
            p_yes = row['p_yes']
            suggested = (p_yes is not None and p_yes >= threshold) or (not calibrated and row['top_label'] == 'yes')
            mark = '*' if suggested else ' '
            p_text = _fmt_prob(p_yes, calibrated=calibrated)
            lines.append(f'    {mark} {row["skill"]:<24} top={row["top_label"] or row["outcome"]}  P(yes)={p_text}')

        lines.append(f'  response classifications (#261 preview, n={len(ev["response_classifications"])}):')
        if not ev['response_classifications']:
            lines.append('    (no HTTP exchanges)')
        for row in ev['response_classifications']:
            p_text = _fmt_prob(row['top_p'], calibrated=calibrated)
            flag = ' [uncertain]' if row['uncertain'] else ''
            lines.append(
                f'    [{row["status"]}] {row["method"]} {row["url"]} -> '
                f'{row["top_label"] or row["outcome"]} ({p_text}){flag} ({row["latency_ms"]}ms)'
            )

        lines.append(f'  finding triage (#258 advisory preview, n={len(ev["finding_triage"])}):')
        if not ev['finding_triage']:
            lines.append('    (no findings)')
        for row in ev['finding_triage']:
            p_text = _fmt_prob(row['top_p'], calibrated=calibrated)
            flag = ' [uncertain]' if row['uncertain'] else ''
            lines.append(
                f'    [{row["severity"]}] {row["finding_id"]} ({row["check_id"]}): '
                f'{row["top_label"] or row["outcome"]} ({p_text}){flag} — {row["title"]}'
            )
    return '\n'.join(lines) + '\n'


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description='Read-only post-run validator previewing decision-model outputs over a saved run (#256).'
    )
    parser.add_argument('run_id', nargs='?', default=None, help='run ID (run_...); defaults to latest usable run')
    parser.add_argument('--db', type=Path, default=None, help='SQLite database path (default: PARTEX_DB or state dir)')
    parser.add_argument(
        '-D',
        '--decision-model',
        action='append',
        default=[],
        help='decision model spec (repeatable; defaults to PARTEX_DECISION_MODEL or google-decisions:gemini-decision-1)',
    )
    parser.add_argument(
        '-t',
        '--threshold',
        type=float,
        default=0.75,
        help='confidence threshold below which calibrated answers are marked uncertain (default: 0.75)',
    )
    parser.add_argument('--max-evidence', type=int, default=10, help='max deduplicated HTTP exchanges to classify')
    parser.add_argument('--max-findings', type=int, default=20, help='max findings to triage')
    parser.add_argument('--timeout', type=float, default=15.0, help='per-call timeout in seconds (default: 15.0)')
    parser.add_argument(
        '--logfire', action='store_true', help=f'send telemetry traces to Logfire (or set {LOGFIRE_ENV}=1)'
    )
    parser.add_argument(
        '--logfire-content',
        action='store_true',
        help=f'keep prompts and evidence excerpts out of the secret scrubber in traces (or set {LOGFIRE_CONTENT_ENV}=1)',
    )
    parser.add_argument(
        '--log-file', default=None, help=f'write traces to a local JSONL file, or "off" (or set {LOG_FILE_ENV})'
    )
    parser.add_argument('--json', action='store_true', help='print JSON report to stdout')
    parser.add_argument('-o', '--out', type=Path, default=None, help='write full JSON report to PATH')
    args = parser.parse_args(argv)

    if not 0.0 <= args.threshold <= 1.0:
        print(f'validate_run: --threshold must be between 0 and 1, got {args.threshold}', file=sys.stderr)
        return 2
    if args.max_evidence < 0 or args.max_findings < 0 or args.timeout <= 0:
        print('validate_run: --max-evidence/--max-findings must be >= 0 and --timeout > 0', file=sys.stderr)
        return 2

    specs = list(args.decision_model)
    if not specs:
        env_spec = (os.environ.get(DECISION_MODEL_ENV) or '').strip()
        specs = [env_spec] if env_spec else ['google-decisions:gemini-decision-1']

    try:
        configs = [resolve_decision_model(spec) for spec in specs]
    except ModelConfigError as exc:
        print(f'validate_run: {exc}', file=sys.stderr)
        return 1

    remote = bool(args.logfire) or os.environ.get(LOGFIRE_ENV) == '1'
    log_path = resolve_log_path('validate', args.log_file)
    content = bool(args.logfire_content) or os.environ.get(LOGFIRE_CONTENT_ENV) == '1'
    if remote or log_path is not None:
        configure_telemetry(
            log_path=log_path,
            remote=remote,
            service_version=engine.engine_version(),
            content=content,
        )
    else:
        suppress_unconfigured_warning()

    db_path = args.db if args.db is not None else resolve_db_path(None)
    try:
        report = anyio.run(
            lambda: validate_run(
                db_path,
                args.run_id,
                configs,
                threshold=float(args.threshold),
                max_evidence=int(args.max_evidence),
                max_findings=int(args.max_findings),
                timeout_seconds=float(args.timeout),
                include_content_in_spans=content,
            )
        )
    except PartexError as exc:
        print(f'validate_run: {exc.rule_code or "error"}: {exc}', file=sys.stderr)
        return 1

    if args.out is not None:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2, sort_keys=True, default=asdict) + '\n', encoding='utf-8')
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True, default=asdict))
    else:
        sys.stdout.write(render_text(report))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
