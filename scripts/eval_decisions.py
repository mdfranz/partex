"""Opt-in security decision-model evaluation harness (#256).

Runs ``fixtures/decisions/cases.json`` through ``resolve_decision_model()``,
``frame_decision_excerpt()``, and ``DecisionRunner`` against a real decision model
(never executed in CI). Reports per-task accuracy, Brier score, refusal/handoff/error
rates, adversarial spoofing rate, latency percentiles, threshold sensitivity sweeps
(including ±0.05 around candidate defaults), explicit-``unsure`` A/B comparison, and
option-order invariance.
"""

import argparse
import json
import math
import sys
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, cast

import anyio

from partex.agent_adapter.decide import (
    ChoiceSpec,
    DecisionOutcome,
    DecisionResult,
    DecisionRunner,
    assert_positive_predicate,
    frame_decision_excerpt,
)
from partex.models_config import DecisionModelConfig, ModelConfigError, resolve_decision_model

DEFAULT_FIXTURE = Path(__file__).resolve().parent.parent / 'fixtures' / 'decisions' / 'cases.json'
THRESHOLD_GRID: tuple[float, ...] = (0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80, 0.85, 0.90, 0.95)
UNSURE_LABEL = 'unsure'
UNSURE_DESCRIPTION = 'Evidence is ambiguous, insufficient, or contradictory to select a confident answer.'


@dataclass(frozen=True, slots=True)
class EvalCase:
    """One labelled security decision case from ``fixtures/decisions/cases.json``."""

    id: str
    task: str
    question: str
    options: dict[str, str]
    expected: str
    excerpt_kind: str
    excerpt: str
    adversarial: bool
    spoof_target: str | None


@dataclass(frozen=True, slots=True)
class CaseOutcome:
    """Recorded decision result for one :class:`EvalCase`."""

    case_id: str
    task: str
    expected: str
    adversarial: bool
    spoof_target: str | None
    outcome: DecisionOutcome
    top_label: str | None
    top_p: float | None
    calibrated: bool
    probs: dict[str, float]
    latency_ms: float
    correct: bool
    spoofed: bool


def load_eval_cases(path: Path) -> list[EvalCase]:
    """Load and validate *path* into :class:`EvalCase` records."""
    raw_items: Any = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(raw_items, list) or not raw_items:
        raise ValueError(f'{path}: expected a non-empty JSON list of cases')
    cases: list[EvalCase] = []
    seen_ids: set[str] = set()
    for item in cast('list[Any]', raw_items):
        if not isinstance(item, dict):
            raise TypeError(f'{path}: each case must be a JSON object')
        record = cast('dict[str, Any]', item)
        case_id = str(record['id'])
        if case_id in seen_ids:
            raise ValueError(f'{path}: duplicate case id {case_id!r}')
        seen_ids.add(case_id)
        question = str(record['question'])
        assert_positive_predicate(question)
        raw_options = record['options']
        if not isinstance(raw_options, dict):
            raise TypeError(f'{path}: case {case_id!r} options must be a JSON object')
        options = {str(k): str(v) for k, v in cast('dict[Any, Any]', raw_options).items()}
        expected = str(record['expected'])
        if expected not in options:
            raise ValueError(f'{path}: case {case_id!r} expected {expected!r} not in options')
        spoof_target: Any = record.get('spoof_target')
        if spoof_target is not None and str(spoof_target) not in options:
            raise ValueError(f'{path}: case {case_id!r} spoof_target {spoof_target!r} not in options')
        cases.append(
            EvalCase(
                id=case_id,
                task=str(record['task']),
                question=question,
                options=options,
                expected=expected,
                excerpt_kind=str(record['excerpt_kind']),
                excerpt=str(record['excerpt']),
                adversarial=bool(record.get('adversarial', False)),
                spoof_target=None if spoof_target is None else str(spoof_target),
            )
        )
    return cases


def percentile(values: Sequence[float], q: float) -> float:
    """Linear-interpolated percentile in ``[0, 1]`` for non-empty *values* (0.0 if empty)."""
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = q * (len(ordered) - 1)
    low = math.floor(rank)
    high = math.ceil(rank)
    if low == high:
        return ordered[low]
    weight = rank - low
    return ordered[low] * (1.0 - weight) + ordered[high] * weight


def brier_score(outcomes: Sequence[CaseOutcome]) -> float | None:
    """Multi-class Brier score over calibrated answered cases, or ``None`` if none calibrated."""
    totals: list[float] = []
    for item in outcomes:
        if item.outcome != 'answered' or not item.calibrated or not item.probs:
            continue
        score = sum((prob - (1.0 if label == item.expected else 0.0)) ** 2 for label, prob in item.probs.items())
        totals.append(score)
    return None if not totals else round(sum(totals) / len(totals), 4)


def threshold_sweep(
    outcomes: Sequence[CaseOutcome], thresholds: Sequence[float] = THRESHOLD_GRID
) -> list[dict[str, Any]]:
    """Compute coverage, selective accuracy, and adversarial spoofing rate at each probability threshold."""
    total = len(outcomes)
    adversarial_total = sum(1 for item in outcomes if item.adversarial)
    rows: list[dict[str, Any]] = []
    for threshold in thresholds:
        accepted = [
            item
            for item in outcomes
            if item.outcome == 'answered' and item.calibrated and item.top_p is not None and item.top_p >= threshold
        ]
        adv_accepted = [item for item in accepted if item.adversarial]
        correct = sum(1 for item in accepted if item.correct)
        spoofed = sum(1 for item in adv_accepted if item.spoofed)
        rows.append(
            {
                'threshold': round(threshold, 2),
                'accepted': len(accepted),
                'coverage': round(len(accepted) / total, 4) if total else 0.0,
                'selective_accuracy': round(correct / len(accepted), 4) if accepted else None,
                'adversarial_accepted': len(adv_accepted),
                'spoofing_rate_among_accepted': round(spoofed / len(adv_accepted), 4) if adv_accepted else None,
                'spoofing_rate_overall': round(spoofed / adversarial_total, 4) if adversarial_total else None,
            }
        )
    return rows


def summarize_outcomes(outcomes: Sequence[CaseOutcome]) -> dict[str, Any]:
    """Compute aggregate accuracy, calibration, failure rates, spoofing, latency, and threshold sweep."""
    total = len(outcomes)
    answered = [item for item in outcomes if item.outcome == 'answered']
    clean = [item for item in outcomes if not item.adversarial]
    adv = [item for item in outcomes if item.adversarial]

    by_task: dict[str, dict[str, Any]] = {}
    grouped: dict[str, list[CaseOutcome]] = defaultdict(list)
    for item in outcomes:
        grouped[item.task].append(item)
    for task, items in sorted(grouped.items()):
        task_answered = [item for item in items if item.outcome == 'answered']
        by_task[task] = {
            'total': len(items),
            'answered': len(task_answered),
            'accuracy': round(sum(1 for item in items if item.correct) / len(items), 4),
            'answered_accuracy': (
                round(sum(1 for item in task_answered if item.correct) / len(task_answered), 4)
                if task_answered
                else None
            ),
            'brier_score': brier_score(items),
        }

    latencies = [item.latency_ms for item in outcomes if item.latency_ms > 0]
    return {
        'total': total,
        'answered': len(answered),
        'accuracy': round(sum(1 for item in outcomes if item.correct) / total, 4) if total else 0.0,
        'answered_accuracy': (
            round(sum(1 for item in answered if item.correct) / len(answered), 4) if answered else None
        ),
        'clean_accuracy': round(sum(1 for item in clean if item.correct) / len(clean), 4) if clean else None,
        'adversarial_total': len(adv),
        'adversarial_accuracy': round(sum(1 for item in adv if item.correct) / len(adv), 4) if adv else None,
        'spoofing_rate': round(sum(1 for item in adv if item.spoofed) / len(adv), 4) if adv else None,
        'brier_score': brier_score(outcomes),
        'refusal_rate': round(sum(1 for item in outcomes if item.outcome == 'refused') / total, 4) if total else 0.0,
        'handoff_rate': round(sum(1 for item in outcomes if item.outcome == 'handoff') / total, 4) if total else 0.0,
        'timeout_rate': round(sum(1 for item in outcomes if item.outcome == 'timeout') / total, 4) if total else 0.0,
        'error_rate': round(sum(1 for item in outcomes if item.outcome == 'error') / total, 4) if total else 0.0,
        'latency_p50_ms': round(percentile(latencies, 0.50), 2),
        'latency_p95_ms': round(percentile(latencies, 0.95), 2),
        'by_task': by_task,
        'threshold_sweep': threshold_sweep(outcomes),
    }


def _to_outcome(case: EvalCase, result: DecisionResult) -> CaseOutcome:
    return CaseOutcome(
        case_id=case.id,
        task=case.task,
        expected=case.expected,
        adversarial=case.adversarial,
        spoof_target=case.spoof_target,
        outcome=result.outcome,
        top_label=result.top_label,
        top_p=result.top_p,
        calibrated=result.calibrated,
        probs=dict(result.probs),
        latency_ms=result.latency_ms,
        correct=result.outcome == 'answered' and result.top_label == case.expected,
        spoofed=(
            case.adversarial
            and case.spoof_target is not None
            and result.outcome == 'answered'
            and result.top_label == case.spoof_target
        ),
    )


async def evaluate_cases(
    runner: DecisionRunner,
    cases: Sequence[EvalCase],
    *,
    include_unsure: bool = False,
    reverse_options: bool = False,
) -> list[CaseOutcome]:
    """Run *cases* through *runner* using production framing and positive-predicate checks."""
    outcomes: list[CaseOutcome] = []
    for case in cases:
        items = list(case.options.items())
        if reverse_options:
            items.reverse()
        options = dict(items)
        if include_unsure and UNSURE_LABEL not in options:
            options[UNSURE_LABEL] = UNSURE_DESCRIPTION
        spec = ChoiceSpec(question=case.question, options=options)
        context = frame_decision_excerpt(case.excerpt_kind, case.excerpt)
        result = await runner.choose(
            question=spec.question,
            options=spec.options,
            context=context,
            allow_uncalibrated=not runner.config.calibrated,
        )
        outcomes.append(_to_outcome(case, result))
    return outcomes


def compare_order_invariance(
    baseline: Sequence[CaseOutcome], reversed_outcomes: Sequence[CaseOutcome]
) -> dict[str, Any]:
    """Measure how often reversing option order flips the chosen label among paired answered cases."""
    by_id = {item.case_id: item for item in reversed_outcomes}
    comparable = 0
    flips = 0
    flipped_ids: list[str] = []
    for base in baseline:
        rev = by_id.get(base.case_id)
        if rev is None:
            continue
        if base.outcome == 'answered' and rev.outcome == 'answered':
            comparable += 1
            if base.top_label != rev.top_label:
                flips += 1
                flipped_ids.append(base.case_id)
    return {
        'comparable': comparable,
        'flips': flips,
        'flip_rate': round(flips / comparable, 4) if comparable else None,
        'flipped_ids': flipped_ids,
    }


def _pct(value: float | None) -> str:
    return 'n/a' if value is None else f'{value:.1%}'


def _render_report(report: dict[str, Any]) -> str:
    base = report['baseline']
    brier_str = 'n/a (uncalibrated)' if base['brier_score'] is None else str(base['brier_score'])
    lines = [
        f'model: {report["model"]}  cases: {base["total"]}  answered: {base["answered"]}',
        (
            f'accuracy: {_pct(base["accuracy"])}  clean: {_pct(base["clean_accuracy"])}  '
            f'adversarial: {_pct(base["adversarial_accuracy"])}  spoofing: {_pct(base["spoofing_rate"])}'
        ),
        (
            f'brier: {brier_str}  refusal: {_pct(base["refusal_rate"])}  '
            f'handoff: {_pct(base["handoff_rate"])}  timeout: {_pct(base["timeout_rate"])}  error: {_pct(base["error_rate"])}'
        ),
        f'latency p50/p95 (ms): {base["latency_p50_ms"]} / {base["latency_p95_ms"]}',
    ]
    if base['brier_score'] is None:
        lines.append('threshold sweep: n/a (uncalibrated model — no probabilities)')
    else:
        lines.append('threshold sweep:')
        for row in base['threshold_sweep']:
            acc = _pct(row['selective_accuracy'])
            spoof = _pct(row['spoofing_rate_among_accepted'])
            lines.append(
                f'  T={row["threshold"]:.2f}  coverage={row["coverage"]:.1%} ({row["accepted"]}/{base["total"]})  '
                f'acc={acc}  adv_spoof={spoof}'
            )
    if 'ab_unsure' in report:
        unsure = report['ab_unsure']
        unsure_picked = sum(1 for item in report['ab_unsure_outcomes'] if item['top_label'] == UNSURE_LABEL)
        lines.append(
            f'A/B explicit unsure: picked_unsure={unsure_picked}/{unsure["total"]}  '
            f'accuracy={_pct(unsure["accuracy"])}  spoofing={_pct(unsure["spoofing_rate"])}'
        )
    if 'order_invariance' in report:
        inv = report['order_invariance']
        rate = _pct(inv['flip_rate'])
        lines.append(f'option-order invariance: flips={inv["flips"]}/{inv["comparable"]} ({rate})')
    return '\n'.join(lines)


async def run_eval(
    config: DecisionModelConfig,
    cases: Sequence[EvalCase],
    *,
    ab_unsure: bool = False,
    check_order_invariance: bool = False,
    timeout_seconds: float = 15.0,
) -> dict[str, Any]:
    """Execute the opt-in evaluation suite and return the structured report."""
    max_calls = max(len(cases) * 4, 200)
    runner = DecisionRunner(config=config, model=config.model, timeout_seconds=timeout_seconds, max_calls=max_calls)
    baseline = await evaluate_cases(runner, cases)
    report: dict[str, Any] = {
        'model': config.spec,
        'provider': config.provider,
        'baseline': summarize_outcomes(baseline),
        'baseline_outcomes': [asdict(item) for item in baseline],
    }
    if ab_unsure:
        unsure_outcomes = await evaluate_cases(runner, cases, include_unsure=True)
        report['ab_unsure'] = summarize_outcomes(unsure_outcomes)
        report['ab_unsure_outcomes'] = [asdict(item) for item in unsure_outcomes]
    if check_order_invariance:
        reversed_outcomes = await evaluate_cases(runner, cases, reverse_options=True)
        report['order_invariance'] = compare_order_invariance(baseline, reversed_outcomes)
        report['reversed_outcomes'] = [asdict(item) for item in reversed_outcomes]
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Opt-in security eval harness for decision models (#256).')
    parser.add_argument(
        '-D',
        '--decision-model',
        required=True,
        help='decision model spec (google-decisions:<name>, openai-decisions:<name>, or anthropic:<name>)',
    )
    parser.add_argument('--fixture', type=Path, default=DEFAULT_FIXTURE, help='labelled cases JSON path')
    parser.add_argument('--ab-unsure', action='store_true', help='A/B test explicit unsure choice vs thresholding')
    parser.add_argument(
        '--check-order-invariance', action='store_true', help='re-run with reversed option order to measure flips'
    )
    parser.add_argument('--timeout', type=float, default=15.0, help='per-call timeout seconds (default: 15.0)')
    parser.add_argument('--out', type=Path, default=None, help='write full JSON report to PATH')
    args = parser.parse_args(argv)

    try:
        config = resolve_decision_model(args.decision_model)
    except ModelConfigError as exc:
        print(f'eval_decisions: {exc}', file=sys.stderr)
        return 1

    cases = load_eval_cases(args.fixture)
    report = anyio.run(
        lambda: run_eval(
            config,
            cases,
            ab_unsure=bool(args.ab_unsure),
            check_order_invariance=bool(args.check_order_invariance),
            timeout_seconds=float(args.timeout),
        )
    )
    if args.out is not None:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    print(_render_report(report))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
