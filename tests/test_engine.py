"""Tests for the passive engine path — PLAN §6, §6.1, §7.1."""

import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from partex.bundle import load_bundle
from partex.engine import (
    MAX_DRAFTS_PER_CHECK,
    CheckSelectionError,
    default_workers,
    engine_version,
    installed_checks,
    run_review,
    select_passive_checks,
)
from partex.ids import finding_id
from partex.models import Evidence, FindingDraft
from partex.storage import RunStore

FIXTURES = Path(__file__).resolve().parents[1] / 'fixtures' / 'bundles'
VALID = FIXTURES / 'valid'
MALFORMED = FIXTURES / 'malformed'


# ── fake checks ───────────────────────────────────────────────────────────────


@dataclass
class FakeCheck:
    """A passive check whose behaviour is a function of the evidence it receives."""

    check_id: str
    behaviour: Callable[[Sequence[Evidence]], Any] = lambda _: ()
    applies: bool = True
    version: str = '1'
    title: str = 'fake'
    description: str = 'fake check'
    delay: float = 0.0
    calls: list[str] = field(default_factory=list[str])

    def applies_to(self, evidence: Sequence[Evidence]) -> bool:
        self.calls.append('applies_to')
        return self.applies

    def review(self, evidence: Sequence[Evidence]) -> Any:
        self.calls.append('review')
        time.sleep(self.delay)
        return self.behaviour(evidence)


def _draft(check_id: str, evidence: Sequence[Evidence], title: str = 'Issue', **over: Any) -> FindingDraft:
    return FindingDraft.model_validate(
        {
            'check_id': check_id,
            'check_version': '1',
            'severity': 'low',
            'subject': 'thing',
            'title': title,
            'description': 'd',
            'evidence_ids': [evidence[0].id],
            'remediation': 'r',
        }
        | over
    )


def _finds(check_id: str, *titles: str) -> Callable[[Sequence[Evidence]], list[FindingDraft]]:
    return lambda ev: [_draft(check_id, ev, title) for title in titles]


def _boom(_: Sequence[Evidence]) -> Any:
    raise KeyError('missing header')


class ActiveOnly:
    check_id = 'active-only'
    version = '1'

    def probe(self, *_: object) -> list[FindingDraft]:  # pragma: no cover — never called
        return []


# ── real check, valid fixture ─────────────────────────────────────────────────


async def test_header_security_review_end_to_end(tmp_store: RunStore):
    result = await run_review(VALID, tmp_store, ['header-security'])

    assert result.state == 'checks_complete'
    assert (result.error, result.failed_check, result.skipped_checks) == (None, None, ())
    assert result.evidence_count == 6
    assert result.findings, 'the valid fixture exercises every header-security finding class'
    assert {f.check_id for f in result.findings} == {'header-security'}
    assert {f.status for f in result.findings} == {'reported'}

    run = await tmp_store.get_run(result.run_id)
    assert (run.state, run.input_kind, run.input_ref) == ('checks_complete', 'bundle', str(VALID))
    assert run.input_sha256 == load_bundle(VALID).fingerprint
    assert run.engine_version == engine_version()
    assert run.selected_checks == ('header-security',)
    assert run.findings_count == len(result.findings)
    assert await tmp_store.findings(result.run_id) == list(result.findings)
    assert [e.id for e in await tmp_store.evidence(result.run_id)] == [e.id for e in load_bundle(VALID).evidence]


async def test_passive_results_are_deterministic_across_stores(tmp_path: Path):
    async with await RunStore.open(tmp_path / 'a.db') as a, await RunStore.open(tmp_path / 'b.db') as b:
        first = await run_review(VALID, a, ['header-security'])
        second = await run_review(VALID, b, ['header-security'])
    assert first.findings == second.findings
    assert first.run_id != second.run_id


def test_installed_checks_include_builtins():
    registry = installed_checks()
    assert 'header-security' in registry
    assert registry['header-security'].check_id == 'header-security'


def test_default_workers_is_bounded():
    assert 1 <= default_workers() <= 4


# ── selection (usage errors: no run row) ──────────────────────────────────────


@pytest.mark.parametrize(
    ('selection', 'rule'),
    [([], 'empty-selection'), (['nope', 'a'], 'unknown-check'), (['active-only'], 'not-passive')],
)
async def test_bad_selection_creates_no_run(tmp_store: RunStore, selection: list[str], rule: str):
    registry = {'a': FakeCheck('a'), 'active-only': ActiveOnly()}
    with pytest.raises(CheckSelectionError) as exc:
        await run_review(VALID, tmp_store, selection, registry=registry)
    assert exc.value.rule_code == rule
    assert await tmp_store.list_runs() == []


def test_unknown_check_lists_available():
    with pytest.raises(CheckSelectionError, match=r'unknown check\(s\): x; available: a, b'):
        select_passive_checks({'b': FakeCheck('b'), 'a': FakeCheck('a')}, ['x'])
    with pytest.raises(CheckSelectionError, match=r'\(none installed\)'):
        select_passive_checks({}, ['x'])


async def test_workers_must_be_positive(tmp_store: RunStore):
    with pytest.raises(CheckSelectionError) as exc:
        await run_review(VALID, tmp_store, ['a'], registry={'a': FakeCheck('a')}, workers=0)
    assert exc.value.rule_code == 'workers'


async def test_selection_is_ordered_and_deduplicated(tmp_store: RunStore):
    registry = {'a': FakeCheck('a', _finds('a', 'A')), 'b': FakeCheck('b', _finds('b', 'B'))}
    result = await run_review(VALID, tmp_store, ['b', 'a', 'b'], registry=registry)
    assert result.selected_checks == ('b', 'a')
    assert [f.check_id for f in result.findings] == ['b', 'a']
    assert (await tmp_store.get_run(result.run_id)).selected_checks == ('b', 'a')


# ── invalid input ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize('case', sorted(p.name for p in MALFORMED.iterdir()))
async def test_invalid_bundle_is_recorded_and_runs_no_checks(tmp_store: RunStore, case: str):
    check = FakeCheck('a', _boom)
    result = await run_review(MALFORMED / case, tmp_store, ['a'], registry={'a': check})

    rule = case.split('--')[0]
    assert (result.state, result.rule_code) == ('invalid', rule)
    assert result.error is not None and result.error.startswith(f'{rule}: ')
    assert check.calls == []
    run = await tmp_store.get_run(result.run_id)
    assert (run.state, run.error, run.input_sha256) == ('invalid', result.error, '')
    assert await tmp_store.evidence(result.run_id) == []


async def test_bundle_warnings_are_reported(tmp_store: RunStore):
    # The valid fixture suggests header-security, which this registry doesn't have (V6).
    result = await run_review(VALID, tmp_store, ['a'], registry={'a': FakeCheck('a')})
    assert result.warnings == ("bundle.json: suggested check 'header-security' is not registered; dropped",)


# ── check failures publish nothing ────────────────────────────────────────────


async def test_raising_check_fails_run_and_publishes_nothing(tmp_store: RunStore):
    registry = {'ok': FakeCheck('ok', _finds('ok', 'Fine')), 'bad': FakeCheck('bad', _boom)}
    result = await run_review(VALID, tmp_store, ['ok', 'bad'], registry=registry)

    assert (result.state, result.failed_check, result.rule_code) == ('checks_failed', 'bad', 'check-failed')
    assert result.error == "bad: raised KeyError: 'missing header'"
    assert result.findings == ()
    run = await tmp_store.get_run(result.run_id)
    assert (run.state, run.error, run.findings_count) == ('checks_failed', result.error, 0)
    assert await tmp_store.evidence(result.run_id) == []


async def test_earliest_failure_in_selection_order_is_reported(tmp_store: RunStore):
    registry = {'slow-bad': FakeCheck('slow-bad', _boom, delay=0.05), 'fast-bad': FakeCheck('fast-bad', _boom)}
    result = await run_review(VALID, tmp_store, ['slow-bad', 'fast-bad'], registry=registry, workers=2)
    assert result.failed_check == 'slow-bad'


def _many(check_id: str) -> Callable[[Sequence[Evidence]], list[FindingDraft]]:
    return lambda ev: [_draft(check_id, ev, f'T{i}') for i in range(MAX_DRAFTS_PER_CHECK + 1)]


@pytest.mark.parametrize(
    ('behaviour', 'message'),
    [
        pytest.param(lambda ev: None, 'returned NoneType', id='none'),
        pytest.param(lambda ev: 'oops', 'returned str', id='string'),
        pytest.param(lambda ev: {'not': 'a list'}, 'returned dict', id='mapping'),
        pytest.param(_many('c'), f'{MAX_DRAFTS_PER_CHECK + 1} drafts', id='too-many'),
        pytest.param(lambda ev: [_draft('other', ev)], "claims check_id 'other'", id='wrong-check-id'),
        pytest.param(lambda ev: [_draft('c', ev, check_version='2')], "claims check_version '2'", id='wrong-version'),
        pytest.param(lambda ev: [_draft('c', ev, evidence_ids=['ev_nope'])], 'unregistered evidence', id='dangling'),
        pytest.param(
            lambda ev: [_draft('c', ev).model_dump() | {'severity': 'catastrophic'}],
            'draft 0 is invalid',
            id='severity',
        ),
        pytest.param(
            lambda ev: [_draft('c', ev).model_dump() | {'evidence_ids': []}], 'draft 0 is invalid', id='no-evidence'
        ),
        pytest.param(lambda ev: [42], 'draft 0 is invalid', id='not-a-draft'),
    ],
)
async def test_bad_drafts_fail_the_check(
    tmp_store: RunStore, behaviour: Callable[[Sequence[Evidence]], Any], message: str
):
    result = await run_review(VALID, tmp_store, ['c'], registry={'c': FakeCheck('c', behaviour)})
    assert (result.state, result.failed_check) == ('checks_failed', 'c')
    assert result.error is not None and message in result.error
    assert (await tmp_store.get_run(result.run_id)).findings_count == 0


async def test_exactly_the_draft_limit_is_accepted(tmp_store: RunStore):
    behaviour = lambda ev: [_draft('c', ev, f'T{i}') for i in range(MAX_DRAFTS_PER_CHECK)]
    result = await run_review(VALID, tmp_store, ['c'], registry={'c': FakeCheck('c', behaviour)})
    assert len(result.findings) == MAX_DRAFTS_PER_CHECK


# ── drafts → findings ─────────────────────────────────────────────────────────


async def test_dict_drafts_accepted_and_ids_assigned_by_engine(tmp_store: RunStore):
    behaviour = lambda ev: [_draft('c', ev, 'From dict').model_dump()]
    result = await run_review(VALID, tmp_store, ['c'], registry={'c': FakeCheck('c', behaviour)})
    (finding,) = result.findings
    assert finding.id == finding_id('c', 'thing', 'From dict', finding.evidence_ids)
    assert (finding.status, finding.verification_id) == ('reported', None)


async def test_duplicate_drafts_collapse_to_one_finding(tmp_store: RunStore):
    result = await run_review(
        VALID, tmp_store, ['c'], registry={'c': FakeCheck('c', _finds('c', 'Same', 'Same', 'Other'))}
    )
    assert [f.title for f in result.findings] == ['Same', 'Other']


async def test_distinct_subjects_with_same_title_and_evidence_are_kept(tmp_store: RunStore):
    """Two cookies on one response: same title and evidence, different subjects — both persist (#39)."""
    behaviour = lambda ev: [_draft('c', ev, 'Weak cookie', subject=f'cookie:{name}') for name in ('a', 'b')]
    result = await run_review(VALID, tmp_store, ['c'], registry={'c': FakeCheck('c', behaviour)})
    assert sorted(f.subject for f in result.findings) == ['cookie:a', 'cookie:b']
    assert len({f.id for f in result.findings}) == 2


async def test_inapplicable_check_is_skipped(tmp_store: RunStore):
    skipped = FakeCheck('skip', _boom, applies=False)
    registry = {'skip': skipped, 'c': FakeCheck('c', _finds('c', 'X'))}
    result = await run_review(VALID, tmp_store, ['skip', 'c'], registry=registry)
    assert (result.state, result.skipped_checks) == ('checks_complete', ('skip',))
    assert skipped.calls == ['applies_to']
    assert [f.check_id for f in result.findings] == ['c']


async def test_check_with_no_findings_completes(tmp_store: RunStore):
    result = await run_review(VALID, tmp_store, ['c'], registry={'c': FakeCheck('c')})
    assert (result.state, result.findings) == ('checks_complete', ())
    assert (await tmp_store.get_run(result.run_id)).state == 'checks_complete'


# ── order independence (§7.1, experiment 13.3 c) ──────────────────────────────


async def test_worker_count_and_completion_order_do_not_change_results(tmp_path: Path):
    def registry() -> dict[str, FakeCheck]:
        # Earlier checks are slower, so with parallel workers they complete in reverse order.
        return {
            f'c{i}': FakeCheck(f'c{i}', _finds(f'c{i}', f'T{i}a', f'T{i}b'), delay=0.02 * (5 - i)) for i in range(5)
        }

    selection = [f'c{i}' for i in range(5)]
    async with await RunStore.open(tmp_path / 'serial.db') as serial, await RunStore.open(tmp_path / 'par.db') as par:
        one = await run_review(VALID, serial, selection, registry=registry(), workers=1)
        eight = await run_review(VALID, par, selection, registry=registry(), workers=8)
        assert one.findings == eight.findings
        assert [f.check_id for f in one.findings] == [c for c in selection for _ in range(2)]
        assert await serial.findings(one.run_id) == await par.findings(eight.run_id)
