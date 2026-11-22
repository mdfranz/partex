"""Bundle surface → live probe seeding — the capture→probe bridge (issue #76; PLAN §17.5 Q5).

Unit tests pin the planner as a pure function (extraction, dedup, drops, cap, determinism, and
the no-captured-secrets rule), live tests run the whole bridge against the loopback fixture
app: a run's captures are exported (#28), and a second engagement seeded from that bundle
reaches the routes the first run discovered — through the same scoped client, never a replay.
"""

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest
from pydantic_ai import Agent
from pydantic_ai.models.test import TestModel

from partex import engine
from partex.agent_adapter import TesterDeps, run_agent
from partex.bundle import MANIFEST_NAME, load_bundle
from partex.errors import ValidationFailed
from partex.har_io import export_bundle
from partex.ids import evidence_id
from partex.models import Engagement, HttpEvidence, HttpExchange, HttpRequest, HttpResponse
from partex.probes import ProbeCandidate, plan_seed_probes, seed_lines
from partex.storage import RunStore

FIXTURES = Path(__file__).parent.parent / 'fixtures'
VALID_BUNDLE = FIXTURES / 'bundles' / 'valid'
SECRET = 'Bearer probe-seed-secret-token'

# tmp_store comes from the root conftest's pytest_plugins; target_app from plugins.target_app.


# ── Helpers ───────────────────────────────────────────────────────────────────


def engagement_for(base_url: str, **scope: Any) -> Engagement:
    """A validated engagement model for *base_url* with an optional scope override."""
    data: dict[str, Any] = {
        'hosts': [base_url.split('//', 1)[1].split(':', 1)[0]],
        'path_prefixes': ['/'],
        'ports': [],
        'max_rps': 64,
        'max_requests': 100,
    }
    data.update(scope)
    return Engagement.model_validate(
        {
            'schema_version': 1,
            'target': {'name': 'target', 'base_url': base_url},
            'scope': data,
            'authorization': {'attestation': 'local fixture app on loopback', 'operator': 'test'},
        }
    )


def engagement_dir(tmp_path: Path, base_url: str, port: int, **scope: Any) -> Path:
    scope_data: dict[str, Any] = {
        'hosts': ['127.0.0.1'],
        'path_prefixes': ['/'],
        'exclusions': ['/admin/shutdown'],
        'ports': [port],
        'max_rps': 64,
        'max_requests': 100,
    }
    scope_data.update(scope)
    directory = tmp_path / 'engagement'
    directory.mkdir(parents=True)
    (directory / 'engagement.json').write_text(
        json.dumps(
            {
                'schema_version': 1,
                'target': {'name': 'fixture-app', 'base_url': base_url},
                'scope': scope_data,
                'authorization': {'attestation': 'local fixture app on loopback', 'operator': 'test'},
            }
        )
    )
    return directory


def write_bundle(root: Path, exchanges: Sequence[HttpEvidence]) -> Path:
    """A hand-written valid bundle from evidence records (ids and sources derived)."""
    evidence_dir = root / 'evidence'
    evidence_dir.mkdir(parents=True)
    names: list[str] = []
    for index, item in enumerate(exchanges, start=1):
        name = f'evidence/{index:04d}.json'
        record = item.model_dump(mode='json', exclude={'id', 'source'})
        (root / name).write_text(json.dumps(record))
        names.append(name)
    (root / MANIFEST_NAME).write_text(
        json.dumps(
            {
                'schema_version': 1,
                'target': {'name': 'target', 'base_url': 'https://app.example.test'},
                'evidence_files': names,
            }
        )
    )
    return root


def make_exchange(
    url: str, method: str = 'GET', headers: list[tuple[str, str]] | None = None, status: int = 200
) -> HttpEvidence:
    request = HttpRequest(method=method, url=url, headers=headers or [('Host', 'app.example.test')])
    evidence = HttpEvidence(
        id='',
        source='capture:test',
        http=HttpExchange(
            request=request,
            response=HttpResponse(status_code=status, headers=[('Content-Type', 'text/plain')], body='ok'),
        ),
    )
    return evidence.model_copy(update={'id': evidence_id(evidence)})


# ── Planner: a pure function of (bundle, engagement) ────────────────────────


def test_plan_extracts_methods_urls_and_query_strings() -> None:
    bundle = load_bundle(VALID_BUNDLE)
    plan = plan_seed_probes(bundle, engagement_for('https://app.example.test'))
    assert plan.candidates == (
        ProbeCandidate(method='GET', url='https://app.example.test/', source_id=plan.candidates[0].source_id),
        ProbeCandidate(method='GET', url='https://app.example.test/account', source_id=plan.candidates[1].source_id),
        ProbeCandidate(method='GET', url='https://app.example.test/login', source_id=plan.candidates[2].source_id),
        ProbeCandidate(method='GET', url='https://app.example.test/dashboard', source_id=plan.candidates[3].source_id),
        ProbeCandidate(method='GET', url='https://app.example.test/api/health', source_id=plan.candidates[4].source_id),
    )
    assert plan.dropped_total == 0


def test_plan_is_deterministic() -> None:
    bundle = load_bundle(VALID_BUNDLE)
    engagement = engagement_for('https://app.example.test')
    assert plan_seed_probes(bundle, engagement) == plan_seed_probes(bundle, engagement)


def test_plan_drops_are_counted_never_silent(tmp_path: Path) -> None:
    exchanges = [
        make_exchange('https://app.example.test/a?x=1'),  # kept, query preserved
        make_exchange(
            'https://app.example.test/a?x=1', status=404
        ),  # same (method, URL), different content → planner duplicate
        make_exchange('https://app.example.test/b', method='POST'),  # method drop
        make_exchange('https://other.example.test/c'),  # out of scope
        make_exchange('https://app.example.test/d'),  # kept
        make_exchange('https://app.example.test/e'),  # kept
    ]
    bundle = load_bundle(write_bundle(tmp_path / 'bundle', exchanges))
    assert len(bundle.evidence) == 6  # distinct content survived the loader's own V3 dedup
    plan = plan_seed_probes(bundle, engagement_for('https://app.example.test'), limit=2)
    assert [c.url for c in plan.candidates] == ['https://app.example.test/a?x=1', 'https://app.example.test/d']
    assert plan.dropped_duplicates == 1
    assert plan.dropped_methods == 1
    assert plan.dropped_out_of_scope == 1
    assert plan.dropped_capped == 1
    assert plan.dropped_total == 4


def test_plan_against_a_narrower_engagement_scope(tmp_path: Path) -> None:
    """The capture's origin scope is not the engagement's: /api-only drops the rest."""
    exchanges = [
        make_exchange('https://app.example.test/api/v1/users'),
        make_exchange('https://app.example.test/login'),
    ]
    bundle = load_bundle(write_bundle(tmp_path / 'bundle', exchanges))
    plan = plan_seed_probes(
        bundle, engagement_for('https://app.example.test', path_prefixes=['/api'], exclusions=['/api/v1/users'])
    )
    assert plan.candidates == ()
    assert plan.dropped_out_of_scope == 2  # outside prefixes, and inside exclusions


def test_candidates_never_carry_captured_credentials(tmp_path: Path) -> None:
    """Cookie/Authorization values from the capture stay in secret_fields, never in candidates."""
    exchanges = [
        make_exchange(
            'https://app.example.test/',
            headers=[('Cookie', f'session={SECRET}'), ('Authorization', SECRET), ('Host', 'app.example.test')],
        )
    ]
    exchanges[0] = exchanges[0].model_copy(
        update={
            'secret_fields': ['$.http.request.headers[0][1]', '$.http.request.headers[1][1]'],
        }
    )
    bundle = load_bundle(write_bundle(tmp_path / 'bundle', exchanges))
    plan = plan_seed_probes(bundle, engagement_for('https://app.example.test'))
    assert len(plan.candidates) == 1
    assert SECRET not in repr(plan), 'a captured secret leaked into the plan'
    assert seed_lines(plan) == ('GET https://app.example.test/',)


# ── run_test seeding: the live bridge over the fixture app ───────────────────


async def test_exported_run_seeds_a_second_engagement(target_app: Any, tmp_store: RunStore, tmp_path: Path) -> None:
    """Live test → export-bundle (#28) → seed a new engagement → reach the discovered routes."""
    base_url = target_app.base_url  # pyright: ignore[reportUnknownMemberType]
    port = target_app.port  # pyright: ignore[reportUnknownMemberType]
    first = await engine.run_test(
        engagement_dir(tmp_path / 'one', base_url, port),
        tmp_store,
        ['version-disclosure'],
        authorized=True,
    )
    assert first.state == 'checks_complete'
    exported = tmp_path / 'exported-bundle'
    await export_bundle(tmp_store, first.run_id, exported)

    second = await engine.run_test(
        engagement_dir(tmp_path / 'two', base_url, port),
        tmp_store,
        ['version-disclosure'],
        authorized=True,
        seed_bundle=exported,
    )
    assert second.state == 'checks_complete'
    assert second.seed_plan is not None
    assert second.seeded_count == len(second.seed_plan.candidates)
    assert second.seed_skipped == 0  # candidates are pre-filtered with the same gate

    # Coverage: the seeded run's requests reached every route the first run discovered.
    evidence = await tmp_store.evidence(second.run_id)
    seeded_urls = {item.http.request.url for item in evidence if isinstance(item, HttpEvidence)}
    first_urls = {
        item.http.request.url for item in await tmp_store.evidence(first.run_id) if isinstance(item, HttpEvidence)
    }
    assert first_urls
    assert first_urls <= seeded_urls
    assert second.seed_plan.dropped_total == 0


async def test_seeding_ends_cleanly_when_the_budget_runs_out(
    target_app: Any, tmp_store: RunStore, tmp_path: Path
) -> None:
    base_url = target_app.base_url  # pyright: ignore[reportUnknownMemberType]
    port = target_app.port  # pyright: ignore[reportUnknownMemberType]
    seed_bundle = write_bundle(
        tmp_path / 'bundle',
        [make_exchange(f'{base_url}/path{i}') for i in range(5)],
    )
    result = await engine.run_test(
        engagement_dir(tmp_path / 'eng', base_url, port, max_requests=3),
        tmp_store,
        ['version-disclosure'],
        authorized=True,
        seed_bundle=seed_bundle,
    )
    assert result.state == 'checks_complete'  # rule 5: exhaustion is not failure
    assert result.budget_exhausted
    assert result.seeded_count == 2  # baseline took 1 of 3; two seeds fit
    assert result.seed_plan is not None and len(result.seed_plan.candidates) == 5


async def test_passive_checks_review_seeded_evidence(target_app: Any, tmp_store: RunStore, tmp_path: Path) -> None:
    """#51 made live runs passive-reviewed: seeded exchanges must reach the passive checks."""
    base_url = target_app.base_url  # pyright: ignore[reportUnknownMemberType]
    port = target_app.port  # pyright: ignore[reportUnknownMemberType]
    seed_bundle = write_bundle(
        tmp_path / 'bundle',
        [make_exchange(f'{base_url}/'), make_exchange(f'{base_url}/robots.txt')],
    )
    result = await engine.run_test(
        engagement_dir(tmp_path / 'eng', base_url, port),
        tmp_store,
        ['header-security'],
        authorized=True,
        seed_bundle=seed_bundle,
    )
    assert result.state == 'checks_complete'
    assert result.seeded_count == 2
    xcto = [f for f in result.findings if f.title == 'Missing X-Content-Type-Options header']
    assert xcto, 'the fixture app sends no X-Content-Type-Options; the seeded paths must be flagged'
    evidence = {item.id for item in await tmp_store.evidence(result.run_id)}  # pyright: ignore[reportUnknownMemberType]
    assert set(xcto[0].evidence_ids) <= evidence


async def test_seeded_requests_never_carry_captured_secrets(
    target_app: Any, tmp_store: RunStore, tmp_path: Path
) -> None:
    """The acceptance pin: a bundle full of credentials seeds a run that transmits none of them."""
    base_url = target_app.base_url  # pyright: ignore[reportUnknownMemberType]
    port = target_app.port  # pyright: ignore[reportUnknownMemberType]
    exchanges = [
        make_exchange(
            f'{base_url}/',
            headers=[('Cookie', f'session={SECRET}'), ('Authorization', SECRET), ('Host', '127.0.0.1')],
        )
    ]
    exchanges[0] = exchanges[0].model_copy(
        update={'secret_fields': ['$.http.request.headers[0][1]', '$.http.request.headers[1][1]']}
    )
    seed_bundle = write_bundle(tmp_path / 'bundle', exchanges)
    result = await engine.run_test(
        engagement_dir(tmp_path / 'eng', base_url, port),
        tmp_store,
        ['version-disclosure'],
        authorized=True,
        seed_bundle=seed_bundle,
    )
    assert result.state == 'checks_complete'
    assert result.seeded_count == 1
    evidence = await tmp_store.evidence(result.run_id)
    for item in evidence:
        assert SECRET not in item.model_dump_json(), 'a captured secret reached the wire or the store'


async def test_a_bad_seed_bundle_fails_the_run_as_invalid(target_app: Any, tmp_store: RunStore, tmp_path: Path) -> None:
    base_url = target_app.base_url  # pyright: ignore[reportUnknownMemberType]
    port = target_app.port  # pyright: ignore[reportUnknownMemberType]
    broken = tmp_path / 'broken-bundle'
    broken.mkdir()
    (broken / MANIFEST_NAME).write_text('not json')
    result = await engine.run_test(
        engagement_dir(tmp_path / 'eng', base_url, port),
        tmp_store,
        ['version-disclosure'],
        authorized=True,
        seed_bundle=broken,
    )
    assert result.state == 'invalid'
    assert result.rule_code == 'bundle-parse'
    assert result.seed_plan is None


# ── partex agent --bundle: read-only surface in the session ──────────────────


async def test_agent_bundle_exposes_the_surface_read_only(
    target_app: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The session gets the plan as context + an audit row; nothing is sent automatically."""
    import partex.agent_adapter

    base_url = target_app.base_url  # pyright: ignore[reportUnknownMemberType]
    port = target_app.port  # pyright: ignore[reportUnknownMemberType]
    # A path the active check never probes, so any request to it could only come from auto-seeding.
    seeded_path = f'{base_url}/seeded-by-nobody'
    seed_bundle = write_bundle(tmp_path / 'bundle', [make_exchange(seeded_path)])

    seen: dict[str, Any] = {}

    async def fake_chat(agent: Agent[TesterDeps, str], **kwargs: Any) -> None:
        seen['deps'] = kwargs['deps']
        seen['usage_limits'] = kwargs['usage_limits']

    monkeypatch.setattr(partex.agent_adapter, 'chat', fake_chat)
    db = tmp_path / 'agent.db'
    run_id = await run_agent(
        engagement_dir(tmp_path / 'eng', base_url, port),
        db,
        TestModel(),
        authorized=True,
        checks=('version-disclosure',),
        bundle=seed_bundle,
        briefing=False,
        request_limit=120,
    )

    assert seen['usage_limits'].request_limit == 120
    deps = seen['deps']
    assert deps.seed_surface == (f'GET {seeded_path}',)
    async with await RunStore.open(db) as store:
        calls = [c for c in await store.tool_calls(run_id) if c.tool == 'seed_surface']
        assert len(calls) == 1
        assert calls[0].result['paths'] == [f'GET {seeded_path}']
        # Read-only: the session's own baseline and check probes exist, the seeded path does not.
        evidence = [item.http.request.url for item in await store.evidence(run_id) if isinstance(item, HttpEvidence)]
        assert evidence
        assert seeded_path not in evidence
        assert evidence[0] == base_url  # the baseline capture


async def test_agent_unknown_bundle_fails_before_any_store_or_socket(tmp_path: Path) -> None:
    from partex.errors import PartexError

    with pytest.raises((ValidationFailed, PartexError)):
        await run_agent(
            engagement_dir(tmp_path / 'eng', 'http://127.0.0.1:1', 1),
            tmp_path / 'agent.db',
            TestModel(),
            authorized=True,
            bundle=tmp_path / 'nope-bundle',
            briefing=False,
        )
