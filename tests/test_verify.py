"""Verification runner — PLAN §8 verify, §13.4 verification (issue #22).

The full probe → verify → replay loop against the local fixture app: the
banner variant verifies ``confirmed``, the hardened variant (no version
digits, clean 404s) yields ``not_reproduced``, and an unreachable target
yields ``inconclusive`` with the finding keeping its status.  In every
case the original evidence and the finding remain readable.
"""

import importlib.util
from collections.abc import Iterator, Sequence
from pathlib import Path

import pytest

from partex.checks.version_disclosure import version_disclosure_check
from partex.engine import run_test
from partex.errors import PartexError, ValidationFailed
from partex.models import Finding, HttpEvidence, VerificationRecipe, VerificationRequest
from partex.storage import RunStore
from partex.verify import run_verification

_TARGET_APP = Path(__file__).parent.parent / 'fixtures' / 'target_app' / 'app.py'


@pytest.fixture
def target_app() -> Iterator[object]:
    """The fixture app on an ephemeral port; toggle ``server.hardened`` to fix the target."""
    spec = importlib.util.spec_from_file_location('partex_fixture_target_app_verify', _TARGET_APP)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    server = module.make_server()  # pyright: ignore[reportAttributeAccessIssue]
    thread = module.serve_thread(server)  # pyright: ignore[reportAttributeAccessIssue]
    try:
        yield server
    finally:
        server.shutdown()  # pyright: ignore[reportAttributeAccessIssue]
        server.server_close()  # pyright: ignore[reportAttributeAccessIssue]
        thread.join(timeout=5)


async def make_run(tmp_path: Path, store: RunStore, server: object, **scope: object) -> tuple[str, list[Finding]]:
    """Run the live probe against the fixture app and return (run_id, findings)."""
    import json

    port = server.port  # pyright: ignore[reportAttributeAccessIssue]
    base_url = server.base_url  # pyright: ignore[reportAttributeAccessIssue]
    scope_data: dict[str, object] = {
        'hosts': ['127.0.0.1'],
        'path_prefixes': ['/'],
        'exclusions': ['/admin/shutdown'],
        'ports': [port],
        'max_rps': 64,
        'max_requests': 100,
    }
    scope_data.update(scope)
    directory = tmp_path / 'engagement'
    directory.mkdir(exist_ok=True)
    (directory / 'engagement.json').write_text(
        json.dumps(
            {
                'schema_version': 1,
                'target': {'name': 'fixture-app', 'base_url': base_url},
                'scope': scope_data,
                'authorization': {'attestation': 'local fixture app on loopback', 'operator': 'test'},
                'suggested_checks': ['version-disclosure'],
            }
        )
    )
    result = await run_test(directory, store, ['version-disclosure'], authorized=True)
    assert result.state == 'checks_complete'
    assert result.findings
    return result.run_id, list(result.findings)


def banner_finding(findings: list[Finding]) -> Finding:
    return next(finding for finding in findings if finding.subject.startswith('header:'))


def error_finding(findings: list[Finding]) -> Finding:
    return next(finding for finding in findings if finding.subject == 'error-page')


# ── confirmed: the banner still reproduces ────────────────────────────────────


async def test_banner_finding_verifies_confirmed(target_app: object, tmp_path: Path, tmp_store: RunStore) -> None:
    run_id, findings = await make_run(tmp_path, tmp_store, target_app)
    result = await run_verification(run_id, banner_finding(findings).id, tmp_store, authorized=True)
    assert result.verdict == 'confirmed'
    assert result.finding_status == 'verified'
    assert result.replay_evidence_ids  # the replay exchange is cited
    assert 'still exhibits' in result.detail
    # The original evidence and the finding both remain readable.  Replay
    # evidence is content-addressed (PLAN §12): an unchanged target may yield
    # the same `ev_` id — either way it resolves in the store.
    original = banner_finding(findings)
    stored = await tmp_store.get_finding(run_id, original.id)
    assert stored is not None and stored.status == 'verified'
    for evidence_id in original.evidence_ids:
        assert await tmp_store.get_evidence(run_id, evidence_id) is not None
    for evidence_id in result.replay_evidence_ids:
        assert await tmp_store.get_evidence(run_id, evidence_id) is not None


async def test_error_page_finding_verifies_confirmed(target_app: object, tmp_path: Path, tmp_store: RunStore) -> None:
    run_id, findings = await make_run(tmp_path, tmp_store, target_app)
    result = await run_verification(run_id, error_finding(findings).id, tmp_store, authorized=True)
    assert result.verdict == 'confirmed'
    assert result.finding_status == 'verified'


# ── not_reproduced: the hardened variant fixed the leak ──────────────────────


async def test_hardened_target_yields_not_reproduced(target_app: object, tmp_path: Path, tmp_store: RunStore) -> None:
    run_id, findings = await make_run(tmp_path, tmp_store, target_app)
    target_app.hardened = True  # pyright: ignore[reportAttributeAccessIssue]
    result = await run_verification(run_id, banner_finding(findings).id, tmp_store, authorized=True)
    assert result.verdict == 'not_reproduced'
    assert result.finding_status == 'verification_failed'
    # The finding is never deleted and stays readable with its history.
    stored = await tmp_store.get_finding(run_id, banner_finding(findings).id)
    assert stored is not None and stored.status == 'verification_failed'
    verifications = await tmp_store.verifications(run_id)
    assert any(v.verdict == 'not_reproduced' for v in verifications)


# ── inconclusive: no response, finding keeps its status ──────────────────────


async def test_unreachable_target_is_inconclusive_and_keeps_status(
    target_app: object, tmp_path: Path, tmp_store: RunStore
) -> None:
    run_id, findings = await make_run(tmp_path, tmp_store, target_app)
    target_app.shutdown()  # pyright: ignore[reportAttributeAccessIssue]
    target_app.server_close()  # pyright: ignore[reportAttributeAccessIssue]
    result = await run_verification(run_id, banner_finding(findings).id, tmp_store, authorized=True)
    assert result.verdict == 'inconclusive'
    assert result.finding_status == 'reported'  # the skill's replay table: inconclusive stays reported
    stored = await tmp_store.get_finding(run_id, banner_finding(findings).id)
    assert stored is not None and stored.status == 'reported'
    verifications = await tmp_store.verifications(run_id)
    assert any(v.verdict == 'inconclusive' for v in verifications)


# ── Gates and errors ─────────────────────────────────────────────────────────


async def test_verify_requires_authorized(target_app: object, tmp_path: Path, tmp_store: RunStore) -> None:
    run_id, findings = await make_run(tmp_path, tmp_store, target_app)
    with pytest.raises(ValidationFailed) as excinfo:
        await run_verification(run_id, banner_finding(findings).id, tmp_store, authorized=False)
    assert excinfo.value.rule_code == 'unauthorized'
    assert len(target_app.requests) == 3  # pyright: ignore[reportAttributeAccessIssue] — only the probes ran


async def test_unknown_finding_errors(target_app: object, tmp_path: Path, tmp_store: RunStore) -> None:
    run_id, _ = await make_run(tmp_path, tmp_store, target_app)
    with pytest.raises(PartexError, match='not found'):
        await run_verification(run_id, 'fn_missing', tmp_store, authorized=True)


async def test_recipeless_check_is_reported_only(target_app: object, tmp_path: Path, tmp_store: RunStore) -> None:
    run_id, findings = await make_run(tmp_path, tmp_store, target_app)
    original = banner_finding(findings)

    class Recipeless:
        check_id = 'version-disclosure'

        def verify_recipe(self, finding: Finding, evidence: list[object]) -> None:
            return None

    with pytest.raises(PartexError, match='reported-only'):
        await run_verification(
            run_id, original.id, tmp_store, authorized=True, registry={'version-disclosure': Recipeless()}
        )


async def test_runner_hands_every_replay_to_the_matcher(
    target_app: object, tmp_path: Path, tmp_store: RunStore
) -> None:
    """Every captured replay reaches ``verify_match_all`` — the verdict never rests on the lead alone (#176)."""
    run_id, findings = await make_run(tmp_path, tmp_store, target_app)
    banner = banner_finding(findings)

    class TwoResends:
        """A multi-request recipe: the same banner re-send twice, so two replays are captured."""

        check_id = 'version-disclosure'

        def __init__(self) -> None:
            self.seen: list[HttpEvidence] = []

        def verify_recipe(self, finding: Finding, evidence: list[object]) -> VerificationRecipe | None:
            exchanges = [item for item in evidence if isinstance(item, HttpEvidence)]
            request = VerificationRequest(method='GET', path=exchanges[0].http.request.url)
            return VerificationRecipe(description='re-send the banner twice', requests=[request, request])

        def verify_match_all(self, finding: Finding, original: HttpEvidence, replays: Sequence[HttpEvidence]) -> bool:
            self.seen = list(replays)
            return any(version_disclosure_check.verify_match(finding, original, replay) for replay in replays)

    recorder = TwoResends()
    result = await run_verification(
        run_id, banner.id, tmp_store, authorized=True, registry={'version-disclosure': recorder}
    )
    assert result.verdict == 'confirmed'
    assert len(recorder.seen) == 2  # both replays were handed over, not just the first
    assert result.replay_evidence_ids  # both are cited on the verification either way


async def test_checks_without_verify_match_all_keep_single_replay_semantics(
    target_app: object, tmp_path: Path, tmp_store: RunStore
) -> None:
    """A check predating the multi-replay seam is matched on its first replay, as before (#176)."""
    run_id, findings = await make_run(tmp_path, tmp_store, target_app)
    banner = banner_finding(findings)

    class OldStyle:
        """Only the single-replay seam — no ``verify_match_all``."""

        check_id = 'version-disclosure'

        def __init__(self) -> None:
            self.matched: list[HttpEvidence] = []

        def verify_recipe(self, finding: Finding, evidence: list[object]) -> VerificationRecipe | None:
            return version_disclosure_check.verify_recipe(
                finding, [item for item in evidence if isinstance(item, HttpEvidence)]
            )

        def verify_match(self, finding: Finding, original: HttpEvidence, replay: HttpEvidence) -> bool:
            self.matched.append(replay)
            return version_disclosure_check.verify_match(finding, original, replay)

    old_style = OldStyle()
    result = await run_verification(
        run_id, banner.id, tmp_store, authorized=True, registry={'version-disclosure': old_style}
    )
    assert result.verdict == 'confirmed'
    assert len(old_style.matched) == 1  # the fallback still matches — once, on the first replay


async def test_replay_runs_inside_the_recorded_scope(target_app: object, tmp_path: Path, tmp_store: RunStore) -> None:
    """The engagement on disk can change; the replay still honors the snapshot."""
    import json

    run_id, findings = await make_run(tmp_path, tmp_store, target_app)
    original = banner_finding(findings)
    directory = tmp_path / 'engagement'
    manifest = json.loads((directory / 'engagement.json').read_text())
    manifest['scope']['exclusions'].append('/')  # a post-run re-scope would break the replay
    (directory / 'engagement.json').write_text(json.dumps(manifest))
    result = await run_verification(run_id, original.id, tmp_store, authorized=True)
    assert result.verdict == 'confirmed'  # snapshot, not the mutated file, governs
