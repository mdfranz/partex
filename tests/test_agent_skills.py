"""Skills as deferred capabilities (issue #59): a compact catalog, load on demand, data only."""

import json
from pathlib import Path

from pydantic_ai.messages import ModelMessage, ModelRequest, ModelResponse, TextPart, ToolCallPart, ToolReturnPart
from pydantic_ai.models.function import AgentInfo, FunctionModel

from partex.agent_adapter import build_reviewer_agent, build_tester_agent
from partex.agent_adapter.skills import MAX_SKILL_CHARS, skill_capabilities, skill_text, usable_skills
from partex.agent_adapter.tools import ReviewDeps
from partex.engine import run_review
from partex.registry import build_registry, load_skill
from partex.storage import RunStore

API_INVENTORY_FIXTURE = Path(__file__).resolve().parents[1] / 'fixtures' / 'bundles' / 'api-inventory' / 'conforming'


def _write_skill(
    root: Path, name: str, *, description: str, body: str, checks: str = '', ref: str | None = None
) -> Path:
    directory = root / name
    (directory / 'reference').mkdir(parents=True)
    checks_line = f'checks: [{checks}]\n' if checks else ''
    (directory / 'SKILL.md').write_text(
        f'---\nname: {name}\ndescription: {description}\nmodes: [passive, active]\n{checks_line}---\n{body}\n'
    )
    if ref is not None:
        (directory / 'reference' / 'details.md').write_text(ref)
    return directory


def _skills(tmp_path: Path):
    _write_skill(
        tmp_path,
        'demo-playbook',
        description='Use when reviewing demo findings',
        body='# Demo\nSTEP-ONE: read the headers.\n```python\nraise SystemExit("must never run")\n```',
        ref='REFERENCE-DETAIL: severity table',
    )
    _write_skill(tmp_path, 'second-playbook', description='Use for the second thing', body='SECOND-BODY')
    skill_a, _ = load_skill(tmp_path / 'demo-playbook')
    skill_b, _ = load_skill(tmp_path / 'second-playbook')
    assert skill_a is not None and skill_b is not None
    return [skill_a, skill_b]


def test_skill_text_is_the_body_without_frontmatter_plus_references(tmp_path: Path) -> None:
    (skill, _) = _skills(tmp_path)
    text = skill_text(skill)
    assert text.startswith('# Demo') and 'name: demo-playbook' not in text
    assert 'STEP-ONE' in text and 'REFERENCE-DETAIL: severity table' in text and 'Reference: details.md' in text


def test_skill_text_is_capped(tmp_path: Path) -> None:
    _write_skill(tmp_path, 'huge', description='big', body='x' * (MAX_SKILL_CHARS * 2))
    skill, _ = load_skill(tmp_path / 'huge')
    assert skill is not None and len(skill_text(skill)) < MAX_SKILL_CHARS + 100


async def test_catalog_lists_descriptions_and_loading_discloses_the_playbook(
    tmp_path: Path, tmp_store: RunStore
) -> None:
    seen: list[tuple[str, list[str], str]] = []

    def model(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        history = ' '.join(str(getattr(part, 'content', '')) for m in messages for part in getattr(m, 'parts', []))
        seen.append((str(info.instructions), [tool.name for tool in info.function_tools], history))
        if len(seen) == 1:
            return ModelResponse(parts=[ToolCallPart('load_capability', {'id': 'demo-playbook'})])
        return ModelResponse(parts=[TextPart('ok')])

    run_id = await tmp_store.create_run(
        input_kind='bundle', input_ref='b', input_sha256='0' * 64, engine_version='0', selected_checks=['c']
    )
    agent = build_reviewer_agent(FunctionModel(model), skills=skill_capabilities(_skills(tmp_path)))
    result = await agent.run('go', deps=ReviewDeps(run_id, tmp_store))
    assert result.output == 'ok'
    first, after_load = seen[0], seen[1]
    # The catalog is compact: descriptions only, no playbook text, and the load tool is offered.
    assert 'demo-playbook: Use when reviewing demo findings' in first[0]
    assert 'second-playbook: Use for the second thing' in first[0]
    assert 'STEP-ONE' not in first[0] and 'SECOND-BODY' not in first[0] and 'load_capability' in first[1]
    # After loading, only the chosen playbook (with its reference) is in context.
    context = after_load[2]  # the loaded playbook arrives as a framed context message
    assert 'STEP-ONE' in context and 'REFERENCE-DETAIL' in context and 'SECOND-BODY' not in context
    assert 'STEP-ONE' not in first[2]


def test_agents_run_without_any_skills() -> None:
    tools = set(build_reviewer_agent('test')._function_toolset.tools)  # pyright: ignore[reportPrivateUsage]
    assert 'load_capability' not in tools  # nothing deferred: no catalog, no load tool
    build_tester_agent('test', skills=[])


def test_playbook_content_is_data_never_executed(tmp_path: Path) -> None:
    # The fenced python above raises SystemExit if anything ever evaluated it; loading must not.
    capabilities = skill_capabilities(_skills(tmp_path))
    assert [c.id for c in capabilities] == ['demo-playbook', 'second-playbook']


def test_skills_for_uninstalled_checks_stay_out_of_the_catalog(tmp_path: Path) -> None:
    _write_skill(tmp_path, 'has-check', description='d', body='b', checks='real-check')
    _write_skill(tmp_path, 'draft-only', description='d', body='b', checks='missing-check')
    _write_skill(tmp_path, 'generic', description='d', body='b')
    registry = build_registry([tmp_path], checks={'real-check': object()})
    offered = [skill.name for skill in usable_skills(registry.skills, registry.checks)]
    assert 'has-check' in offered and 'generic' in offered and 'draft-only' not in offered


def test_shipped_skills_for_installed_checks_load() -> None:
    registry = build_registry()
    names = {skill.name for skill in usable_skills(registry.skills, registry.checks)}
    assert {
        'api-inventory',
        'version-disclosure',
        'header-review',
        'js-analysis',
        'openapi-spec-review',
        'server-error',
    } <= names
    capabilities = {c.id: c for c in skill_capabilities(usable_skills(registry.skills, registry.checks))}
    assert 'version-disclosure' in capabilities and capabilities['version-disclosure'].defer_loading is True


async def test_run_chat_and_run_agent_pass_skills_through(tmp_path: Path, tmp_store: RunStore) -> None:
    import inspect

    from partex.agent_adapter import run_agent, run_chat

    for function in (run_chat, run_agent):
        assert 'skills' in inspect.signature(function).parameters


async def test_shipped_skill_session_runs_through_persisted_coverage(tmp_store: RunStore) -> None:
    """Scripted session: catalog -> load the real api-inventory playbook -> paired check's persisted coverage (#177)."""
    registry = build_registry()
    skills = [s for s in usable_skills(registry.skills, registry.checks) if s.name == 'api-inventory']
    assert [c.id for c in skill_capabilities(skills)] == ['api-inventory']
    # The paired passive check runs over the fixture evidence; a conforming bundle is clean, not skipped.
    review = await run_review(API_INVENTORY_FIXTURE, tmp_store, ['api-contract-conformance'])
    assert review.state == 'checks_complete' and review.findings == ()

    catalogs: list[str] = []

    def model(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        returns = [p for m in messages if isinstance(m, ModelRequest) for p in m.parts if isinstance(p, ToolReturnPart)]
        if not returns:
            catalogs.append(str(info.instructions))
            return ModelResponse(parts=[ToolCallPart('load_capability', {'id': 'api-inventory'}, tool_call_id='c0')])
        if len(returns) == 1:
            return ModelResponse(parts=[ToolCallPart('list_coverage', {}, tool_call_id='c1')])
        return ModelResponse(parts=[TextPart('done')])

    agent = build_reviewer_agent(FunctionModel(model), skills=skill_capabilities(skills))
    result = await agent.run('review', deps=ReviewDeps(review.run_id, tmp_store))

    assert 'api-inventory:' in catalogs[0]  # the real skill is in the catalog, playbook text is not
    assert 'Operation Inventory' not in catalogs[0]
    context = ' '.join(
        str(getattr(part, 'content', '')) for m in result.all_messages() for part in getattr(m, 'parts', [])
    )
    assert '# API Surface Inventory and Contract Conformance' in context  # loaded on demand
    coverage_return = [
        p
        for m in result.all_messages()
        if isinstance(m, ModelRequest)
        for p in m.parts
        if isinstance(p, ToolReturnPart) and p.tool_name == 'list_coverage'
    ]
    assert len(coverage_return) == 1
    start = str(coverage_return[0].content).index('[')
    rows = json.loads(str(coverage_return[0].content)[start : str(coverage_return[0].content).rindex(']') + 1])
    by_surface = {row['surface']: row for row in rows}
    stored = {row.surface: row for row in await tmp_store.coverage(review.run_id)}
    assert set(by_surface) == set(stored) and by_surface  # tool reads back exactly the persisted rows
    assert by_surface['GET /api/v2/users/me']['outcome'] == 'no_issue_found'
    assert by_surface['POST /api/v2/orders']['outcome'] == 'needs_follow_up'  # skipped != checked
    evidence_ids = {item.id for item in await tmp_store.evidence(review.run_id)}
    assert (
        by_surface['GET /api/v2/users/me']['evidence_ids']
        and set(by_surface['GET /api/v2/users/me']['evidence_ids']) <= evidence_ids
    )
