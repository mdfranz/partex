"""Registry: entry-point discovery, skills-as-data, frontmatter lint, and the §13.2 separation experiment."""

import json
import shutil
import sys
from collections.abc import Iterator
from pathlib import Path
from textwrap import dedent

import pytest

from partex import cli
from partex.registry import build_registry, builtin_skill_root, load_skill, load_skills

ROOT = Path(__file__).parent.parent
FIXTURE_SKILLS = ROOT / 'fixtures' / 'skills'
PLUGIN_SRC = Path(__file__).parent / 'plugins' / 'banner_leak_ep'


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    code = cli.main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def write_skill(root: Path, dirname: str, frontmatter: str, body: str = 'body\n') -> Path:
    directory = root / dirname
    directory.mkdir(parents=True)
    (directory / 'SKILL.md').write_text(f'---\n{dedent(frontmatter).strip()}\n---\n{body}')
    return directory


def rules(directory: Path) -> set[str]:
    _, diagnostics = load_skill(directory)
    return {d.rule for d in diagnostics if d.level == 'error'}


# ── Lint ──────────────────────────────────────────────────────────────────────


def test_staged_and_builtin_skills_lint_clean() -> None:
    skills, diagnostics = load_skills([builtin_skill_root()])
    assert [d for d in diagnostics if d.level == 'error'] == []
    assert {'api-inventory', 'authorization-testing', 'auth-session-controls', 'header-review'} <= set(skills)
    assert 'version-disclosure' in skills


def test_fixture_skill_lints_clean() -> None:
    _, diagnostics = load_skills([FIXTURE_SKILLS])
    assert diagnostics == []


def test_valid_skill_parsed(tmp_path: Path) -> None:
    directory = write_skill(
        tmp_path, 'my-skill', 'name: my-skill\ndescription: d\nmodes: [passive, active]\nchecks: [a, a, b]'
    )
    skill, diagnostics = load_skill(directory)
    assert diagnostics == [] and skill is not None
    assert (skill.modes, skill.checks) == (('passive', 'active'), ('a', 'b'))


@pytest.mark.parametrize(
    ('dirname', 'frontmatter', 'rule'),
    [
        ('my-skill', 'name: other\ndescription: d\nmodes: [passive]', 'name-mismatch'),
        ('my-skill', 'description: d\nmodes: [passive]', 'name-missing'),
        ('My_Skill', 'name: My_Skill\ndescription: d\nmodes: [passive]', 'name-not-kebab'),
        ('my-skill', 'name: my-skill\nmodes: [passive]', 'description-missing'),
        ('my-skill', 'name: my-skill\ndescription: d\nmodes: [passive, fuzz]', 'modes-invalid'),
        ('my-skill', 'name: my-skill\ndescription: d', 'modes-invalid'),
        ('my-skill', 'name: my-skill\ndescription: d\nmodes: passive', 'modes-invalid'),
        ('my-skill', 'name: my-skill\ndescription: d\nmodes: [passive]\nchecks: x', 'checks-invalid'),
        (
            'my-skill',
            'name: my-skill\ndescription: d\nmodes: [passive]\nmetadata:\n  derived_from: [src]',
            'provenance-missing',
        ),
        (
            'my-skill',
            'name: my-skill\ndescription: d\nmodes: [passive]\nlicense: MIT\nmetadata:\n  derived_from: []',
            'provenance-missing',
        ),
        ('my-skill', 'name: [unclosed', 'frontmatter-invalid'),
        ('my-skill', '- a\n- b', 'frontmatter-invalid'),
    ],
)
def test_lint_rules(tmp_path: Path, dirname: str, frontmatter: str, rule: str) -> None:
    assert rule in rules(write_skill(tmp_path, dirname, frontmatter))


def test_missing_frontmatter(tmp_path: Path) -> None:
    directory = tmp_path / 'plain'
    directory.mkdir()
    (directory / 'SKILL.md').write_text('# no frontmatter\n')
    assert rules(directory) == {'frontmatter-missing'}


def test_derived_skill_with_provenance_is_clean(tmp_path: Path) -> None:
    directory = write_skill(
        tmp_path,
        'my-skill',
        'name: my-skill\ndescription: d\nmodes: [passive]\nlicense: MIT\nmetadata:\n  derived_from: [x (MIT)]',
    )
    assert load_skill(directory)[1] == []


def test_skill_body_is_never_executed(tmp_path: Path) -> None:
    marker = tmp_path / 'executed'
    write_skill(
        tmp_path / 'skills',
        'my-skill',
        'name: my-skill\ndescription: d\nmodes: [passive]',
        body=f'```python\nopen({str(marker)!r}, "w")\n```\n',
    )
    (tmp_path / 'skills' / 'my-skill' / 'helper.py').write_text(f'open({str(marker)!r}, "w")\n')
    load_skills([tmp_path / 'skills'])
    assert not marker.exists()


def test_duplicate_skill_first_root_wins(tmp_path: Path) -> None:
    fm = 'name: dup\ndescription: {}\nmodes: [passive]'
    write_skill(tmp_path / 'a', 'dup', fm.format('first'))
    write_skill(tmp_path / 'b', 'dup', fm.format('second'))
    skills, diagnostics = load_skills([tmp_path / 'a', tmp_path / 'b'])
    assert skills['dup'].description == 'first'
    assert [(d.level, d.rule) for d in diagnostics] == [('warning', 'duplicate-skill')]


def test_missing_skill_dir_is_an_error(tmp_path: Path) -> None:
    _, diagnostics = load_skills([tmp_path / 'nope'])
    assert [d.rule for d in diagnostics] == ['skill-dir-missing']


# ── Join ──────────────────────────────────────────────────────────────────────


def test_join_by_check_id_with_warnings_only_for_unknown_checks(tmp_path: Path) -> None:
    write_skill(tmp_path, 'orphan-skill', 'name: orphan-skill\ndescription: d\nmodes: [passive]\nchecks: [ghost]')
    write_skill(tmp_path, 'playbook', 'name: playbook\ndescription: d\nmodes: [active]')  # no check: fine
    registry = build_registry([tmp_path])
    assert registry.skills_for('header-security') == ['header-review']
    assert registry.skills_for('version-disclosure') == ['version-disclosure']
    assert registry.errors == ()
    ghost = [d for d in registry.diagnostics if d.skill == 'orphan-skill']
    assert [(d.level, d.rule) for d in ghost] == [('warning', 'unknown-check')]
    assert not [d for d in registry.diagnostics if d.skill == 'playbook']


def test_check_with_no_skill_is_fine() -> None:
    class Bare:
        check_id = 'bare'

    registry = build_registry(checks={'bare': Bare()})
    assert registry.skills_for('bare') == [] and registry.errors == ()


# ── CLI ───────────────────────────────────────────────────────────────────────


def test_checks_reports_skills_and_warnings(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, err = run(capsys, 'checks')
    assert code == cli.EXIT_OK
    by_check = {r['check_id']: r['skills'] for r in json.loads(out)}
    assert by_check['header-security'] == ['header-review']
    assert by_check['api-contract-conformance'] == ['api-inventory']
    assert 'warning: api-inventory:' not in err
    assert 'warning: authorization-testing: unknown-check' in err


def test_checks_lint_errors_exit_1(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    write_skill(tmp_path, 'bad-skill', 'name: other\ndescription: d\nmodes: [passive]')
    code, _, err = run(capsys, 'checks', '--skill-dir', str(tmp_path))
    assert code == cli.EXIT_FATAL
    assert 'error: bad-skill: name-mismatch' in err


def test_checks_skill_dir_adds_fixture_skill(capsys: pytest.CaptureFixture[str]) -> None:
    _, _, err = run(capsys, 'checks', '--skill-dir', str(FIXTURE_SKILLS))
    assert "banner-leak: unknown-check: check 'banner-leak' is not registered" in err  # no entry point installed yet


# ── §13.2: banner-leak via an entry-point distribution, zero engine edits ─────


@pytest.fixture
def banner_leak_installed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Make ``partex-banner-leak`` discoverable: module on ``sys.path`` plus a ``.dist-info`` with its entry point."""
    site = tmp_path / 'site'
    site.mkdir()
    shutil.copy(PLUGIN_SRC / 'banner_leak.py', site)
    dist_info = site / 'partex_banner_leak-0.1.0.dist-info'
    dist_info.mkdir()
    (dist_info / 'METADATA').write_text('Metadata-Version: 2.1\nName: partex-banner-leak\nVersion: 0.1.0\n')
    (dist_info / 'entry_points.txt').write_text('[partex.checks]\nbanner-leak = banner_leak:banner_leak_check\n')
    monkeypatch.syspath_prepend(str(site))
    yield
    sys.modules.pop('banner_leak', None)


def banner_bundle(root: Path) -> Path:
    (root / 'evidence').mkdir(parents=True)
    exchange = {
        'kind': 'http_exchange',
        'http': {
            'request': {'method': 'GET', 'url': 'https://app.example.test/', 'headers': [['Host', 'app.example.test']]},
            'response': {
                'status_code': 200,
                'headers': [['Server', 'nginx/1.18.0'], ['Content-Type', 'text/html']],
                'body': 'hi',
            },
        },
    }
    (root / 'evidence' / '0001.json').write_text(json.dumps(exchange))
    (root / 'bundle.json').write_text(
        json.dumps(
            {
                'schema_version': 1,
                'target': {'base_url': 'https://app.example.test', 'name': 'app'},
                'evidence_files': ['evidence/0001.json'],
                'suggested_checks': [],
            }
        )
    )
    return root


@pytest.mark.usefixtures('banner_leak_installed')
def test_banner_leak_registers_persists_and_exports(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    code, out, err = run(capsys, 'checks', '--skill-dir', str(FIXTURE_SKILLS))
    assert code == cli.EXIT_OK
    assert {r['check_id']: r['skills'] for r in json.loads(out)}['banner-leak'] == ['banner-leak']
    assert 'banner-leak' not in err

    db = tmp_path / 'p.db'
    bundle = banner_bundle(tmp_path / 'bundle')
    code, out, _ = run(capsys, 'review', str(bundle), '--checks', 'banner-leak', '--db', str(db))
    assert code == cli.EXIT_FINDINGS
    review = json.loads(out)
    assert review['state'] == 'checks_complete' and review['checks'] == ['banner-leak']
    assert [f['check_id'] for f in review['findings']] == ['banner-leak']

    code, out, _ = run(capsys, 'show', review['run_id'], '--db', str(db))
    assert code == cli.EXIT_OK
    shown = json.loads(out)
    assert [f['check_id'] for f in shown['findings']] == ['banner-leak']
    assert shown['run']['selected_checks'] == ['banner-leak']


def test_plugin_distribution_metadata() -> None:
    import tomllib

    meta = tomllib.loads((PLUGIN_SRC / 'pyproject.toml').read_text())
    assert meta['project']['entry-points']['partex.checks'] == {'banner-leak': 'banner_leak:banner_leak_check'}
