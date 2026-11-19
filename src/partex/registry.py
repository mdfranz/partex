"""Check and skill registry — PLAN §10.

Checks are code and load **only** from installed distributions through the ``partex.checks``
entry-point group (built-ins register the same way).  Skills are data: ``skills/<name>/SKILL.md``
directories whose YAML frontmatter is parsed and linted here — the Markdown body is never imported
or executed.  Extra skill roots (``--skill-dir``) can add Markdown, never code.  The two sides are
joined by ``check_id``; neither requires the other.
"""

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml

from . import engine

VALID_MODES = frozenset({'passive', 'active'})
SKILL_FILE = 'SKILL.md'

_KEBAB = re.compile(r'^[a-z0-9]+(?:-[a-z0-9]+)*$')


def builtin_skill_root() -> Path:
    """The packaged skills (``partex/skills`` in a wheel), else the repository's ``skills/`` in a checkout."""
    packaged = Path(__file__).parent / 'skills'
    return packaged if packaged.is_dir() else Path(__file__).resolve().parents[2] / 'skills'


@dataclass(frozen=True)
class Diagnostic:
    """One lint finding.  Errors fail ``partex checks``; warnings are informational."""

    level: Literal['error', 'warning']
    skill: str
    rule: str
    message: str

    def render(self) -> str:
        return f'{self.level}: {self.skill}: {self.rule}: {self.message}'


@dataclass(frozen=True)
class Skill:
    """A skill's parsed frontmatter.  ``body`` is data; nothing in it is ever evaluated."""

    name: str
    directory: Path
    description: str = ''
    modes: tuple[str, ...] = ()
    checks: tuple[str, ...] = ()
    license: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict[str, Any])


@dataclass(frozen=True)
class Registry:
    """Discovered checks, loaded skills, and every lint diagnostic found while building them."""

    checks: Mapping[str, Any]
    skills: Mapping[str, Skill]
    diagnostics: tuple[Diagnostic, ...]

    @property
    def errors(self) -> tuple[Diagnostic, ...]:
        return tuple(d for d in self.diagnostics if d.level == 'error')

    def skills_for(self, check_id: str) -> list[str]:
        """Names of the skills that list *check_id*, sorted."""
        return sorted(name for name, skill in self.skills.items() if check_id in skill.checks)


# ── Frontmatter ───────────────────────────────────────────────────────────────


def _split_frontmatter(text: str) -> str | None:
    """The YAML between the leading ``---`` fences, or ``None`` when absent."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != '---':
        return None
    for index in range(1, len(lines)):
        if lines[index].strip() == '---':
            return '\n'.join(lines[1:index])
    return None


def _string_list(value: Any) -> list[str] | None:
    if not isinstance(value, list):
        return None
    items: list[Any] = list(value)  # pyright: ignore[reportUnknownArgumentType]
    return [item for item in items if isinstance(item, str)] if all(isinstance(item, str) for item in items) else None


def load_skill(directory: Path) -> tuple[Skill | None, list[Diagnostic]]:
    """Parse and lint one skill directory.  Returns ``(skill, diagnostics)``; ``skill`` is ``None`` if unusable."""
    label = directory.name
    path = directory / SKILL_FILE
    try:
        raw = _split_frontmatter(path.read_text(encoding='utf-8'))
    except (OSError, UnicodeDecodeError) as exc:
        return None, [Diagnostic('error', label, 'frontmatter-unreadable', f'cannot read {path}: {exc}')]
    if raw is None:
        return None, [Diagnostic('error', label, 'frontmatter-missing', f'{SKILL_FILE} has no YAML frontmatter')]
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        return None, [Diagnostic('error', label, 'frontmatter-invalid', f'frontmatter is not valid YAML: {exc}')]
    if not isinstance(data, dict):
        return None, [Diagnostic('error', label, 'frontmatter-invalid', 'frontmatter must be a YAML mapping')]
    front: dict[str, Any] = {str(key): value for key, value in data.items()}  # pyright: ignore[reportUnknownVariableType, reportUnknownArgumentType]

    problems: list[Diagnostic] = []

    def error(rule: str, message: str) -> None:
        problems.append(Diagnostic('error', label, rule, message))

    name = front.get('name')
    if not isinstance(name, str) or not name:
        error('name-missing', '`name` is required')
        name = label
    elif name != label:
        error('name-mismatch', f'`name` ({name!r}) must equal the directory name ({label!r})')
    if not _KEBAB.fullmatch(label):
        error('name-not-kebab', f'directory name {label!r} must be kebab-case')

    description = front.get('description')
    if not isinstance(description, str) or not description.strip():
        error('description-missing', '`description` is required')
        description = ''

    modes = _string_list(front.get('modes'))
    if modes is None or not modes:
        error('modes-invalid', '`modes` must be a non-empty list drawn from passive/active')
        modes = []
    elif unknown := sorted(set(modes) - VALID_MODES):
        error('modes-invalid', f'`modes` has unknown value(s) {", ".join(unknown)}; allowed: active, passive')

    checks = _string_list(front.get('checks', []))
    if checks is None:
        error('checks-invalid', '`checks` must be a list of check ids')
        checks = []

    license_ = front.get('license')
    metadata = front.get('metadata')
    if license_ is not None and not isinstance(license_, str):
        error('license-invalid', '`license` must be a string (an SPDX identifier)')
        license_ = None
    if metadata is not None and not isinstance(metadata, dict):
        error('metadata-invalid', '`metadata` must be a mapping')
        metadata = None
    meta: dict[str, Any] = {str(k): v for k, v in metadata.items()} if metadata else {}  # pyright: ignore[reportUnknownVariableType, reportUnknownArgumentType, reportUnknownMemberType]
    if 'derived_from' in front or 'derived_from' in meta:
        # Third-party-derived content must carry its licence and provenance (PLAN §10).
        if not license_:
            error('provenance-missing', 'a derived skill must declare `license`')
        if not _string_list(meta.get('derived_from')):
            error('provenance-missing', 'a derived skill must list its sources under `metadata.derived_from`')

    skill = Skill(
        name=name,
        directory=directory,
        description=description,
        modes=tuple(modes),
        checks=tuple(dict.fromkeys(checks)),
        license=license_,
        metadata=meta,
    )
    return skill, problems


def load_skills(roots: Iterable[Path]) -> tuple[dict[str, Skill], list[Diagnostic]]:
    """Load every ``<root>/<name>/SKILL.md``.  The first root to define a name wins; later duplicates warn."""
    skills: dict[str, Skill] = {}
    diagnostics: list[Diagnostic] = []
    for root in roots:
        if not root.is_dir():
            diagnostics.append(Diagnostic('error', str(root), 'skill-dir-missing', f'{root} is not a directory'))
            continue
        for directory in sorted(p for p in root.iterdir() if p.is_dir() and (p / SKILL_FILE).is_file()):
            skill, problems = load_skill(directory)
            diagnostics.extend(problems)
            if skill is None:
                continue
            if directory.name in skills:
                diagnostics.append(
                    Diagnostic('warning', directory.name, 'duplicate-skill', f'{directory} shadowed by an earlier root')
                )
                continue
            skills[directory.name] = skill
    return skills, diagnostics


# ── Join ──────────────────────────────────────────────────────────────────────


def build_registry(skill_dirs: Sequence[str | Path] = (), *, checks: Mapping[str, Any] | None = None) -> Registry:
    """Discover checks and skills (built-in root first, then *skill_dirs*) and lint the join."""
    found = engine.installed_checks() if checks is None else checks
    roots = [builtin_skill_root(), *(Path(d) for d in skill_dirs)]
    skills, diagnostics = load_skills(roots)
    for name, skill in sorted(skills.items()):
        for check_id in skill.checks:
            if check_id not in found:
                diagnostics.append(
                    Diagnostic('warning', name, 'unknown-check', f'check {check_id!r} is not registered')
                )
    return Registry(checks=found, skills=skills, diagnostics=tuple(diagnostics))
