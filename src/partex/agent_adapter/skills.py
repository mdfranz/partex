"""Skills as deferred capabilities — PLAN §9 (progressive disclosure), issue #59.

Each discovered skill becomes a ``Capability(defer_loading=True)``: the model sees only a one-line catalog
entry (the skill's description) and calls the framework's ``load_capability`` tool to pull a playbook in when
it is relevant. Skills are data: this module reads Markdown (``SKILL.md`` body and ``reference/*.md``) and never
imports or executes anything under a skill directory. A playbook is guidance only; findings are still recorded
by checks alone.
"""

from collections.abc import Mapping
from typing import Any

from pydantic_ai.capabilities import Capability

from ..registry import SKILL_FILE, Skill, _split_frontmatter  # pyright: ignore[reportPrivateUsage]

MAX_SKILL_CHARS = 60_000
"""Cap on one skill's loaded text (body plus references), so a huge playbook cannot flood the context."""


def skill_text(skill: Skill) -> str:
    """The playbook text: the ``SKILL.md`` body (after the frontmatter) followed by ``reference/*.md`` files."""
    parts: list[str] = []
    path = skill.directory / SKILL_FILE
    try:
        raw = path.read_text(encoding='utf-8')
    except OSError, UnicodeDecodeError:
        return ''
    front = _split_frontmatter(raw)
    body = raw
    if front is not None:
        # Drop the fenced frontmatter block: the first '---' line pair.
        lines = raw.splitlines()
        closing = next((i for i, line in enumerate(lines[1:], start=1) if line.strip() == '---'), None)
        body = '\n'.join(lines[closing + 1 :]) if closing is not None else raw
    parts.append(body.strip())
    reference = skill.directory / 'reference'
    if reference.is_dir():
        for file in sorted(reference.glob('*.md')):
            try:
                parts.append(f'## Reference: {file.name}\n\n{file.read_text(encoding="utf-8").strip()}')
            except OSError, UnicodeDecodeError:
                continue
    text = '\n\n'.join(part for part in parts if part)
    if len(text) > MAX_SKILL_CHARS:
        text = text[:MAX_SKILL_CHARS] + '\n\n[playbook truncated]'
    return text


def usable_skills(skills: Mapping[str, Skill], checks: Mapping[str, Any]) -> list[Skill]:
    """Skills worth offering: those with no listed checks, or at least one installed check.

    A playbook whose checks are not installed (an unfinished draft) would send the model after tools it
    cannot use, so it stays out of the catalog.
    """
    return [
        skill
        for _, skill in sorted(skills.items())
        if not skill.checks or any(check_id in checks for check_id in skill.checks)
    ]


def skill_capabilities(skills: list[Skill]) -> list[Capability[Any]]:
    """One deferred capability per skill; the catalog shows ``[modes] description``, ``load_capability`` loads the text."""
    capabilities: list[Capability[Any]] = []
    for skill in skills:
        text = skill_text(skill)
        if not text:
            continue
        description = (
            f'[{", ".join(sorted(set(skill.modes)))}] {skill.description}' if skill.modes else skill.description
        )
        capabilities.append(Capability(id=skill.name, description=description, instructions=text, defer_loading=True))
    return capabilities
