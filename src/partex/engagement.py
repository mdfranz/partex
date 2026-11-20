"""Engagement loading and validation — PLAN §4.1 rules E1–E7 (manifest half).

An engagement declares a live target and the authority to test it.  Everything
here is pure validation: no sockets, no model calls, no storage.  Rules:

- E1  manifest parses and ``schema_version`` is exactly 1  → ``engagement-version``
- E2  non-empty authorization attestation                  → ``unauthorized``
- E3  scope structural rules (hosts, prefixes, ceilings)   → ``scope-invalid``
- E4  credentials are environment variable **names**       → ``credential-invalid``
- E5  ``base_url`` host is inside ``scope.hosts``           → ``scope-invalid``
- E7  ``roles`` validated like credentials, distinct vars    → ``credential-invalid``

The ``--authorized`` CLI flag half of E2 and the run-start "referenced
variables are set" half of E4/E7 are deliberately separate:

- the flag is enforced by the live commands (``partex test`` et al., issue #21);
- :func:`check_credentials_available` returns unset variables instead of
  raising, so a future ``engage check`` can report all of them at once.
"""

import json
import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from pydantic import ValidationError

from .errors import ScopeViolation, ValidationFailed
from .models import Engagement
from .scope import check_url, normalize_host, validate_scope

# E4/E7: credential references must be partex-namespaced, so an engagement file from a
# third party cannot name an unrelated secret (GITHUB_TOKEN, AWS_SECRET_ACCESS_KEY) and have
# partex send it to the target (#39).
ENV_VAR_PATTERN = re.compile(r'^PARTEX_[A-Z0-9_]+$')

MANIFEST_NAME = 'engagement.json'


def _fail(rule_code: str, detail: str) -> ValidationFailed:
    return ValidationFailed(detail, rule_code=rule_code)


def load_engagement(path: Path | str) -> Engagement:
    """Load and fully validate the engagement manifest at *path*.

    *path* may be the engagement directory (``<dir>/engagement.json``) or the
    manifest file itself.  Raises :class:`ValidationFailed` with the failing
    rule code (E1–E5, E7) on any violation.
    """
    manifest = Path(path)
    if manifest.is_dir():
        manifest = manifest / MANIFEST_NAME
    try:
        raw = manifest.read_text(encoding='utf-8')
    except OSError as exc:
        raise _fail('engagement-version', f'cannot read engagement manifest {manifest}: {exc}') from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise _fail('engagement-version', f'engagement manifest does not parse: {exc}') from exc
    return validate_engagement(data)


def validate_engagement(data: Any) -> Engagement:
    """Validate a parsed engagement manifest (dict) against E1–E5 and E7."""
    if not isinstance(data, dict):
        raise _fail('engagement-version', f'engagement manifest must be a JSON object, got {type(data).__name__}')
    manifest: dict[str, Any] = cast('dict[str, Any]', data)
    # E1 — before anything else, so a future schema version never runs through
    # the wrong validation code.
    if manifest.get('schema_version') != 1:
        raise _fail('engagement-version', f'schema_version must be exactly 1, got {manifest.get("schema_version")!r}')
    # E2 — attestation half (the --authorized flag half lives in the live CLI).
    authorization = manifest.get('authorization')
    if not isinstance(authorization, dict):
        raise _fail('unauthorized', 'authorization must be an object with a non-empty attestation')
    auth: dict[str, Any] = cast('dict[str, Any]', authorization)
    if not isinstance(auth.get('attestation'), str) or not auth['attestation'].strip():
        raise _fail('unauthorized', 'authorization.attestation must be present and non-empty')
    # E4 / E7 — env var names only; inline values rejected before the model
    # ever sees them.
    _validate_env_var_map(manifest.get('credentials'), 'credentials', require_distinct=False)
    _validate_env_var_map(manifest.get('roles'), 'roles', require_distinct=True)
    # Structural backstop: map pydantic failures onto the E-rule failure modes.
    try:
        engagement = Engagement.model_validate(manifest)
    except ValidationError as exc:
        raise _fail(_rule_code_for(exc), f'engagement manifest fails its schema: {exc}') from exc
    # E3 — scope structural rules (hosts parse, exclusions within prefixes,
    # budget ceilings).
    problems = validate_scope(engagement.scope)
    if problems:
        raise _fail('scope-invalid', 'invalid scope: ' + '; '.join(problems))
    # E5 — the declared target must live inside the declared scope.
    try:
        check_url(engagement.scope, engagement.target.base_url)
    except Exception as exc:
        raise _fail('scope-invalid', f'target.base_url is outside scope: {exc}') from exc
    # TLS — insecure_hosts only make sense with verify:false and must be in scope.
    tls = engagement.tls
    if tls.insecure_hosts and tls.verify:
        raise _fail('tls-invalid', 'tls.insecure_hosts is set but tls.verify is true; set verify to false')
    in_scope = {normalize_host(host) for host in engagement.scope.hosts}
    for host in tls.insecure_hosts:
        try:
            normalized = normalize_host(host)
        except ScopeViolation as exc:
            raise _fail('tls-invalid', f'tls.insecure_hosts entry {host!r}: {exc}') from exc
        if normalized not in in_scope:
            raise _fail('tls-invalid', f'tls.insecure_hosts entry {host!r} is not in scope.hosts')
    return engagement


def _validate_env_var_map(value: Any, field_name: str, *, require_distinct: bool) -> None:
    """Validate a name → env-var-name mapping (E4 / E7).

    Values must match ``PARTEX_[A-Z0-9_]+`` — anything else (an inlined secret, a
    lowercase name) is rejected as ``credential-invalid``.  With
    ``require_distinct`` (roles), values must additionally be pairwise
    distinct so no two roles silently share one credential.
    """
    if value is None:
        return
    if not isinstance(value, dict):
        raise _fail('credential-invalid', f'{field_name} must be an object mapping names to env var names')
    mapping: dict[str, Any] = cast('dict[str, Any]', value)
    seen_vars: set[str] = set()
    for name, env_var in mapping.items():
        if not name:
            raise _fail('credential-invalid', f'{field_name} names must be non-empty strings')
        if not isinstance(env_var, str) or not ENV_VAR_PATTERN.fullmatch(env_var):
            raise _fail(
                'credential-invalid',
                f'{field_name}[{name!r}] must be an environment variable name matching PARTEX_[A-Z0-9_]+, '
                f'got {env_var!r} (inline secret values are rejected)',
            )
        if require_distinct:
            if env_var in seen_vars:
                raise _fail(
                    'credential-invalid',
                    f'roles must map to distinct environment variables, but {env_var!r} is reused',
                )
            seen_vars.add(env_var)


def _rule_code_for(exc: ValidationError) -> str:
    """Map a pydantic ValidationError onto an E-rule failure mode."""
    locations = ' '.join(str(error.get('loc')) for error in exc.errors())
    if 'schema_version' in locations or 'target' in locations:
        return 'engagement-version'
    if 'authorization' in locations:
        return 'unauthorized'
    if 'credentials' in locations or 'roles' in locations:
        return 'credential-invalid'
    if 'tls' in locations:
        return 'tls-invalid'
    return 'scope-invalid'


def check_credentials_available(engagement: Engagement, env: Mapping[str, str] | None = None) -> list[str]:
    """Return the referenced credential env vars that are not set (E4/E7 run-start half).

    Deliberately returns instead of raising so ``engage check`` can report every
    missing variable at once; live commands raise ``credential-missing`` when
    the list is non-empty.
    """
    env = os.environ if env is None else env
    referenced = {var for var in engagement.credentials.values()}
    referenced.update(engagement.roles.values())
    return sorted(var for var in referenced if var not in env)


def scoped_hosts(engagement: Engagement) -> set[str]:
    """Return the normalized comparison form of the engagement's scope hosts."""
    return {normalize_host(host) for host in engagement.scope.hosts}
