"""Role-scoped client handles — PLAN §4.1 D2 (``engagement.roles``); issue #23.

Authorization boundary testing needs two scoped identities: ``engagement.roles``
maps role names to ``PARTEX_*`` credential env vars (validated by #11, E7) and
this module binds each role to its own :class:`~partex.target.ScopedHttpClient`
through the same scope gate — sharing **one** engagement-wide request budget
and DNS pin table, so N roles never multiply the engagement's ``max_requests``.

Captures cite their role in the evidence ``source`` (``...:role=<name>``) — the
provenance the engine's surface graph consumes when it records role nodes.
Role credentials are resolved once at handle creation, never inlined anywhere,
and pre-registered as capture secrets so any header or body carrying one is
marked ``secret_fields`` and redacted at the export and model-facing boundaries
exactly like primary credentials (PLAN §5).
"""

import os
from collections.abc import Mapping
from dataclasses import dataclass

from partex.engagement import Engagement
from partex.errors import ValidationFailed
from partex.target import DEFAULT_SOURCE, CaptureCallback, RequestBudget, Resolver, ScopedHttpClient


@dataclass(frozen=True, slots=True)
class RoleHandle:
    """One engagement role: its resolved credential and its isolated client.

    ``credential`` is the resolved environment value — trusted code only
    (checks, the verification runner); it is never logged, never written to
    findings or exports, and is pre-registered as a capture secret on the
    bound client.
    """

    role: str
    env_var: str
    credential: str
    client: ScopedHttpClient


def resolve_role_credentials(
    engagement: Engagement, env: Mapping[str, str] | None = None
) -> dict[str, tuple[str, str]]:
    """Resolve every role credential: ``role -> (env_var, value)``.

    Raises :class:`ValidationFailed` (``credential-missing``) naming each role
    and its variable when anything is unset or empty — before any client is
    constructed or any socket could open.
    """
    environment = os.environ if env is None else env
    resolved: dict[str, tuple[str, str]] = {}
    missing: list[str] = []
    for role, env_var in engagement.roles.items():
        value = environment.get(env_var)
        if value is None or value == '':
            missing.append(f'{role} ({env_var})')
        else:
            resolved[role] = (env_var, value)
    if missing:
        raise ValidationFailed(
            f'role credential env vars not set: {", ".join(sorted(missing))}', rule_code='credential-missing'
        )
    return resolved


def role_handles(
    engagement: Engagement,
    *,
    env: Mapping[str, str] | None = None,
    on_capture: CaptureCallback | None = None,
    resolver: Resolver | None = None,
    source: str = DEFAULT_SOURCE,
    budget: RequestBudget | None = None,
    pins: dict[str, str] | None = None,
) -> dict[str, RoleHandle]:
    """Bind every engagement role to its own client handle through the same gate.

    All handles share one :class:`~partex.target.RequestBudget` (the engagement's
    ``max_requests`` / ``max_rps`` are engagement-wide, not per-role) and one DNS
    pin table.  Each client's ``secret_fields`` machinery is pre-loaded with the
    role's credential value, and captures cite the role via ``source``.

    ``budget`` and ``pins`` let the engine share the *primary* client's allowance
    and resolver table with the role handles, so one engagement never multiplies
    its budget across the live run's handles (#27).
    """
    resolved = resolve_role_credentials(engagement, env)
    budget = budget if budget is not None else RequestBudget(engagement.scope.max_requests, engagement.scope.max_rps)
    pins = pins if pins is not None else {}
    handles: dict[str, RoleHandle] = {}
    for role, (env_var, value) in resolved.items():
        client = ScopedHttpClient(
            engagement,
            secrets=[value],
            source=f'{source}:role={role}',
            on_capture=on_capture,
            resolver=resolver,
            budget=budget,
            pins=pins,
        )
        handles[role] = RoleHandle(role=role, env_var=env_var, credential=value, client=client)
    return handles
