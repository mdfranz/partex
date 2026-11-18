"""Error types for the Partex engine — PLAN §5.

Every failure carries a rule code for diagnostics and exit-code mapping.
"""


class PartexError(Exception):
    """Base exception for all Partex errors."""

    rule_code: str | None = None

    def __init__(self, message: str, *, rule_code: str | None = None) -> None:
        super().__init__(message)
        self.rule_code = rule_code


class ValidationFailed(PartexError):
    """Input validation failure with a named rule code.

    Each failure mode maps to a rule code so the CLI can print precise diagnostics.
    Failure modes (see §4.1):
    - ``engagement-version`` — schema_version is not exactly 1 (E1)
    - ``unauthorized`` — missing attestation or --authorized flag (E2)
    - ``scope-invalid`` — scope is empty, malformed, or base_url outside scope (E3, E5)
    - ``credential-invalid`` — credentials value is not an env var name (E4, E7)
    - ``credential-missing`` — referenced env var is not set at run start (E4, E7)
    - ``bundle-version`` — bundle schema_version unsupported (V1)
    - ``bundle-parse`` — manifest does not parse (V1)
    - ``evidence-invalid`` — an evidence file fails model validation (V2)
    - ``duplicate-evidence`` — dedup collision (V3)
    - ``evidence-too-large`` — file exceeds size cap (V4)
    - ``unknown-check`` — suggested_checks references an unregistered check (V6)
    """


class ScopeViolation(PartexError):
    """A request was blocked because it fell outside the engagement scope (§4.2).

    Raised before any bytes hit the wire.  When triggered by an agent tool,
    it surfaces as a ``ToolFailed`` so the model sees the failure without
    burning its tool retry budget.
    """


class BudgetExhausted(PartexError):
    """The engagement's ``max_requests`` budget was consumed.

    This is a clean termination: the run ends ``checks_complete`` with what
    was committed, not an error.
    """
