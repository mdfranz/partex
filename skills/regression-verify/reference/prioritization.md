# Prioritization and report-data alignment

Reference for `skills/regression-verify/SKILL.md`. Condensed from
`communitytools/skills/risk-prioritiser` (MIT, severity and remediation
prioritization) and `communitytools/skills/transilience-report-style` (MIT,
report-data alignment), rewritten to the partex `Severity` scale and stored-finding
model. The defaults below are an operator-adjustable ordering, not a policy the model
invents.

## Ordering a regression sweep's findings

1. **Verification state first.** `verified` findings (replay-confirmed, live now)
   outrank everything; `reported` findings are unconfirmed leads until a replay or a
   fresh capture corroborates them; `verification_failed` findings leave the
   remediation queue but stay in the report with their counterevidence.
2. **Then severity**, descending, on the engine scale:
   `critical`, `high`, `medium`, `low`, `info` (`Severity`, PLAN §5). Severity is
   assigned by the check from evidence, never re-rated by hand during a sweep; if the
   rating looks wrong, that is a check bug — file it, do not edit the finding.
3. **Then blast radius**, from the finding's own fields: the number of distinct
   evidence items (captured across how many sources/origins) and whether the subject
   names an operation key, a host-wide policy, or a single response.
4. **Regressed rows jump the queue.** A finding that returned after
   `not_reproduced`/absence (drift class *regressed*) is re-verified before new
   low-severity rows: it is a change in the target's behavior, not just noise.

## Remediation mapping

The finding's `remediation` text comes from the check; the sweep maps severity to
urgency and never rewrites the remediation itself:

| Severity | Default urgency |
|---|---|
| `critical` | Before the next release / immediate operator attention |
| `high` | Current remediation cycle |
| `medium` | Next scheduled cycle |
| `low` / `info` | Batched; informational rows are triage input, not work items |

A `not_reproduced` finding is reported as "no longer reproduces as of
`<verification_id>`" with its counterevidence — it is closed evidence, and reopening it
needs a new finding or a re-verification that returns `confirmed`.

## Report-data alignment

- Every claim in a sweep report cites stored finding IDs (`fn_*`) and verification IDs
  (`vf_*`); nothing is asserted from memory of an earlier run.
- Severity counts and status breakdowns come from the stored findings
  (`report.py` gathers them), never re-derived by hand.
- Revision diffs state the revisions compared and the bundle export settings
  (secrets redacted by default; `--include-secrets` exports are replay-only and must be
  labeled as such wherever referenced).
- Unverified (`reported`) findings are labeled as such wherever they appear; the report
  never upgrades a row's confidence because the sweep is old.
