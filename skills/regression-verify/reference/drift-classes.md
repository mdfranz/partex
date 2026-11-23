# Drift classes for regression re-verification

Reference for `skills/regression-verify/SKILL.md`. Condensed from
`communitytools/skills/regression-sweep` (MIT, diff normalization / drift classes);
every transition below is engine behavior (`src/partex/verify.py`, PLAN §13.4), not
guidance the model improvises.

## Replay verdicts (`partex verify`)

| Verdict | When | Finding status transition | Evidence retained |
|---|---|---|---|
| `confirmed` | Replayed responses still exhibit the finding (the check's matcher said so; for role-pair findings every replay is matched) | `reported` → `verified` | Original + every replay |
| `not_reproduced` | Responses arrived and none exhibits the finding | `reported` → `verification_failed` | Original + every replay |
| `inconclusive` | No usable response: unreachable, rate-limited, budget exhausted, or the replay did not complete | Unchanged (stays `reported` / prior status) | Original + replays already committed at capture time |

Rules that always hold:

- **Verification never deletes a finding.** Both transitions leave the finding readable
  with its original evidence; the replay evidence is attached to the `vf_*` record.
- **`inconclusive` is not `not_reproduced`.** Unreachability and budget exhaustion are
  local limits, not evidence about the target; the finding keeps its status.
- **`not_reproduced` is evidence-backed absence.** The engine records counterevidence
  ("a clean response arrived, so absence is evidence of absence, not unreachability")
  — cite it rather than restating the finding as fixed.
- All three verdicts exit 0 (a recorded verdict is a completed command). Exit 1 with a
  `partex:` diagnostic means the replay never ran; classify as follows.

## Refusal classes (exit 1, nothing replayed)

| Rule | Meaning | Sweep action |
|---|---|---|
| `verify-not-live` | Run is not a live run (no scope snapshot to replay under) | Re-capture, or use the passive bundle path |
| `finding-not-found` / `unknown-check` | Bad IDs, or the finding's check is not registered in this install | Fix the invocation; do not substitute a manual replay |
| `verify-no-evidence` | Finding cites no HTTP evidence to replay | Passive-only finding: diff bundles instead |
| `verify-no-recipe` | The check provides no recipe for this finding (reported-only) | Passive-only finding: diff bundles instead |
| `verify-scope` | The recipe (or target drift) left the recorded scope | Treat as **target drift**: the recorded surface no longer matches the deployed one; re-run discovery |

## Bundle revision diff (passive re-review)

Match rows by `(check_id, subject)` across bundle revisions; compare severity and
evidence IDs second. Classes:

| Drift class | Definition | Report wording |
|---|---|---|
| Persistent | Same `(check_id, subject)` reported in both revisions | "Still reported in revision N+1"; carry both evidence sets |
| New | Only in the later revision | Report as a first-class finding; the diff date is context, not evidence |
| Fixed-candidate | Reported earlier, absent now | "**Not observed** in revision N+1's captures" — never "fixed"; only a verify replay records `not_reproduced` |
| Regressed | Earlier run recorded `not_reproduced`/absent, later revision reports it again | Highest re-verification priority: a regression that came back |

Normalized operation keys (`METHOD /normalized/path/{param}`, §12) are the identity for
API findings, so concrete-ID churn and route reordering do not manufacture drift rows.
