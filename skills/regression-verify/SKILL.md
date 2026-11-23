---
name: regression-verify
description: >-
  Invoke when re-verifying previously reported findings against a changed target,
  replaying verification recipes, or re-reviewing exported bundle revisions to
  detect regression drift between runs.
modes:
  - passive
  - active
checks: []
license: Apache-2.0
metadata:
  author: partex
  derived_from:
    - communitytools/skills/regression-sweep/SKILL.md (MIT)
    - communitytools/skills/risk-prioritiser/SKILL.md (MIT)
    - communitytools/skills/transilience-report-style/SKILL.md (MIT)
---

# Regression Re-verification

After the target changes — a new deployment, a config edit, or simply a fresh capture —
re-verify what was previously reported instead of re-testing from scratch. Two engine
paths cover the two questions a regression sweep asks:

1. **Is a specific finding still live?** Replay its verification recipe against the
   authorized target with `partex verify` (§13.4). One finding, minimal requests,
   recorded verdict.
2. **What changed across captures?** Export a live run's captures as a passive bundle
   (`partex export-bundle`) and re-review it (`partex review`), then diff the findings
   against the earlier revision. No traffic is sent: passive findings are a pure
   function of (evidence, selected checks, engine version).

## Workflow: live re-verification (`partex verify <run-id> <finding-id> --authorized`)

- **Prerequisites.** The run must be a live run (engagement input with a recorded scope
  snapshot); the finding must cite `HttpEvidence`; its check must be registered and
  provide a `verify_recipe`. Passive-only runs, findings without HTTP evidence, and
  reported-only checks are refused with an exit-1 diagnostic (`verify-not-live`,
  `verify-no-evidence`, `verify-no-recipe`) — record the refusal, do not work around it.
- **Authorization.** `--authorized` is required for every live command (E2). The replay
  executes inside the run's recorded scope snapshot even if the engagement file on disk
  has changed (§12): a re-verification re-tests the target under the authorization the
  original run was granted, never under a wider one.
- **Verdicts.** `confirmed` (replay still exhibits the finding), `not_reproduced`
  (responses arrived and they do not), `inconclusive` (no usable response —
  unreachable, rate-limited, budget exhausted). All three are completed commands and
  exit 0; the finding never keeps drifting silently. See
  [reference/drift-classes.md](reference/drift-classes.md) for the full transition
  table and the error classes.
- **Guardrails.** Verification never deletes a finding: every transition retains the
  original evidence and attaches the replay evidence. Replays count against the
  engagement budgets (`max_requests`, `max_rps`): exhausting them mid-replay records
  `inconclusive` rather than ending the run, and a sweep run that spends its budget
  ends cleanly in `checks_complete` with everything captured so far. A recipe that
  leaves the scope snapshot fails the run (`verify-scope` — treat it as target
  drift, not as a pass). A state-changing recipe goes through the same write
  approval gate as any other write request.

## Workflow: bundle round-trip and revision diff (passive)

1. `partex export-bundle <run-id> --out DIR` writes the run's captures as a
   passive-reviewable bundle. Secrets are redacted by default; `--include-secrets`
   re-includes cleartext for `verify` replay data and warns.
2. `partex review DIR --checks <id>[,<id>…]` re-runs the passive checks over the same
   evidence. The §13.4 round-trip guarantees the passive findings of the source run
   are reproduced.
3. Diff the two revisions by **(check_id, subject)** — never by raw title text or
   evidence IDs. Subjects are normalized identifiers (operation keys, header names,
   tracker slugs), so route reordering and concrete-ID paths do not create churn.
   Classify each row as persistent, new, fixed-candidate, or regressed per
   [reference/drift-classes.md](reference/drift-classes.md).
4. **A missing finding is not a fix.** Absence in a passive re-review only means the
   new capture does not exhibit it. Only a `partex verify` replay that records
   `not_reproduced` is evidence that the finding no longer reproduces.

## Prioritization and reporting

Order a sweep's results by verification state first, then severity — a replay-confirmed
finding outranks an unverified one at any severity, and `not_reproduced` findings move
out of the remediation queue but stay in the report with their counterevidence. The
severity mapping and the report-data alignment rules (every claim cites finding IDs;
severity counts come from stored findings, never re-derived by hand) are in
[reference/prioritization.md](reference/prioritization.md).

## Scope and evidence model

- The passive path issues no traffic. The `verify` replay is the only sanctioned
  re-request, and it replays the recipe as the original request was made (same
  User-Agent, same TLS posture).
- Findings survive every failure mode: they are persisted before any model-backed
  stage, and a failed, timed-out, or cancelled re-verification leaves the prior
  finding readable with its original evidence intact.
