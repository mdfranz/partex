---
name: banner-leak
description: >-
  Fixture skill for passive banner-leakage detection used to verify registry separation
  without modifying engine modules.
modes:
  - passive
checks:
  - banner-leak
---

# Banner Leak (Fixture Skill)

Minimal data-only skill paired with the `banner-leak` fixture check distribution for
the registry-separation validation experiment (`PLAN.md` §13.2).

## Purpose

- Proves that third-party or fixture `PassiveCheck` distributions registered via the
  `partex.checks` entry-point group and `--skill-dir` skill roots integrate cleanly with
  `partex review` and `partex checks`.
- Findings emitted by `banner-leak` must persist to `RunStore` and export via
  `partex show` with zero edits to `engine.py`, `storage.py`, `models.py`, or
  `agent_adapter.py`.

## Passive Check Contract (`banner-leak`)

- Inspect bundled `HttpExchange` records for `Server` or `X-Powered-By` headers
  exposing explicit software version strings.
- Emit `FindingDraft` records citing the `ev_*` evidence ID of the matching response.
- Never open network sockets or access storage directly.
