---
name: server-error
description: >-
  Invoke after probing parameterized or malformed requests, or when reviewing captured
  responses, to record unhandled server errors (HTTP 5xx) and debug-page disclosure as findings.
modes:
  - passive
checks:
  - server-error
---

# Unhandled Server Errors (5xx)

Record 5xx responses already captured in the run as findings, so errors provoked by probing are
not left only in prose. Passive: the check reads existing evidence and sends no requests.

## When to run

- After operator-directed probes (`http_request`, `batch_http_request`) that returned 5xx, or
  when reviewing a bundle or HAR containing them.
- Not a substitute for `version-disclosure`: its error-page rule only judges its own unknown-path
  probe. Run `server-error` for errors found anywhere else.

## Check Mapping (`server-error`)

| Condition | Severity | CWE |
|---|---|---|
| `500`, `501`, `505`+ response | `low` | 755 |
| `502` / `503` / `504` response (usually infrastructure) | `info` | 755 |
| Any 5xx body containing a stack trace or framework debug page | `medium` | 209 |

## Output Discipline

- One finding per **host and path pattern**: numeric, UUID and long-hex path segments collapse to
  `{id}`, with every affected `ev_*` ID attached. Fuzzing one route does not flood the findings.
- Cite the HTTP status and the matched debug marker class (never paste secrets from the body).
- A 5xx caused by an obviously malformed probe is still a finding (missing input validation),
  but say in the report which input provoked it.
- Do not report a 5xx the target returns for every request (outage); note it as a coverage gap.
