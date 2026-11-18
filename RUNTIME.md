# Partex runtime decisions

[PLAN.md](PLAN.md) owns milestone sequencing and validation gates. This document defines what
each execution environment can access, how long its state lives, and how failures are handled.

## Deterministic passive checks

Run installed Python checks through the passive engine. Check packages are trusted code.
Checks receive validated evidence and return findings candidates. The engine validates
evidence references and owns persistence. Markdown skills remain guidance. The passive
pipeline can complete without model calls or a model-code runtime.

## M5 read-only reviewer

Use Monty-backed `CodeMode` for `chat <run-id>` by attaching `CodeMode(tools=['list_findings', 'get_finding', 'lookup_evidence'], eager=True, ..., mount=None, os_access=None)` directly on `partex_reviewer_agent` while keeping CLAI2's `run.code_mode` and `run.speculative_code_mode` disabled (so CLAI2's `WorkspaceCodeMode` does not mount the host working directory). Generated Python can group findings, compare captured headers, and correlate records using `list_findings`, `get_finding`, and `lookup_evidence`. Host tools enforce the current run ID and redact their results before returning them to the snippet. Give the sandbox no filesystem mounts, credentials, shell, network access, or store handles. CLAI2's plugin loading remains disabled.

Start with fresh sandbox state for each review invocation. State may live across turns within
that invocation and is discarded on exit, including when conversation history is retained.
Enforce time, memory, output, and tool-call limits. Cancel pending work when a turn is
cancelled, and discard the sandbox session after a terminal time or memory limit. The
operator can retry the review without changing stored evidence or findings.

## M5 speculative reads

Keep speculation opt-in. Eager Code Mode runs complete statements as they stream. Speculation
can start independent reads before execution reaches their statement. Two lookups whose IDs
are already known are candidates. A lookup that needs an ID from an earlier result must wait.

CLAI2's stock `SpeculativeExecution` allowlist hardcodes `FileSystem` and `ClaiDocs` tools (`SPECULATIVE_TOOLS`) and overrides `read_only` metadata. Attaching `CodeMode(..., speculate=['list_findings', 'get_finding', 'lookup_evidence'])` directly on `partex_reviewer_agent` restricts speculation to the reviewer's run-scoped reads without modifying CLAI2, and counts speculative calls against concurrency and tool-call limits from launch, including calls that are discarded. Cancel unused work where possible.

Compare direct calls, eager Code Mode, and eager Code Mode with speculation on the same
offline fixtures. Record answer accuracy, time to answer, and calls started, reused, or
discarded. Verify redaction, run isolation, and cancellation in each mode. Consider enabling
speculation by default only if the observed latency improvement justifies the added work.

## Full Python and native tools

Defer a second runtime until an offline analysis task needs packages or binaries unavailable
in Monty. Evaluate a local microVM such as BoxLite or Smol with networking disabled, a copy
of the required inputs, no host credentials, and a disposable guest. Treat outputs as
untrusted data. A full Python kernel under the host user's account has that user's authority.

## M0 local dependencies

CLAI2 depends on `pydantic-monty` even when Code Mode is disabled. Build the metapackage, client,
and worker runtime from the same audited local Monty revision. Verify version resolution and
worker startup in a fresh environment from outside the checkouts.
