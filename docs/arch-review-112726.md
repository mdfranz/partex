# Architectural review — operational abstractions (2026-11-27)

This review examines who has authority to act and which outputs are deterministic across evidence,
findings, engagement and scope, checks and skills, and the new decision-model role.

The implementation reviewed is `issue-256-decision-model` at `0a019ff`, with the test fix at
`f2ab2b2`. PR #266 bundles fixes for #267, #268, and #274 and merged as `022e237`. The PLAN and RUNTIME describe
intended behavior as well as current behavior. Tests and the implementation establish the guarantees
available at this revision. [PR #266](https://github.com/mdfranz/partex/pull/266) · [PLAN](../PLAN.md) ·
[RUNTIME](../RUNTIME.md)

## 0. Who can change the record

Registered checks produce findings. The engine validates their structure and evidence links before
committing them. The model can select checks and request scoped actions through host tools. The
verification runner records replay results and updates finding status. When `--search-model` is set,
`web_search` persists capped third-party answers and source URLs in `web_research`, kept distinct from
target evidence and never eligible as finding `evidence_ids`. Skills can influence choices and
reports, and the live agent can save model-written prose with citation checks and a run-record footer.
The strength of the validation depends on the artifact being written. [Draft validation](../src/partex/engine.py#L279-L349) ·
[Verification storage](../src/partex/storage.py#L911-L960) · [Web research storage](../src/partex/storage.py#L988-L1045) ·
[Tester tools and report saving](../src/partex/agent_adapter/tester.py#L537-L645)

## 1. Evidence and reproducibility

- **Identity.** The store models `http_exchange`, `config_excerpt`, and `artifact` as a discriminated
  union. Evidence IDs use the first 16 hex characters of a SHA-256 hash of canonical JSON. The hash
  excludes `id`, `source`, `secret_fields`, `tls_verified`, and `file_path`. Hashes survive changes to
  those fields when the payload is identical. Default bundle export redacts marked payload values, and
  bundle import recomputes IDs from the resulting content; for exchanges with `secret_fields`, a
  default redacted round-trip therefore produces new `ev_` and `fn_` IDs while preserving `finding_key`
  (`fk_`) and cookie attributes. In addition, `export_bundle` currently serializes `tls_verified: false`
  on unverified HTTPS exchanges and `artifact` records as-is, whereas `load_bundle` accepts only
  `http_exchange` and `config_excerpt` without `tls_verified` (`extra='forbid'`). [Evidence models](../src/partex/models.py) ·
  [Hashing](../src/partex/ids.py#L35-L44) · [Bundle export](../src/partex/har_io.py#L435-L443) ·
  [Bundle record schema](../src/partex/bundle.py#L79-L97) · [Bundle import](../src/partex/bundle.py#L224-L241)
- **Passive determinism.** Given the same bundle input and check selection, the engine assembles
  results in selection order and serializes canonical exports. Tests separately check identical
  findings across fresh stores and byte-identical serialization of equivalent stored results. The
  fixture HAR reproduces the reference bundle’s `header-security` findings. The live round-trip
  test uses `version-disclosure` to capture traffic and `header-security` to review the exported
  bundle. It establishes that the bundle is reviewable and yields the expected kind of finding.
  [PLAN §12](../PLAN.md#12-determinism-and-reproducibility) · [Engine test](../tests/test_engine.py#L111-L116) ·
  [Export test](../tests/test_export.py#L228-L275) · [Round-trip tests](../tests/test_har_io.py#L280-L291) ·
  [Live round-trip test](../tests/test_har_io.py#L382-L424)
- **Live auditability.** Capture records a structured exchange after the response is read, with a
  body cap and omission of binary or undecodable bodies. The capture callback commits each record
  before the caller can proceed. Already committed captures survive a later failure. The store
  deduplicates by content within a run and still counts repeat requests. `seq` orders retained rows,
  and `source` records their origin. Each retained evidence row can represent multiple occurrences.
  [Capture limits](../src/partex/target.py#L84-L92) · [Capture path](../src/partex/target.py#L469-L482) ·
  [Evidence transaction](../src/partex/storage.py#L885-L905) · [Evidence insertion](../src/partex/storage.py#L1136-L1143)
- **Provenance and secrets.** Model-triggered sends return engine-captured evidence. Operator-supplied
  bundles establish format and content identity, while the provenance of their contents depends on
  the producer. HAR import applies its own origin filtering. Marked fields must resolve at load,
  are stored in cleartext for the single-operator replay model, and are redacted on default evidence
  export and model-facing evidence reads. Cookie-value redaction preserves attributes. The coverage
  of these redaction rules is specific to those evidence paths. #260 tracks credential-bearing URLs
  in approval displays and audit records. [HAR import](../src/partex/har_io.py#L286-L337) ·
  [PLAN evidence contract](../PLAN.md#L591-L621) · [#260](https://github.com/mdfranz/partex/issues/260)

## 2. Findings, verification, and coverage

- **Finding validation.** The engine limits checks to 1,000 drafts and validates the claimed check
  ID and version, required fields, and evidence links before assigning a content-derived finding ID
  and deduplicating. Automatic discovery reruns can trigger checks in a live session alongside
  explicit `run_check` calls. A well-formed, evidence-linked draft can still be wrong. PR #266’s fixes
  for default pages and documentation links are examples of detection errors that passed structural
  validation. [Draft validation](../src/partex/engine.py#L279-L349) ·
  [Discovery and check execution](../src/partex/engine.py#L1138-L1200) ·
  [#267](https://github.com/mdfranz/partex/issues/267) · [#274](https://github.com/mdfranz/partex/issues/274)
- **Verification.** The operator’s `partex verify` command runs the check’s recipe against the scope
  snapshot stored for the run. The client uses the original exchange’s TLS posture and defaults to its
  User-Agent, with an explicit User-Agent override. Checks with `verify_match_all` receive every captured
  replay. Legacy `verify_match` receives the first. A conclusive replay can update a previously verified
  finding, and an `inconclusive` replay leaves its status unchanged. `request_verification` is a PLAN
  tool sketch. [Replay setup](../src/partex/verify.py#L116-L181) · [Replay matching](../src/partex/verify.py#L215-L264) ·
  [Status updates](../src/partex/storage.py#L911-L960) · [#176](https://github.com/mdfranz/partex/issues/176) ·
  [PLAN tool sketch](../PLAN.md#L978-L996)
- **Coverage.** `CoverageEntry` distinguishes `check_observed` from `agent_reported` and represents
  outcomes such as `no_issue_found`, `ruled_out`, `not_applicable`, and `needs_follow_up`. The type
  permits empty evidence and reason fields. The current check path verifies the source and resolves any
  provided IDs. The branch exposes coverage reads, while agent-reported coverage recording appears in
  the PLAN tool sketch. [Coverage model](../src/partex/models.py#L264-L275) ·
  [Coverage validation](../src/partex/engine.py#L302-L335) · [Tester tools](../src/partex/agent_adapter/tester.py#L637-L645) ·
  [PLAN coverage sketch](../PLAN.md#L993-L996)

## 3. Engagement and scope

- **Authorization.** Live engagement startup requires the manifest attestation and `--authorized`.
  Validation refusals can leave a finalized `invalid` audit row without target traffic or a model
  call. Verification requires fresh CLI confirmation and uses the stored scope. [Live gates](../src/partex/engine.py#L520-L546) ·
  [Invalid run audit](../src/partex/engine.py#L1228-L1259) · [Verify authorization](../src/partex/verify.py#L116-L143)
- **Traffic policy.** `ScopedHttpClient` enforces scope, allowed methods, and budgets on the request
  path. Scope canonicalization conservatively checks plausible path interpretations. The PLAN
  reserves a browser route hook for M7, which remains pending on this branch. [Scope](../src/partex/scope.py) ·
  [Client request path](../src/partex/target.py#L432-L456) · [PLAN milestones](../PLAN.md#L1398-L1405)
- **Operator control.** In the interactive HTTP tool, engagement policy and operator consent are
  separate requirements. Session approval keys on method, scheme, host, port, and exact path. An
  unapproved action that needs a prompt is denied when the asker is absent. #119 settles the shared
  approval policy, and #65 delivers interactive HTTP approval. Write-bearing verification and the
  other protocol integrations remain pending in the PLAN. Method policy classifies requests by HTTP
  verb, while the server determines their actual effects. [Write gate](../src/partex/agent_adapter/approval.py#L60-L115) ·
  [PLAN §4.2](../PLAN.md#L441-L470) · [M5 status](../PLAN.md#L1403) ·
  [#119](https://github.com/mdfranz/partex/issues/119) · [#65](https://github.com/mdfranz/partex/issues/65)
- **Scope changes.** The operator can stage and confirm live scope additions (`/scope add` and
  `/scope nmap`). The engine persists the snapshot and audit row before applying the change. The model
  can relay a refusal and explain the operator’s options. When `/scope nmap` activates `scope.urls` on a
  session that previously had none, path-prefix matching on `scope.hosts` narrows to the explicit URL
  allowlist (with `target.base_url` kept covered), after which the allowlist only grows; `set_scope`
  itself checks `hosts`, `ports`, `path_prefixes`, `exclusions`, budgets, and methods, but not `urls`.
  An operator who needs to retract an added entry must end the run and start with the corrected scope.
  [Scope amendment](../src/partex/engine.py#L1053-L1136) ·
  [Scope client](../src/partex/target.py#L376-L395) · [PLAN operator controls](../PLAN.md#L430-L439)

## 4. Checks and skills

| | Checks | Skills |
|---|---|---|
| Loading | Trusted Python from installed entry points | Markdown discovered in skill directories and loaded on demand |
| Execution | Host code produces drafts and coverage entries | Text steers the model’s choices and prose |
| Determinism | Passive checks are required to be deterministic by contract. Installed check code runs in-process. | Model-mediated |
| Effect on findings | Check drafts pass through engine validation | Can influence which checks the agent selects and how it describes results |

The loose `check_id` association lets teams develop a playbook before a check exists, and checks can
ship independently of skills. Entry-point registration establishes where code comes from. Passive
purity depends on the installed check honoring its contract. [Check loading](../src/partex/engine.py#L123-L132) ·
[Passive check execution](../src/partex/engine.py#L242-L269) · [Check protocol](../src/partex/checks/__init__.py#L50-L60) ·
[Skill registry](../src/partex/registry.py) · [#59](https://github.com/mdfranz/partex/issues/59)

Report prose is where model judgment can become durable. #268 responds to observed wrong counts,
stale scope, and a mistyped evidence ID. `save_report` refuses recognized citation tokens that are
absent from both the current run and its `--from` run. It appends counts, budgets, and a bounded scope
summary at save time. A report can still contain an incorrect claim alongside a valid citation or in
prose above the engine’s footer. [Report validation and footer](../src/partex/agent_adapter/tester.py#L537-L633) ·
[#268](https://github.com/mdfranz/partex/issues/268)

## 5. Decision model in PR #266

- **Authority and egress.** The decision role answers closed-set questions using an agent with zero
  tools, target-client access, or filesystem mounts. Host code can record decisions’ usage totals
  without claiming `runs.model`. A configured provider receives the excerpt over the network. Callers
  have a shared helper to redact marked evidence, scrub known secrets, cap excerpt length, and frame
  untrusted text. Spans are metadata-only by default. [RUNTIME](../RUNTIME.md#L42-L52) ·
  [Excerpt framing](../src/partex/agent_adapter/decide.py#L74-L100) · [Usage](../src/partex/agent_adapter/usage.py#L22-L50)
- **Typed uncertainty.** The runner limits calls and time per call, and represents provider refusals,
  handoffs, timeouts, and handled errors as typed outcomes. It checks probability labels, finite
  values in `[0, 1]`, and a sum near one. The uncalibrated Anthropic fallback requires opt-in and
  returns `calibrated=False` and `top_p=None`. Structural validation gives consumers a usable
  probability map. Statistical calibration and thresholds for each use require empirical evidence.
  [Decision results](../src/partex/agent_adapter/decide.py#L129-L155) ·
  [Distribution validation](../src/partex/agent_adapter/decide.py#L187-L206) ·
  [Runner limits and outcomes](../src/partex/agent_adapter/decide.py#L387-L479)
- **Integration and evaluation.** `run_agent` constructs the runner with usage recording and has no
  interactive consumer. The eval harness and `validate_run.py` exercise the runner directly. The
  earlier benchmark in #256 used 231 non-security items and reported 63.9% on inverted questions for
  one model and 27–47% on date and arithmetic items across the benchmarked models. PR #266 reports
  opt-in runs on 42 security cases, including 12 adversarial cases. The results measure accuracy,
  spoofing, and abstention on that fixture. One reported spoofed answer among 12 adversarial cases
  is material at that sample size. Feature thresholds and behavior on live distributions remain open.
  [Agent wiring](../src/partex/agent_adapter/__init__.py#L254-L272) ·
  [Eval harness](../scripts/eval_decisions.py) · [Validation script](../scripts/validate_run.py) ·
  [#256](https://github.com/mdfranz/partex/issues/256) · [PR #266 eval results](https://github.com/mdfranz/partex/pull/266)

## 6. What the issue threads add

- #257, #261, #262, and #263 propose independent opt-ins for skill suggestions, response labels,
  surface triage, and loop or coverage advice. They describe advisory behavior and how to proceed
  when the classifier abstains. Those issue contracts are open. [#257](https://github.com/mdfranz/partex/issues/257) ·
  [#261](https://github.com/mdfranz/partex/issues/261) · [#262](https://github.com/mdfranz/partex/issues/262) ·
  [#263](https://github.com/mdfranz/partex/issues/263)
- #258 proposes attaching a model opinion to a finding while preserving severity and verification
  status and keeping raw candidate secrets local. #276 adds agent proposals and operator-confirmed
  dispositions that work independently of `-D`, and suggests sharing one table with #258. #280 is the
  open PLAN amendment. Because #258 is keyed per `(run_id, finding_id, question_id, question_version, model)`
  with probability distributions while #276 is append-only per `(run_id, finding_id)` with `proposed` vs.
  `confirmed` disposition state and cited `evidence_ids`/`research_ids`, their authority and row shapes
  differ even when surfaced together on finding reads. [#258 and design discussion](https://github.com/mdfranz/partex/issues/258) ·
  [#276](https://github.com/mdfranz/partex/issues/276) · [#280](https://github.com/mdfranz/partex/issues/280)
- #259 proposes risk labels at the human consent prompt, with asymmetric thresholds intended to
  counter automation bias. It keeps operator authority and depends on #260 for URL secret scrubbing.
  #281 proposes measuring operator-choice agreement once there is usage. Those observations can show
  how choices correlate with labels. Measuring the label’s effect would require a comparison with
  approvals made without labels. [#259](https://github.com/mdfranz/partex/issues/259) ·
  [#260](https://github.com/mdfranz/partex/issues/260) · [#281](https://github.com/mdfranz/partex/issues/281)
- #278 proposes engine-rendered facts and model-authored judgment in reports, extending the footer
  approach from #268. #124 raises the persistence question and calls for recording the provenance of
  report sections. These proposals make report authorship part of the durable-record design.
  [#278](https://github.com/mdfranz/partex/issues/278) · [#124](https://github.com/mdfranz/partex/issues/124)

## 7. Concrete findings on PR #266

1. **Hermeticity regression reproduced and fixed on the branch.** At `0a019ff`, both CI jobs recorded
   1 failed and 1,271 passed. The coexistence test passed a fake environment mapping to the resolver,
   then provider construction read from the process environment. A focused run reproduced the failure
   with both Google credential variables unset. `f2ab2b2` sets a dummy credential in the test fixture,
   and the focused test passed locally with both variables unset before pytest started. Linux and
   macOS CI both passed on the fixed commit.
   [Failing CI run](https://github.com/mdfranz/partex/actions/runs/46040384320) ·
   [Passing CI run](https://github.com/mdfranz/partex/actions/runs/46046172836) ·
   [Fix](https://github.com/mdfranz/partex/commit/f2ab2b29feec6d7c171f23a52ddce48b85105d08) ·
   [Test](../tests/test_decide.py#L453-L498)
2. **Runner wiring is preparatory.** A comment at `_decision_runner` would make it clear that feature
   consumers are tracked in the follow-up issues. The current integration exercises provider setup
   before those consumers exist. [Agent wiring](../src/partex/agent_adapter/__init__.py#L254-L272)
3. **Post-run usage needs an enforceable rule.** The `usage.py` docstring tells future triage callers
   to avoid writing token totals to a finalized passive run, while #278 proposes recording reporter
   spend via `UsageRecordingModel(role='report')` (`runs.model_calls` and token totals are serialized in
   `export_run_json`). #159 records the broader gap between PLAN immutability and the storage API. Because
   `live_session` keeps a run in `created` until the session exits, `record_model_usage` and in-session
   writes can require `state == 'created'`, while post-`checks_complete` passes record their model
   metadata on their own rows and spans, backed by a test that compares the passive export before and
   after annotation. [Usage note](../src/partex/agent_adapter/usage.py#L22-L30) ·
   [Run export](../src/partex/export.py#L38-L58) ·
   [Session lifecycle](../src/partex/engine.py#L1261-L1292) ·
   [Storage API](../src/partex/storage.py#L883-L1077) · [#159](https://github.com/mdfranz/partex/issues/159) ·
   [#278](https://github.com/mdfranz/partex/issues/278)

## 8. Open questions for the next pass

1. **Who can add or confirm a judgment after `checks_complete`, and what may it change in the
   exported record?** #280 should settle three distinct authority tiers and their storage/export rules
   together with #258, #276, and #159: (a) `partex verify` as the sole writer of `findings.status`
   (`reported -> verified | verification_failed`); (b) #276 dispositions as append-only per
   `(run_id, finding_id)` where an agent (`tester` or #278 reporter) can only record `proposed`
   dispositions and only the `operator` can record or confirm an active disposition; and (c) #258
   decision-model triage as advisory probability distributions keyed by
   `(run_id, finding_id, question_id, question_version, model)`. On the storage and export side (#159),
   in-session writes (`add_evidence`, `commit_findings`, `amend_scope`, `add_web_research`,
   `upsert_coverage`, `record_model_usage`) should require `state == 'created'`, post-`checks_complete`
   annotation and report passes should not mutate `runs` token counters or passive export bytes, and the
   schema v5 → v6 bump should be coordinated across #258, #276, #219, and #124 under #245.
   [#280](https://github.com/mdfranz/partex/issues/280) ·
   [#258](https://github.com/mdfranz/partex/issues/258) · [#276](https://github.com/mdfranz/partex/issues/276) ·
   [#278](https://github.com/mdfranz/partex/issues/278) ·
   [#159](https://github.com/mdfranz/partex/issues/159) · [#245](https://github.com/mdfranz/partex/issues/245) ·
   [#219](https://github.com/mdfranz/partex/issues/219) · [#124](https://github.com/mdfranz/partex/issues/124)
2. **What can the approval study establish?** #281 can measure label and operator-choice agreement.
   Whether labels reduce rubber-stamping is a separate question about decisions with and without
   labels under comparable conditions. [#259](https://github.com/mdfranz/partex/issues/259) ·
   [#281](https://github.com/mdfranz/partex/issues/281)
3. **Where should decision-question limits be enforced?** The current predicate lint checks for
   emptiness and patterns associated with negation. #282 proposes a lint or evaluation gate for the
   date and arithmetic tasks that performed poorly in #256. [Question validation](../src/partex/agent_adapter/decide.py#L103-L125) ·
   [#282](https://github.com/mdfranz/partex/issues/282)
4. **How should durable reports expose authorship?** #268 provides a citation check and a save-time
   factual footer. #278 and #124 raise how readers and tools can identify engine-rendered facts,
   model judgment, and operator-confirmed dispositions in later reports. [#268](https://github.com/mdfranz/partex/issues/268) ·
   [#278](https://github.com/mdfranz/partex/issues/278) · [#124](https://github.com/mdfranz/partex/issues/124)
5. **When does a check need occurrence-level evidence?** A second identical exchange can increment
   the request count while sharing an evidence row. A future check that needs to cite a particular
   occurrence would need a record tied to that occurrence. [Evidence and request accounting](../src/partex/storage.py#L885-L905) ·
   [Evidence insertion](../src/partex/storage.py#L1136-L1143)
6. **Where does the autonomy boundary sit when `--auto` ships?** M5 still lists it as open. #263’s
   proposed judge supplies advice. The review of operator authority belongs against the implementation
   once it exists. [M5 status](../PLAN.md#L1403) · [#263](https://github.com/mdfranz/partex/issues/263)

## 9. Verdict

The current architecture gives checks responsibility for producing findings, the engine responsibility
for validating evidence links, and the operator responsibility for changing scope and consenting to
interactive HTTP writes. Passive reproducibility rests on canonical serialization and deterministic
check code. Live auditability rests on bounded captures and the replay semantics a check implements.
PR #266 adds a typed decision capability with preliminary evaluation results. The next architecture
choice is how to preserve the authority and provenance of judgments added after a run ends.
