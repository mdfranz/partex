# ParTEx skill plan: structure, synthesis, and priorities

> Status: active skill roadmap for `partex` (P0 built-in skills `header-review`,
> `version-disclosure`, and `js-analysis`, plus P1.1 `api-inventory` (#24), are shipped; S2–S3
> skills are drafted and staged
> in `skills/`). Consolidates and supersedes `WEB_API_SKILL_PRIORITIES.md` and
> `SOURCE_SKILL_SYNTHESIS.md` (preserved in git history at 39c1028). The engine contract
> targeted here is `PLAN.md`: **full offensive scope**, two execution modes — passive review
> of offline bundles and active live testing with probe → verify → replay — and three
> capture/probe paths (scoped HTTP client and HAR import landed in M3, browser capture
> harness in M7; `DEPS.md` §5), with skills as data-only Markdown and checks as entry-point
> code (`PLAN.md` §10).

## 1. Reading order

| Doc | Role |
|---|---|
| `PLAN.md` | Engine contract: modes, data contracts, registry, milestones M0–M7 |
| `docs/lineage/SKILLS.md` | Historical inventory of skill **sources** in the three Go forks |
| `docs/lineage/ARCHITECTURE.md` | Historical fork internals the skill system inherited |
| this doc | How ParTEx skills are structured, synthesized from sources, and sequenced |

The superseded drafts disagreed with the current plan: `WEB_API_SKILL_PRIORITIES.md` was
written for the earlier offline-only defensive scope (app-owned CI evidence, owner-defined
access matrices). This plan re-ranks every family against the dual-mode engine: each skill
declares which mode(s) it serves, which check protocol its checks use, and what fixtures prove.

## 2. Skill structure in ParTEx

Target layout (per `PLAN.md` §10; conventions refined here):

```text
skills/<name>/
  SKILL.md        # YAML frontmatter: name, description, checks, license, metadata
  reference/*.md  # optional deeper content, loaded on demand (defer_loading=True)
```

Frontmatter contract:

| Field | Rule |
|---|---|
| `name` | **Must equal the directory name**, kebab-case. The forks match skills by directory name; the `scopesentry`/`scopesentry-mcp` divergence (see `docs/lineage/SKILLS.md`) is the warning case. |
| `description` | One *when-to-invoke* sentence. The agent reads only this (plus the capability catalog) until it loads the skill. |
| `checks` | Every registered check id the skill documents. Unknown ids warn at `partex checks` time; a check with no skill and a skill with no check are both legal (§10). |
| `modes` | Required. The execution modes the skill's guidance serves — `passive` (bundle review), `active` (live testing), or both. Validated by the D6 lint; surfaced to the agent alongside the description, so mode relevance is visible before the body loads. |
| `license`, `metadata` | Optional, strix-style (`license: Apache-2.0`, `metadata: {author, homepage}`). **Required when content is derived** — see §7. |

Structural rules:

- **Data only.** No scripts, no frontmatter `allowed-tools`, no `mcps`. The forks' `api-recon`
  `scripts/` tree (spider, harvest, Puppeteer runtime) does **not** port: execution moves into
  check code driven by the `ScopedHttpClient`, into the M7 browser capture harness
  (`DEPS.md` §5 — the Puppeteer-harvesting capability returns as engine machinery, not
  scripts), or into agent guidance over the fixed toolset (`http_request`, `run_check`,
  `request_verification`, `list_findings`, `lookup_evidence`, `list_surface`,
  `record_coverage`, §9 — plus the M7 `browser_*` harness tools).
- **References condense.** `references/` (plural, forks) → `reference/` (singular, ParTEx).
  A 40–55-file scenario tree ports as a small set of thematic reference docs, one per finding
  class the checks actually emit (see §7 targets).
- **English only**, UTF-8, wrapped ~90 cols, matching the repo's doc style.
- **Mode annotations are frontmatter.** `modes` declares the skill's modes (§2 table); the
  body elaborates per check id where they differ (e.g. `session-cookie-config` passive vs
  `token-weakness` active within one skill).
- **Fixtures ship with the skill**: fixture bundles under `fixtures/skills/<name>/`
  (engine fixtures already live in `fixtures/`, §13), one bundle per acceptance case.

## 3. Taxonomy

The six synthesis topics from `SOURCE_SKILL_SYNTHESIS.md` resolve into five skill families plus
one non-skill (engagement machinery). Modes and protocols per family:

| Family | Covers | Modes | Check protocol |
|---|---|---|---|
| A. Response policy | Security headers, banner/version disclosure, cookie attributes | passive + active | `PassiveCheck`, `ActiveCheck` + `verify_recipe` |
| B. Surface inventory | Declared vs observed API operations, contract conformance, data exposure | passive (+ active probing later) | `PassiveCheck` |
| C. Access controls | Authorization (BOLA/IDOR/BFLA), authentication, session/token lifecycle | active + passive | `ActiveCheck` + `verify_recipe`, `PassiveCheck` |
| D. Evidence lifecycle | Regression re-verification, prioritization, reporting | passive + engine `verify` replay | mostly data-only; optional `PassiveCheck` |
| E. Depth & breadth | Gateway/lifecycle policy, injection/server-side, source-assisted review | mixed | `PassiveCheck`/`ActiveCheck`; **new protocols undecided** |

Non-skill: the old topic 1 (assessment intake brief, coverage matrix) maps to **engagement
machinery and docs**, not a shipped skill — `engagement.json` scope/format (§4.1), `engage init`
author docs (M6), and the coverage report derived from `runs.scope_snapshot` +
`requests_spent` (§12). Family D skills reference these; none of it is playbook content.

## 4. Re-ranked priorities (dual-mode)

Ranking criteria carried over from the superseded draft — **impact on the application under
test, breadth of coverage, readiness of the existing evidence model** — now applied per mode.
API inventory comes first because it establishes the **stable operation identifiers and
evidence references** that authorization reuses; authorization is the highest-impact family;
session/auth builds on both. Defensive coverage validation (the old P1.2/P1.3 core) moves
behind the offensive path as P2.3 because it depends on an engine input format that does not
exist yet (D4 below).

| Priority | Skill (dir name) | Modes & checks | Primary sources | First deliverable | Acceptance criteria | Lands after |
|---|---|---|---|---|---|---|
| P0 | `header-review` + `header-security` check | passive | in plan (§10) | Extend the M1 fixture with HTML, API, and redirect response examples; document which policy applies per response type | Compliant response and each violation class produce distinct findings; inapplicable and incomplete evidence distinguishable; findings cite the response and redact cookie values | M1–M3 (in plan) |
| P0 | `version-disclosure` + active check | active, `verify_recipe` | in plan (§10) | As planned: banner probe → verify → replay (§13.4) | Banner finding verifies `confirmed`; app variant without banner yields `not_reproduced`/`verification_failed`, finding stays readable | M3 (in plan) |
| P0 | `banner-leak` fixture distribution | passive | in plan (§13.2) | Registry-separation test distribution | Findings persist and export with **no edits** to engine modules | M2 (in plan) |
| P1.1 | `api-inventory` + `api-contract-conformance` checks | passive | ARTEX `api-recon` (declared vs observed), BaaRai `api-security` (EN base), strix `api-security-testing` (input checklist), communitytools `api-security` (protocol taxonomy + corpus workflow) | Operation inventory from bundle `HttpExchange`s; match against OpenAPI contract excerpts; flag drift, disallowed fields, unobserved declared ops as coverage gaps | Fixtures: conforming response, disallowed field, response with no matching contract, no-contract-in-bundle (insufficient evidence). Operation keys stable across runs; sensitive values stay out of findings/exports | S1 |
| P1.2 | `authorization-testing` + `authz-boundary` active check | active + passive pre-review | BaaRai `api-security` (BOLA/IDOR/BFLA, second-account rule), communitytools `web-app-logic`, communitytools `api-security` | Role-pair probes over the P1.1 operation inventory: same operation under two engagement roles (D2), boundary crossing via `verify_recipe` | Distinguish a **verified boundary crossing** (second credential, replayable recipe) from an unprobed operation (coverage gap) from missing evidence; finding names operation, policy, and both exchanges | S2 |
| P1.3 | `auth-session-controls` + `session-cookie-config` (passive), `token-weakness` (active) | passive + active | communitytools `authentication` + `client-side`, ARTEX `playwright-cli` (agent guidance only) | Passive cookie/token review of captures; active probes for token weakness (expired-token replay, logout invalidation, alg confusion within §17.2 depth) | Distinguish response-visible controls from probe-verified controls from missing evidence; fixtures cover expected, failing, and missing-evidence cases | S3 |
| P2.1 | `regression-verify` | passive + engine `verify` | communitytools `regression-sweep`, `risk-prioritiser`, `transilience-report-style`, strix CI/fix skills | Workflow skill: re-verify via `partex verify`, export bundle → re-review round-trip (§13.4 proves the engine path), severity/prioritization mapping to `Severity` + remediation | Documents the drift classes (`confirmed` → `not_reproduced`) and the report-data schema alignment; no new check required to land | S4 (independent of S2/S3; can swap) |
| P2.2 | `gateway-policy` + lifecycle coverage | passive + active | communitytools `api-security`, strix `api-security-testing` | Declared limit (contract/gateway config excerpt) vs CI-verified limit vs no evidence; deprecated operations still in traffic | Three-way distinction per §13-style fixture; rate/size limits probed within `max_rps`/`max_requests` budgets | S5 |
| P2.3 | `coverage-validation` (defensive remainder of the old draft) | passive | old `WEB_API_SKILL_PRIORITIES.md` P1.2/P1.3 | CI-result import format (D4) + owner role/tenant matrix as bundle excerpts; validates the application's own controls | Import format round-trips; policy mismatch vs missing test distinguishable | S6 (blocked on D4) |
| P3 | depth & breadth backlog | mixed | communitytools `server-side`/`injection`, BaaRai `codeaudit`, strix `find-security-vulnerabilities-in-code` | Data-only playbooks first; **no new protocol until decided** | A `SourceCheck` protocol proposal (D5) precedes any source-assisted skill | backlog |

Slices S1+ are the post-M6 integration slots (§18: one skill at a time, each with its own
fixture). P0 rows are already inside M1–M3 and anchor every contract below.

## 5. Engine deltas required (proposed `PLAN.md` amendments)

Gaps the re-ranked skills expose in the engine plan. **D1, D2, D6, and D7 are landed in `PLAN.md`
(this round); D3 rides with its slice (S4); D4 and D5 stay deferred:**

| # | Delta | Amends | Needed by | State |
|---|---|---|---|---|
| D1 | Contracts as evidence: OpenAPI documents enter bundles as `ConfigExcerpt` with `format: openapi` and a `revision` field; checks match concrete captured paths against path templates. Evidence model (§5) unchanged; adds an **operation-key normalization rule** (method + normalized path) so finding IDs stay stable (§12). | §4.3, §5, §12 | P1.1 | **landed in PLAN.md** |
| D2 | Engagement `roles` block: optional role→credential map (`{"owner": "PARTEX_CRED_OWNER", ...}`), validated like `credentials` (E4: env-var names only). Authorization probes need two scoped identities. | §4.1 | P1.2 | **landed in PLAN.md** |
| D3 | Coverage report: derive from `runs.scope_snapshot` + `requests_spent`; the owner-maintained route inventory is a bundle `ConfigExcerpt`. Replaces the old "assessment brief" draft artifact. | §7, §11 | P2.1/P2.3 | proposal |
| D4 | CI-result import format (policy revision, operation/test id, expected, observed, evidence ref). New evidence kind, not a `ConfigExcerpt`. | §4.3, §5 | P2.3 | deferred, then proposal |
| D5 | `SourceCheck` protocol for white-box review. `PLAN.md` §17.8 already asks; answer stays **deferred** — no source-assisted skill lands before the P3 proposal. | §10 | P3 | deferred |
| D6 | Frontmatter lint: `name == dirname`, `modes` values valid, attribution fields present when derived, `checks` cross-join clean under `partex checks`. | §10 | P0/M2 | **landed in PLAN.md** |
| D7 | ActiveCheck protocol reality: async `probe`, evidence-returning client (`TargetClient.request(method, url) -> HttpEvidence`, full URL for the scope gate), `verify_recipe(finding, evidence)` and `verify_match(finding, original, replay)`. Landed by #21 and #22; PLAN §10 amended (#44). Needed by S2/S3 checks (#26/#27). | §10 | P0/M3 | **landed in PLAN.md** |

## 6. Definition of ready (per skill)

A skill lands only when all of these hold — the triad from the superseded draft, extended for
active checks and redaction:

1. **Data only**: `SKILL.md` + `reference/*.md`; no scripts, no `allowed-tools`, no `mcps`.
2. **Identity**: `name == dirname` (kebab-case); `description` is a when-to-invoke sentence;
   `checks` lists exactly the documented check ids; `partex checks` reports no join warnings.
3. **Fixture triad**: clean case, one case per supported finding class, insufficient-evidence
   case. Active checks add a probe recipe and a replayable `verify_recipe`.
4. **Determinism**: passive fixtures export byte-identical twice (§13.3a pattern).
5. **Redaction**: any fixture carrying a credential asserts `secret_fields` marking and
   redacted export + agent tool returns (§13.4).
6. **Vocabulary**: engine terms with their §5 meanings — evidence kinds, finding, verification,
   `checks_complete`, exit codes; modes annotated per §2.
7. **Provenance**: attribution frontmatter present when derived; reference docs record which
   source files each condensed doc came from.

## 7. Source pool notes

Condensed from `SOURCE_SKILL_SYNTHESIS.md`; the full fork inventory stays in `docs/lineage/SKILLS.md`:

- **Go forks** — 16 manifest instances across three repos representing 10 names; all share
  `api-recon`, `playwright-cli`, `scopesentry`. Use **BaaRai as the English base** (10 skills),
  consult **failsafe** for packaging hardening (runtime refusal patterns), treat `artex-global`
  as the Chinese localization reference. `playwright-cli`'s 9 companion docs are byte-identical
  across forks — port once, as agent guidance over the M7 `browser_*` harness tools, without
  the Bash tool gate (never a shell to a browser CLI; `DEPS.md` §7 item 4). Treat `scopesentry`
  as an integration-dependency reference (platform management, outside assessment coverage).
  **License gate:** the forks are AGPL-3.0. Never cite a fork file as `derived_from` for an
  Apache-2.0 skill — fork-original text cannot be relicensed. When a fork skill is itself
  adapted from a permissive upstream (e.g. BaaRai `api-security` ← `zhaoxuya520/reverse-skill`,
  MIT), cite the upstream directly and condense from its concepts; otherwise the resulting
  skill must carry `license: AGPL-3.0`.
- **strix** — 9 single-file skills, Apache-2.0. Best source for intake, result review, and
  handoff *structure* (`application-security-testing`'s asset→test mapping). They are
  product-CLI-specific: port the method, rewrite every command reference to the `partex` CLI.
- **communitytools** — MIT (© 2025 Transilience AI), 49 manifests incl. nested specializations,
  plus a router `INDEX.md`. Deepest scenario trees (`api-security`: 42 refs, `web-app-logic`:
  55). `transilience-report-style` ships schema + example + generator test — the packaging
  exemplar for any evidence/report format (D3/D4). Use the router `INDEX.md` as a **coverage
  catalog**: sweep it before drafting to catch topic gaps. `regression-sweep` ships a companion
  on **diff normalization** — the model for S4's drift classes.
- **Python `ARTEX` + `pydantic-ai`** — no web/API skill content; out of this backlog.

Condensation targets: port `api-security`'s 42-file tree into ≤ 6 thematic reference docs (one
per check finding class), `web-app-logic`'s 55 into ≤ 4; keep only scenarios the checks emit.

## 8. Synthesis workflow (per skill)

1. Pick the family and slice from §4; re-read the source rows and `docs/lineage/SKILLS.md` entries.
2. Base the draft on the named primary source in English (BaaRai fork content, communitytools
   depth, strix structure — never strix commands verbatim).
3. Condense reference trees per §7 targets; drop tool-specific content; replace with `partex`
   CLI and engine references.
4. Re-annotate with ParTEx concepts: mode(s), evidence kinds, check ids, fixture expectations.
5. Draft the checks against the §10 protocols; file any engine gaps as §5 deltas.
6. Build fixtures to the §6 definition of ready.
7. Review gate: walk the acceptance criteria; land post-M6, one skill per slice.
8. Record provenance per doc (source files condensed, license carried).

**First drafting targets**, field-level specs carried from the superseded draft so S1–S2
synthesis starts from the same place the old backlog did:

1. **Coverage matrix** — surface, role, workflow, evidence reference, status
   (`assessed` / `unassessed` / `inapplicable`). This is the core table of the D3 coverage
   report, not a shipped skill.
2. **API operation inventory** (S1) — operation identity, protocol, contract revision,
   provenance (declared vs observed), linked application workflows. Drafting it answers the
   D1 gate question: can the bundle format represent both declared and observed operations?
   (Answer is now yes — `format: openapi` excerpts — but the draft still decides how the
   linkage is expressed.)
3. **Authorization and workflow coverage guide** (S2) — roles and tenants mapped to expected
   outcomes per operation, verified against one ordinary **browser** workflow and one
   **API-only** workflow, to prove one vocabulary covers both surfaces.

## 9. Out of scope for this backlog

Wider reconnaissance (`bbot-recon`), binary/package RE (`rea`), patch diffing (`patch-diff`),
defense telemetry (`edr-bypass-re`), exploitation chains (`php2shell`), infrastructure/network,
mobile — see `docs/lineage/SKILLS.md` for the inventory and `PLAN.md` §17.8 for the porting question these
defer to.