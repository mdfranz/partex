# Decision Models for Security Use Cases — Research & References

Curated documentation, academic papers, and GitHub repositories on using **decision models**
(single-pass calibrated classification/decision APIs as well as structured symbolic decision
trees) in security workflows, mapped directly to `partex`'s architecture and the active
decision-model issue stack (**#256–#263**).

> **Context in `partex`:** `partex` keeps deterministic checks (`partex review`, `partex test`)
> strictly model-free and treats the decision model role (`-D` / `PARTEX_DECISION_MODEL`, #256)
> as an **advisory-only** third role alongside the analyst (`-m`) and isolated search model (`-S`).
> Decision models never mutate findings, bypass `WriteGate`, or weaken scope/secret boundaries.
>
> **Related files in `docs/research/`:**
> - [`decision-models-vuln-validation-classification.md`](decision-models-vuln-validation-classification.md) — Empirical findings, adversarial/calibration failure modes, and architectural patterns from November 2026 System One research.
> - [`decision-models-references.md`](decision-models-references.md) — Deduplicated index of System One security papers, adversarial attack preprints, vendor evaluations, GitHub repos, and open-weight models.

---

## Issue Mapping (#256–#263)

| Issue | Feature | Primary Research Themes |
|---|---|---|
| **#256** | Decision-model role (`-D`), `pydantic-ai >= 2.75`, `decide.py`, eval fixture | Decisions APIs, probability calibration, selective abstention/deferral, prompt-injection spoofing resistance |
| **#257** | Advisory skill suggestions after discovery | Multi-predicate single-context scoring over bounded summaries |
| **#258** | Second-opinion triage on heuristic findings (`finding_triage`) | Calibrated false-positive triage, structured vulnerability categorization (SSVC) |
| **#259** (+ **#260**) | Advisory risk labels on held writes (`WriteGate`) | Asymmetric thresholds, automation-bias mitigation, high-confidence false-safe risk |
| **#261** | HTTP response classification (SPA/soft-404/auth-gate/WAF) | Low-latency closed-set classification over `<partex_untrusted_data>`-framed excerpts |
| **#262** | Multi-host initial-probe surface triage | Batched single-pass prioritization over scrubbed host summaries |
| **#263** | Semantic loop & coverage-closure judge (`--auto` / runbooks) | Trajectory judges, step-level rubrics, trajectory-adapted uncertainty quantification |

---

## 1. Provider & SDK Documentation

Directly relevant to **#256** (`models_config.py`, `agent_adapter/decide.py`).

- **Pydantic AI — Decision Models API (`pydantic_ai.models.decision`)**
  - URL: <https://pydantic.dev/docs/ai/api/models/decision>
  - Relevance: Core SDK interface `partex` targets in #256 for closed-set choices, predicates, and calibrated probability distributions.
- **Pydantic AI — OpenAI Decisions Model (`pydantic_ai.models.openai_decisions`)**
  - URL: <https://pydantic.dev/docs/ai/api/models/openai_decisions>
  - Relevance: Provider binding for `openai-decisions:gpt-6-luna`.
- **Google Developers Blog — Gemini Decisions API**
  - URL: <https://blog.google/innovation-and-ai/technology/developers-tools/gemini-decisions-api/>
  - Docs: <https://aistudio.google.com/docs/decisions-api>
  - Relevance: Single-prefill-pass multimodal decision model (`google-decisions:gemini-decision-1`) returning calibrated probabilities with zero output tokens; supports scoring multiple questions against one shared context (key for #257 and #262).
- **OpenAI Platform Guides — Decisions API**
  - URL: <https://platform.openai.com/docs/guides/decisions>
  - Relevance: Reference for `openai-decisions:` choices, rubrics, refusal/content-filter behavior, and latency/cost tradeoffs.

---

## 2. Research Papers: Calibration, Selective Automation, & Trajectory Judges

Directly relevant to **#256**, **#258**, **#259**, and **#263**.

- **Evaluating System One Models for Agent Security Decisions: Reliability, Calibration, and Selective Automation** (arXiv)
  - Relevance (#256, #259): Evaluates single-pass "System 1" decision models on prompt-injection detection and agent security decisions. Key takeaway: strong aggregate accuracy and Brier/ECE scores can still mask **high-confidence false negatives ("safe" with high `p`)**, reinforcing #259's asymmetric thresholds (`P(destructive)` warning at lower threshold, `read-like` only at `>= 0.90–0.95`) and #256's advisory-only contract.
- **From Detection to Decision: Calibration and Deferral for Prompt-Injection Detection** (`arXiv:2610.20907`)
  - URL: <https://arxiv.org/abs/2610.20907>
  - Relevance (#256, #261): Studies operational allow/block/defer policies under distribution shift. Shows that raw probabilities and post-hoc temperature scaling alone are insufficient without explicit deferral/abstention policies — directly informing #256's A/B test of threshold abstention (`max(p) < T`) vs. explicit `unsure`.
- **What Outcome-Only LLM Judges Miss on Agent Trajectories** (`arXiv:2611.02035`)
  - URL: <https://arxiv.org/abs/2611.02035>
  - Relevance (#263): Demonstrates why evaluating only final outcomes misses intermediate loops, silent failures, and weak evidence closures; motivates step-rubric trajectory judging over compact tool-call histories.
- **Beyond Single-Turn Confidence: Trajectory-Adapted Uncertainty Quantification for LLM Agents** (`arXiv:2608.12656`)
  - URL: <https://arxiv.org/abs/2608.12656>
  - Relevance (#263): Adapts calibration and selective prediction to multi-turn tool-using agents, useful for tuning `--decision-judge` nudge thresholds in `--auto` and scripted runbooks (#240).
- **SANS Institute — AI-Human Collaboration in Modern SOCs**
  - Relevance (#258, #259): Frames hybrid human-in-the-loop gating where fast calibrated models triage high-volume alerts while irreversible actions remain gated on human approval.

---

## 3. GitHub Repositories — AI Decision Models, Guardrails & Trajectory Judges

Directly relevant to **#256**, **#259**, **#261**, and **#263**.

- **[raxITlabs/decision-models-as-guardrails](https://github.com/raxITlabs/decision-models-as-guardrails)**
  - Open benchmark comparing 19 decision-model and guardrail systems (including native decisions endpoints, Jev, Clef, and managed guardrail APIs) on accuracy, latency, and cost. Useful reference for structuring `scripts/eval_decisions.py` and `fixtures/decisions/` in **#256**.
- **[patronus-protect/decision-model-guard](https://github.com/patronus-protect/decision-model-guard)**
  - Security library specifically targeting prompt-injection attacks against decision models, classifiers, and LLM judges operating on untrusted text (emails, payloads, tool outputs). Directly relevant to **#256**'s adversarial prompt-injection spoofing eval slice and `<partex_untrusted_data>` framing.
- **[mohammadi-hadi/trajectory-judge](https://github.com/mohammadi-hadi/trajectory-judge)**
  - Reference implementation for `arXiv:2611.02035` analyzing multi-step agent trajectories with controlled faults and step-rubrics. Directly relevant to **#263** (`src/partex/agent_adapter/judge.py`).
- **[mohammadi-hadi/judgekit](https://github.com/mohammadi-hadi/judgekit)**
  - Companion audit toolkit for detecting systematic judge biases (position bias, verbosity bias) with bootstrap confidence intervals — useful when validating decision-model eval fixtures in **#256** and **#263**.
- **[P0rtal-Security/awesome-agent-skills-security](https://github.com/P0rtal-Security/awesome-agent-skills-security)**
  - Curated threat-modeling and defense catalog for agent skills, persistence attacks, and trajectory guardrails; relevant to `partex`'s "skills are data, never executed" invariant and **#257**/**#263**.

---

## 4. Structured / Symbolic Security Decision Models (Deterministic Reference)

Relevant as a **deterministic complement** for **#258** (finding triage / prioritization), passive checks, and runbook/policy design (#240). Unlike probabilistic decision models, these encode auditable, deterministic decision trees or tables.

- **[CERTCC/SSVC](https://github.com/CERTCC/SSVC)** — Official Stakeholder-Specific Vulnerability Categorization repo (CMU SEI / CERT/CC), with JSON schemas (`/data/schema/`) and computed decision trees (`/data/json/`) replacing raw numeric severity scores with stakeholder-specific actions.
  - Foundational papers: [Towards Improving CVSS (CMU SEI, 2018)](https://www.sei.cmu.edu/library/towards-improving-cvss/) and [Prioritizing Vulnerability Response: SSVC (CMU SEI, 2019)](https://resources.sei.cmu.edu/library/asset-view.cfm?assetid=653459).
  - Operational guide: [CISA SSVC Guide](https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc).
- **[csaf-rs/ssvc](https://github.com/csaf-rs/ssvc)** — Rust schema-validated SSVC parser/evaluator (clean reference for representing typed decision points and selection lists as data).
- **[theparanoids/PrioritizedRiskRemediation](https://github.com/theparanoids/PrioritizedRiskRemediation)** — Yahoo's open-source enterprise risk remediation decision-tree taxonomy.
- **[gorules/zen](https://github.com/gorules/zen)** — Portable JSON Decision Model (JDM) engine (Rust core with Python bindings) illustrating how deterministic decision tables/graphs can be kept as versioned data outside application code.
- **[red6/dmn-check](https://github.com/red6/dmn-check)** — Static analysis for OMG DMN `.dmn` decision tables to catch logical gaps, overlaps, and dead rows in CI.

---

## Key Takeaways for `partex`

1. **Keep decision models advisory and inspect the full probability distribution (#256, #259):** Research on System-1 security decision models shows aggregate accuracy/Brier scores can hide confident misclassifications on adversarial inputs. Storing full `probs`, enforcing asymmetric thresholds (low threshold for `destructive` warnings, high threshold for `read-like`), and never letting the model auto-approve writes aligns with the literature.
2. **Test adversarial prompt-injection spoofing explicitly (#256, #261):** Because single-pass decision models have no chain-of-thought and ingest target-controlled HTTP/JS excerpts, the adversarial spoofing slice in `fixtures/decisions/` (paired with `<partex_untrusted_data>` framing and patterns from `decision-model-guard`) is essential before choosing default thresholds.
3. **Evaluate deferral / abstention alongside accuracy (#256, #258, #261):** Calibration papers emphasize joint evaluation of selective-automation coverage vs. error rate—matching #256's plan to A/B test threshold abstention (`max(p) < T`) against an explicit `unsure` label.
4. **Judge trajectories by steps, not just final outcomes (#263):** Trajectory-judge research reinforces checking periodic compact tool-call windows (`making-progress` vs. `semantically-looping`) and verifying that cited evidence actually supports `no_issue_found` / `ruled_out` coverage closures.
5. **Separate probabilistic judgement from deterministic policy (#258, #240):** Use probabilistic decision models for noisy semantic classification (SPA shells, soft-404s, heuristic FP triage, skill relevance) and keep deterministic, schema-validated structures (like SSVC trees or `partex`'s passive checks and scope/write gates) as the source of truth.
