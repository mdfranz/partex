# Decision Models (System One / Jev) — Curated Reference Index

Deduplicated reference index extracted from November 2026 research on Jev-style System One
decision models for vulnerability validation, classification, calibration, adversarial
robustness, and open-weight alternatives.

- **Type labels:** `Preprint` (arXiv, not peer-reviewed), `Published` (peer-reviewed /
  institutional), `Vendor` (company engineering post or docs), `Repo` (GitHub / Hugging Face),
  `Explainer` (commentary / radar).
- Nearly all security-specific sources date from September–November 2026 and are preprints,
  vendor evaluations, or open-source experiments.

---

## 1. Security-Specific Decision-Model Papers

| Paper | Authors / Org | ID | Type | Relevance to `partex` |
|---|---|---|---|---|
| [JevVibe: Efficient Classification-Guided Secure Code Generation](https://arxiv.org/abs/2609.34963) | Rezvani, Behrouzi, Sadeghi (TU Darmstadt) | 2609.34963 | Preprint | 50-way CWE classification; Top-5 `0.836`, MRR `0.624` vs `0.628` at 55.9× lower cost (#257, #258) |
| [Cyber-JEV: Matched Contrastive Fine-Tuning of Language Models for Fast Source-Code Vulnerability Triage](https://arxiv.org/abs/2611.02957) | Zhao et al. | 2611.02957 | Preprint | Function-level scoring; 33 vs 7 vulns at 1% FPR; exposes 18.8% exact probability ties on pre/post-fix pairs (#256, #258) |
| [Calibrated Decision Models for Autonomous Penetration-Testing Harnesses: JEV and Laya as System One Decision Layers](https://arxiv.org/abs/2609.28940) | Joas Antonio dos Santos | 2609.28940 | Preprint | NeuroSploit DP1–DP4; validator-gated adjudication; BOLA structured-evidence failure mode (#258, #259, #263) |
| [JEV as a Judge for Agent Trace Security](https://arxiv.org/abs/2609.34862) | — | 2609.34862 | Preprint | Decision models vs. generative judges on agent-trace security labels (#263) |
| [Benchmarking System One decision models against trained classifiers and language models for automated decision gates](https://arxiv.org/abs/2610.00346) | Rafe, Das (Texas State) | 2610.00346 | Preprint | Automated decision-gate design and threshold selection (#256, #259) |
| [The Hitchhiker's Guide to System 1 Models: Fast Decision-Making Beyond LLMs](https://arxiv.org/abs/2610.33775) | Haggai Roitman | 2610.33775 | Preprint | Survey of the System One decision-model category |

---

## 2. Adversarial Attacks on Decision Models

Directly relevant to **#256** (`fixtures/decisions/` adversarial prompt-injection spoofing
slice), **#258**, **#259**, and **#261**.

| Paper | Authors / Org | ID | Type | Attack Vector & Key Finding |
|---|---|---|---|---|
| [S1-Evo: Experience-Guided Evidence Competition Attacks on Typed System-1 Decision Models](https://arxiv.org/abs/2611.16937) | Wang et al. | 2611.16937 | Preprint | `71.99%` mean attack success on `jev-1.14` via competing evidence |
| [JevBreak: Your Model, Their Decision](https://arxiv.org/abs/2611.03759) | Birur et al. (Enkrypt AI) | 2611.03759 | Preprint | Slot Attack; appended text forces chosen wrong label (`32–99%` ASR) |
| [DICE: Tilting the Odds through Interface Attacks on System One Model](https://arxiv.org/abs/2610.14404) | — | 2610.14404 | Preprint | Compromised state, question, or interpretation adapters flip decisions |
| [JevOut: Natural Context Can Flip Decision Models](https://arxiv.org/abs/2609.30243) | Zixiang Xu (USC) | 2609.30243 | Preprint | Fluent natural context redirects `61.4%` of correct decisions |
| [FlipJev: Fast Black-Box Red Teaming Finds Universal Adversarial Suffixes for Typed Decision Models](https://arxiv.org/abs/2610.38895) | — | 2610.38895 | Preprint | Universal suffix attacks (`~20%` Jev, `77%` `gpt-6-luna`); bypasses confidence thresholds |
| [JevAdvBench: A Benchmark and Black-Box Attacks for RLCD Models](https://arxiv.org/abs/2609.31142) | — | 2609.31142 | Preprint | Attack benchmark across `jev-1.13.0` and 8 open decision models |
| [Decision Hijacking: Prompt Injection Attacks on Jev's Typed Probabilistic Decisions](https://arxiv.org/abs/2609.28613) | — | 2609.28613 | Preprint | Injection via tool results (InjecAgent reconstruction) |
| [One Word Opens the Gate: The Option-Channel Attack on Typed Decision Models as Agent Guardrails](https://arxiv.org/abs/2610.12292) | — | 2610.12292 | Preprint | Misleading option names open agent guardrails (`100%` ASR on 4/5 models under adaptive attack) |

---

## 3. Calibration, Framing Sensitivity & Cascade Evaluations

Directly relevant to **#256** (thresholding, abstention, prompt discipline) and **#263**.

| Paper | Authors / Org | ID | Type | Key Finding |
|---|---|---|---|---|
| [Evaluating and Benchmarking the System One Model Jev](https://arxiv.org/abs/2609.37647) | Deußer et al. | 2609.37647 | Preprint | 37-dataset eval; `Choice` ECE `0.028`, but binary `Noul` needs tuned thresholds |
| [JEV-as-a-Judge: Accept When Confident, Escalate When Unsure](https://arxiv.org/abs/2609.26550) | Li, Miao, Krishnan, Padman (CMU) | 2609.26550 | Preprint | Gate-and-cascade; 31% escalation beats GPT-6 at 41% cost |
| [Commit or Abstain? System One Decision Models, LLMs, and Missing Legal Authority](https://arxiv.org/abs/2610.29961) | M. Mikail Demir (SUNY Albany) | 2610.29961 | Preprint | Abstention behavior under missing evidence |
| [Typed Decision Models under Prevalence Shift and Label Budgets](https://arxiv.org/abs/2610.26325) | — | 2610.26325 | Preprint | Run-to-run probability variance and rare-event base rates |
| [How far can a commercial decision model's probabilities be trusted? A calibration audit of Jev](https://escholarship.org/uc/item/4t4449jv) | Lingsen Meng (UCLA) | — | Published | Calibration shifts with question wording |
| [Jev thinks "I don't know", but doesn't say it: Sys1Cal-v1](https://arxiv.org/abs/2609.35342) | — | 2609.35342 | Preprint | Per-primitive calibration audit (`Noul`, `Choice`, `Score`) |
| [TypedBench: Calibration, Framing Sensitivity, and Cost in System One Decision Models](https://arxiv.org/abs/2610.11392) | — | 2610.11392 | Preprint | Framing-sensitivity benchmark |
| [Understanding Jev-Style System One Models: Does Structure Reduce Selection Bias?](https://arxiv.org/abs/2610.35826) | Song, Zheng, Ma, Zhou | 2610.35826 | Preprint | Option-order bias across Jev and 12 open reproductions |
| [To Jev or Not to Jev: When Can System-1 Decision Models Replace LLM Judges?](https://arxiv.org/abs/2611.00505) | — | 2611.00505 | Preprint | Compares `jev-1.14`, DReX-Max, `pplx-decider`, `d1` |
| [DecisionPivot: A Diagnostic Benchmark for Decision Models in LLM Systems](https://arxiv.org/abs/2610.28522) | — | 2610.28522 | Preprint | Diagnostic benchmark for agent/LLM decision routing |

---

## 4. Vendor & Industry Security Evaluations

| Source | Organization | Date | Key Contribution |
|---|---|---|---|
| [Testing Jev on security triage and classification](https://www.runsybil.com/blog/testing-jev-on-security-triage-and-classification) | RunSybil | Nov 2026 | Pentest FP filter (CatBoost over Noul → `63.2%` TPR / `86.7%` TNR), pairwise root-cause dedup, OWASP tuning |
| [Jevil in the details: System One model security](https://www.hiddenlayer.com/research/system-one-model-security) | HiddenLayer | Oct 2026 | TokenBreak & indirect prompt injection against Jev and OpenAI Decisions |
| [Jev is not a language model, but it breaks like one](https://blog.checkpoint.com/ai-security/jev-is-not-a-language-model-but-it-breaks-like-one-prompt-injection-against-a-typed-decision-model/) | Check Point | Sep 2026 | Agentic prompt-injection tests against typed decision models |
| [Jev Decision Models on Trial](https://blogs.cisco.com/ai/jev-decision-models-on-trial) | Cisco | Oct 2026 | 8 safety benchmarks at 0.5% FPR: zero-shot Jev vs. Gemma 4 31B vs. Laya vs. fine-tuned classifier |
| [AI in Your SOC Without Breaking the Bank: Testing Jev on Blue Team Workflows](https://www.immersivelabs.com/resources/c7-blog/ai-in-your-soc-without-breaking-the-bank-testing-jev-on-blue-team-workflows) | Immersive Labs | 2026 | Stateless SOC event flagging (vs. 18 Sigma rules) vs. stateful incident threading failure |
| [Building a Faster, Cheaper Vulnerability Scanner With Jev](https://depthfirst.com/research/building-a-faster-cheaper-vulnerability-scanner-with-jev) | DepthFirst | 2026 | `dfbench`: parallel per-CWE binary queries over cached context |
| [Introducing Security-One: a decision model for security](https://www.superagent.sh/blog/introducing-security-one) | Superagent | 2026 | Apache-2.0 `Security-One 27B` security decision model (BIPIA, Deepset, NotInject) |
| [Jev's paradox: hidden cost of cheap AI decisions](https://www.sophos.com/blog/jevs-paradox-hidden-cost-of-cheap-ai-decisions) | Sophos | 2026 | Overconfident errors (`p=1.0` wrong on 6/102 items) and reviewer-time economics |
| [Jev security alert triage](https://torq.io/blog/jev-security-alert-triage/) | Torq | 2026 | Prompt/framing sensitivity in security alert triage |
| [AIMultiple Decision Models Benchmark & System One Index](https://aimultiple.com/decision-models) | AIMultiple | Nov 2026 | 68→78 decision models; documents `<=45.0%` ceiling on security flaw severity rating |
| [Thoughtworks Technology Radar: Decision models (Assess)](https://www.thoughtworks.com/de/radar/platforms/decision-models) | Thoughtworks | Nov 2026 | Industry positioning; recommends defined eval criteria |
| [Simon Willison: decision-models tag](https://simonwillison.net/tags/decision-models) | Simon Willison | Sep–Nov 2026 | Ongoing tracking of Jev, OpenAI Decisions API, and Gemini Decision 1 |

---

## 5. GitHub Repositories & Datasets (Security Decision Models)

| Repository | Focus | Why It Matters for `partex` |
|---|---|---|
| [Sarim-MBZUAI/awesome-jev-security](https://github.com/Sarim-MBZUAI/awesome-jev-security) | Curated index | Comprehensive index of security attacks, defenses, and benchmarks for System One models |
| [Oscar-dzy/Awesome-jev-papers](https://github.com/Oscar-dzy/Awesome-jev-papers) | Curated index | Broad paper tracker for System One models (also <https://awesomejev.github.io/>) |
| [san3ncrypt3d/jev-security-prioritization](https://github.com/san3ncrypt3d/jev-security-prioritization) | Validation & prioritization | "Facts in, rules decide" (450 findings); `"known false positive"` steering test (17/20 flipped); explicit `"unknown"` behavior |
| [NurvX/neurosploit (PR #39)](https://github.com/NurvX/neurosploit/pull/39) | Pentest adjudication | TypeSafe decision layer inside an autonomous pentest harness |
| [timuroncu/ai-vulnerability-triage](https://github.com/timuroncu/ai-vulnerability-triage) | SAST FP triage | CodeQL on RealVuln (`97.8%` recall, `62.9%` precision) |
| [RicardoZ-kisara/cyber-jev](https://github.com/RicardoZ-kisara/cyber-jev) | Function-level scoring | Code for the Cyber-JEV matched contrastive fine-tuning paper |
| [Red5d/jev-cvss](https://github.com/Red5d/jev-cvss) | CVSS v3.0/3.1/4.0 | "Select, then compute" pattern (decision model picks metrics, code computes score) |
| [ChristianAlexander/effect-jev-cwe](https://github.com/ChristianAlexander/effect-jev-cwe) | CWE hierarchy | Beam search over MITRE CWE tree to handle >255 classes |
| [knowlet/jev-security (PR #1)](https://github.com/knowlet/jev-security/pull/1) | Dedup & severity | Judge/explainer separation (decision model decides; LLM explains without override) |
| [existential-birds/daydream (issue #1583)](https://github.com/existential-birds/daydream/issues/1583) | Host deduplication | Spec for replayable labelled eval set, pinned version, and LLM fallback |
| [trapstreet/jev-class-cve-bench](https://huggingface.co/datasets/trapstreet/jev-class-cve-bench) | CWE dataset (HF) | 30-way CWE benchmark from CVE descriptions |

---

## 6. Open-Weight Local Decision Models & Recipes

Relevant for future local-only `resolve_decision_model()` backends (**#256**) when target
evidence or candidate secrets (**#258**) cannot be sent to a hosted API.

| Model / Resource | Link | Notes |
|---|---|---|
| **Security-One 27B** | [Superagent blog](https://www.superagent.sh/blog/introducing-security-one) | Apache-2.0 security-specific decision model |
| **Laya** | [NandhaKishorM/laya](https://github.com/NandhaKishorM/laya) | Apache-2.0 421M multilingual encoder trained on Brier score; used in NeuroSploit |
| **Nimble** | [bespokelabsai/nimble](https://github.com/bespokelabsai/nimble) | Bespoke Labs (Qwen3.5-9B) |
| **Kev** | [jaredpalmer/kev](https://github.com/jaredpalmer/kev) | LoRA decision model on Qwen |
| **openjev-sglang** | [ekzhang/openjev-sglang](https://github.com/ekzhang/openjev-sglang) | Jev request shape served on SGLang |
| **Jeva-4B** | [arXiv:2610.18773](https://arxiv.org/abs/2610.18773) | Research architecture with explicit null-option detection |
| **Releasing the Inner Jev** | [arXiv:2610.17205](https://arxiv.org/abs/2610.17205) | Training-free open decision models (Gemma 4 31B, Qwen3.6-27B) |
| **AnyJev Technical Report** | [arXiv:2610.00831](https://arxiv.org/abs/2610.00831) | Training-free readout with option-order correction |
| **Jev Decision Index** | [multimodalart/jev-decision-index](https://huggingface.co/spaces/multimodalart/jev-decision-index) | Community leaderboard (Hugging Face Space) |

---

## 7. Unverified Claims (Do Not Cite Without Locating Primary Source)

Flagged in the source reference list as unlocated during verification:
- *"Fast Models, Slow Evidence"* (cited as `arXiv:2610.02267`) — not found by title or ID.
- *"Beyond Answer Confidence"* (Shankaranarayana et al., cited as `arXiv:2610.01006`) — not found by title or ID.
- *Eye Research, "Rise of the Jev-Clones"* (25 Sep 2026) — not located.
- *`rzhade3/cwe-classifier`* beam-search figures (44.6% vs 21.0%) — fetched repo showed an older embedding tool.
- *Startup Fortune "Jev leak" article* — misreported a joke about the 101 possible probability values; not a real breach.
