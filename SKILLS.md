# ARTEX Skill Inventory

An inventory of the agent skills shipped in the three Go forks (`artex-global/`,
`BaaRai/ARTEX/`, `failsafe/artex/`). The Python `ARTEX/` prototype has no skill
system — its equivalent is the hardcoded scan modules in `modules/` (see the
main `README.md`).

Skills are **agents' packaged playbooks**: each one is a directory under
`skills/` with a `SKILL.md` manifest that the platform loads at startup and
exposes to the planner/worker agents as on-demand instructions.

---

## How the skill system works (all three Go forks)

- **Layout** — `skills/<name>/SKILL.md` with YAML frontmatter:

  ```yaml
  ---
  name: <skill name>          # display name (may differ from directory name!)
  description: <when to invoke>  # the agent reads this to decide relevance
  allowed-tools: Bash(...)    # optional — tool gating (playwright-cli)
  mcps: <server name>         # optional — host MCP server binding (rea)
  ---
  ```

  Optional companions: `reference.md` (api-recon), `references/*.md`
  (playwright-cli, 9 docs), `scripts/` (api-recon runtime helpers).

- **Loading** — at startup, `server/assembly.go → wireAgentAugment()` calls
  `skill.LoadDir(skillDir)` and packs all visible skills into the agent's
  Skill meta-tool. **Matching is by directory name (`filepath.Base`), not the
  frontmatter `name`** (commented explicitly in failsafe's `assembly.go`).

- **Server API** (from `server/server.go` route table):

  | Route | Purpose |
  |---|---|
  | `GET /api/skills` | List skills |
  | `POST /api/skills` | Create skill |
  | `POST /api/skills/upload` | Upload skill as zip archive |
  | `DELETE /api/skills/{name}` | Delete skill |
  | `GET /api/skills/missing` | **Gap tracking** — skills the agent tried to invoke but that don't exist |
  | `GET /api/skills/{name}/usage` | Per-skill recent invocation ledger |
  | `PUT /api/skills/{name}/meta` | Update skill metadata |
  | `POST /api/skills/{name}/dirs` | Create subdirectory inside a skill |

  The zip uploader (`skill_zip.go`) supports bzip2 and Deflate64 methods on
  top of Go's built-in Store/Deflate, since archivers often write them.

---

## Overview

| Skill | Category | `artex-global` | `BaaRai/ARTEX` | `failsafe/artex` |
|---|---|---|---|---|
| `api-recon` | Recon | ✅ (zh) | ✅ (en) | ✅ (en) |
| `playwright-cli` | Browser automation | ✅ | ✅ | ✅ |
| `scopesentry` | Platform mgmt (MCP) | ✅ (zh) | ✅ (en) | ✅ (en) |
| `api-security` | Offensive API testing | ❌ | ✅ | ❌ |
| `bbot-recon` | Recon breadth | ❌ | ✅ | ❌ |
| `codeaudit` | White-box audit | ❌ | ✅ | ❌ |
| `edr-bypass-re` | Defense telemetry RE | ❌ | ✅ | ❌ |
| `patch-diff` | N-day recovery | ❌ | ✅ | ❌ |
| `php2shell` | LFI → RCE | ❌ | ✅ | ❌ |
| `rea` | Binary/package RE (MCP) | ❌ | ✅ | ❌ |
| | **Total** | **3** | **10** | **3** |

---

## Shared skills (all three repos)

### 1. `api-recon` — frontend API reconnaissance

Discovers, under an authorized engagement: **backend APIs** (paths, methods,
parameters, response bodies), **frontend routes**, and **UI trigger points**
(tabs, modals, table actions). Stops at mapping — no exploitation.

- **Files**: `SKILL.md`, `reference.md`, `scripts/`
- **Scripts** (`scripts/`): `build_perm_tree.py`, `extract_route_map.py`,
  `harvest_static.py`, `spider_mpa.py` (Python), `preload.js` +
  `runtime_harvest.js` (Puppeteer-based runtime harvest), `package.json`,
  `package-lock.json`.
- **Divergences**:
  - `artex-global`: Chinese description and body.
  - `BaaRai` / `failsafe`: English, near-identical to each other (minor
    phrasing: "Invoke this skill…" vs "Use this skill…").
  - `failsafe` adds `scripts/.npmrc` + `scripts/ensure-runtime.sh`: the runtime
    check **refuses to repair an image over the network** — when
    `ARTEX_PUPPETEER_PATH` is set it verifies the absolute path resolves,
    otherwise installs only from the copied official lockfile
    (`npm ci --ignore-scripts --registry=https://registry.npmjs.org/`).
    `package.json` pins `puppeteer-core` to `25.17.0` and the Dockerfile
    jq-guards every lockfile URL to the official npm registry.

### 2. `playwright-cli` — browser automation

Automates browser interactions and Playwright tests via the `playwright-cli`
npm package. Frontmatter identical in all three repos, including
`allowed-tools: Bash(playwright-cli:*) Bash(npx:*) Bash(npm:*)`.

- **Files**: `SKILL.md`, `references/` — 9 reference docs:
  `element-attributes.md`, `playwright-tests.md`, `request-mocking.md`,
  `running-code.md`, `session-management.md`, `storage-state.md`,
  `test-generation.md`, `tracing.md`, `video-recording.md`.
- **Divergences**: `references/` is **byte-identical across all three
  repos**. `SKILL.md` differs in exactly one example line (a snapshot
  filename placeholder vs. a dated example).

### 3. `scopesentry` — ScopeSentry platform management (MCP)

Manages a deployed ScopeSentry scanning platform — projects, tasks, templates,
assets, nodes — through the ScopeSentry MCP, from a client such as Cursor. No
local source needed; requires a reachable instance and an API key.

- **Files**: `SKILL.md` only.
- **Divergences**:
  - Frontmatter **name** differs: `scopesentry-mcp` (artex-global,
    failsafe) vs `scopesentry` (BaaRai). Since the platform matches skills by
    **directory name** (`scopesentry`), both resolve correctly, but API
    responses that echo the frontmatter name will differ.
  - `artex-global`: Chinese description; `BaaRai` / `failsafe`: English.

---

## BaaRai-only skills (7)

All seven live in `BaaRai/ARTEX/skills/<name>/SKILL.md` (no extra files).
Three carry attribution to the [`zhaoxuya520/reverse-skill`](https://github.com/zhaoxuya520/reverse-skill)
playbook collection (MIT License), noted per skill.

| Skill | Frontmatter name | Purpose | Attribution |
|---|---|---|---|
| `api-security` | `api-security` | Authorized offensive testing of REST/GraphQL/WebSocket/SOAP APIs **beyond recon**: BOLA/IDOR/BFLA, JWT & OAuth weaknesses, GraphQL abuse, input validation, business logic, rate-limit trust confusion, excessive data exposure. Access-control findings require a second account/role to prove the boundary. | reverse-skill `api-security` |
| `bbot-recon` | `bbot-recon` | Breadth-first recon on authorized targets via bbot (recursive event-graph scanner, pinned v3.0.2, preinstalled in image): subdomain enumeration, takeover surface, archived URLs, parameter mining, IP/ASN enrichment. Hard **program-policy gates**: passive zero-touch mode when scanners are banned; active modules only when allowed. | — |
| `codeaudit` | `codeaudit` | White-box audit of provided/fetched source: attacker-first forward analysis from every user-controllable input to dangerous sinks, adversarial verification, PoC with measured impact. **Production code only** — test/build/vendored/generated code excluded. | — |
| `edr-bypass-re` | `edr-bypass-re` | For authorized adversary simulation: map what an EDR/AV actually monitors (user-mode hooks, kernel callbacks, ETW, AMSI), survey installed hooks from memory, evaluate countermeasures in an isolated lab. Maps to MITRE ATT&CK **T1562** (Impair Defenses), T1562.001/.006, with T1055/T1027 adjacent. | reverse-skill `edr-bypass-re` |
| `patch-diff` | `patch-diff` | Recover a vulnerability from its vendor fix: diff patched vs. unpatched builds, infer bug class from added guards, verify with a PoC that crashes only the unpatched build. For CVEs without public PoC, Patch Tuesday triage, backport gaps, closed-source patches. | reverse-skill `patch-diff-exploit` |
| `php2shell` | `php2shell` | Turn a verified LFI/unsafe-include on PHP 5.4–8.5.11 (default `session.upload_progress`) into RCE via the session-file-injection chain (**CVE-2026-109618/109619**), lab-first and gated by program policy; also passive detection of the vulnerable config. Vendored PoCs live at repo-level `scripts/poc/php2shell/` (upstream ikow/php2shell-poc, MIT). | ikow/php2shell-poc |
| `rea` | `rea` | Reverse-engineer binaries and packages (ELF, PE, Mach-O, APK, IPA, HAP, WASM, ZIP/JAR, JS bundles) through the **`rea` MCP server running on the host** — tools are named `mcp__rea__<tool>` and must be fetched as deferred tools. Static analysis: embedded secrets, endpoints, native library review, string extraction, deobfuscation. | — |

---

## Server-side skill subsystem (per repo)

All three forks ship the same core skill management in `server/`:

| File | `artex-global` | `BaaRai/ARTEX` | `failsafe/artex` |
|---|---|---|---|
| `skill_zip.go` — upload/unzip | ✅ | ✅ | ✅ |
| `skill_usage.go` — invocation ledger | ✅ | ✅ | ✅ |
| `skill_gaps.go` — missing-skill tracking | ❌ | ✅ | ❌ |
| `shipped_skills_test.go` | ❌ | ✅ | ❌ |
| `skill_frontmatter_test.go` | ❌ | ✅ | ❌ |
| `skill_zip_localized_test.go` | ✅ | ❌ | ❌ |
| `skill_upload_test.go` | ✅ | ✅ | ✅ |

BaaRai's extras (`skill_gaps.go`, shipped-skills and frontmatter tests) pair
with its RSI contract: the gap tracker feeds Loop B (evidence-gated lessons),
and the shipped-skills test pins the expected skill set so harness edits are
visible in CI.

---

## Skill counts per repo

| Repo | Skill dirs | Files | Notes |
|---|---|---|---|
| `artex-global/skills/` | 3 | 21 | Chinese api-recon & scopesentry; `references/` + `scripts/` trees |
| `BaaRai/ARTEX/skills/` | 10 | 28 | Shared 3 (English) + 7 unique playbooks |
| `failsafe/artex/skills/` | 3 | 23 | English; hardened api-recon runtime (`ensure-runtime.sh`, `.npmrc`, pinned `puppeteer-core` 25.17.0) |

All skills are invoked under the platforms' standing rules visible in every
`SKILL.md`: **authorized engagements only**, finding quality gates, and the
adversarial gate on tool output.