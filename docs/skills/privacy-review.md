# Research: Privacy Review (`privacy-signals`)

- **Priority / Slice:** post-M6 skill slice for #224 (first increment: trackers and consent signals).
- **Skill / check:** `skills/privacy-review/` and the passive `privacy-signals` check
  (`src/partex/checks/privacy_signals.py`).
- **Standards and references (context only; findings never state a legal conclusion):**
  - [GDPR (Regulation (EU) 2016/679) Arts. 5–7 & 13](https://eur-lex.europa.eu/eli/reg/2016/679/oj)
  - [ePrivacy Directive (2002/58/EC, as amended by 2009/136/EC) Art. 5(3)](https://eur-lex.europa.eu/eli/dir/2002/58/2009-12-19)
  - [California Consumer Privacy Act / CPRA (Cal. Civ. Code § 1798.100 et seq.)](https://leginfo.legislature.ca.gov/faces/codes_displayText.xhtml?lawCode=CIV&division=3.&title=1.81.5.&part=4.)
  - [OWASP Top 10 Privacy Risks Project](https://owasp.org/www-project-top-10-privacy-risks/)
  - [OWASP Application Security Verification Standard (ASVS) V8 — Data Protection](https://owasp.org/www-project-application-security-verification-standard/)
  - [IAB Europe Transparency & Consent Framework (TCF v2.2 `__tcfapi`)](https://iabeurope.eu/transparency-consent-framework/) & [W3C Global Privacy Control (GPC)](https://w3c.github.io/gpc/)
  - [CWE-359 — Exposure of Private Personal Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/359.html)

## 1. Motivation (what the local corpus showed)

A review of four live runs (a network-appliance web UI and a SaaS web app) found 30 findings, all from
`js-analysis`. None covered trackers or consent, although the downloaded bundles loaded Google's gtag
(analytics) and Sentry on the appliance and PostHog on the SaaS app (a `posthogApiKey` field in the runtime
config). The "potential secret" mediums there were public-by-design identifiers a triager had to open each
bundle to dismiss.

## 2. Design

- **Evidence:** JavaScript (inline, downloaded or response) and 2xx text/HTML/JSON bodies. Passive only.
- **Signatures are data** (`TRACKERS`, `CONSENT_MARKERS`), mirrored in the skill's
  `reference/tracker-signatures.md`; a test fails if they drift. The check never imports or executes
  anything under `skills/`.
- **Strong versus weak markers.** A finding needs one strong marker (loader URL, init call, config field,
  ingest host). Weak markers (container IDs, source-map chunk markers, package names) corroborate only.
- **No matched text in findings.** Project keys, DSNs and IDs are never copied; only marker labels are.
- **Severity:** `info` for analytics, error monitoring, support chat and CAPTCHA; `low` for session replay and
  advertising pixels. Nothing above `low` in this increment.
- **Consent note:** `consent:no-cmp-signal` (`info`) when non-essential trackers (analytics, session replay,
  advertising) appear and no consent-platform signature or consent API call does. Worded as a limit of
  static evidence and always paired with a recommendation to confirm in a browser.

## 3. False-positive guardrails (from the corpus)

| Loose match | What it really was | Rule |
|---|---|---|
| "amplitude" | an SVG attribute name | needs a host or `amplitude.init(` |
| "Intercom" | a hardware product name | needs the widget host, `intercomSettings` or `Intercom('boot'` |
| "posthog" | a build-tool chunk marker | `_posthogChunkIds` is weak; needs the host, `posthog.init(` or the config key |

## 4. Not in this increment

Cookie-based trackers from `Set-Cookie`, the inventory of third-party hosts a page contacts, classifying
client-side keys as public-by-design versus credentials, personal data in authenticated responses, and
policy-link discovery. Pre-consent loading can only be confirmed in a browser (M7, #191).
