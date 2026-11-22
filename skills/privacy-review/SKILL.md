---
name: privacy-review
description: >-
  Invoke when reviewing captured pages, scripts and runtime config for third-party trackers,
  analytics and session-replay SDKs, support widgets, CAPTCHA providers, and whether any
  consent-management signal accompanies them.
modes:
  - passive
checks:
  - privacy-signals
license: Apache-2.0
metadata:
  author: partex
---

# Privacy Review: Trackers and Consent Signals

Record which third-party tracking SDKs the application references and whether any consent
mechanism shows up next to them. Passive: the check reads evidence already captured and sends no
requests. Run it after discovering and downloading the application's JavaScript bundles
(`discover_js_assets` and `download_asset`), because most trackers are loaded from scripts, not
from the HTML.

## Signals, not verdicts

- A finding says an SDK is **referenced**. It does not say what data is sent, to whom, or whether
  that happens before consent. Never write "violates GDPR/ePrivacy/CCPA" or any legal conclusion.
- "No consent-management signal observed" is a **limit of static evidence**. A consent flow may
  load later, vary by region, or live server-side. Always recommend confirming in a real browser
  session with a clean profile (M7 browser harness once available) and never report it as "the site
  has no consent banner".

## Check Mapping (`privacy-signals`)

| Finding subject | Severity | Meaning |
|---|---|---|
| `tracker:<vendor>` | `info`; `low` for session-replay and advertising pixels | A captured source references the vendor by a strong marker (loader URL, init call, config field, ingest host). One finding per vendor, every source cited. |
| `consent:no-cmp-signal` | `info` | Non-essential trackers (analytics, session replay, advertising) are referenced and no consent-platform signature or consent API call appears anywhere in the captured evidence. |

The signature table, with the markers and the false positives each rule avoids, is in
[`reference/tracker-signatures.md`](reference/tracker-signatures.md).

## Precision rules

- **A vendor word alone is not evidence.** "amplitude" is an SVG attribute name, "Intercom" is a
  hardware product name, "posthog" can be a build-tool comment. Require a loader URL, an init call,
  a config field (`posthogApiKey`), or an ingest host.
- **Weak markers corroborate, never decide.** A bare container ID or a `_posthogChunkIds` source-map
  marker does not produce a finding on its own.
- **Never copy matched text into a finding.** Project keys, DSNs and measurement IDs stay out of
  descriptions; report the marker's label only.
- **Public-by-design values are not secrets.** An analytics measurement ID, a Sentry DSN, a reCAPTCHA
  site key and a PostHog project key are meant to be in client code. Report the tracker; do not
  escalate them as leaked credentials (that is `js-analysis`'s job for credential-shaped values).
- **Essential versus non-essential.** Error monitoring, CAPTCHA and support chat are rated `info`
  and do not on their own trigger the missing-consent note; analytics, session replay and
  advertising do.

## Agent guidance

1. Make sure scripts were downloaded (`discover_js_assets`, then `download_asset`).
2. Run `run_check('privacy-signals')`, then read the findings with `list_findings`.
3. For each tracker, say which sources reference it and offer the operator the browser confirmation
   step; do not speculate about data flows.
4. Do not request the tracker's own hosts to "check" them. They are out of scope unless the operator
   has added them, and this check never needs traffic.

## Not covered yet

Cookie-based trackers from `Set-Cookie`, the full inventory of third-party hosts a page contacts,
personal data in authenticated responses, and policy-link discovery. See issue #224.
