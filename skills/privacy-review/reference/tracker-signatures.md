# Tracker Signatures

Data for the `privacy-signals` check (`src/partex/checks/privacy_signals.py` carries the same table;
`tests/test_check_privacy_signals.py` fails if the two drift apart). A rule fires on a **strong** marker;
**weak** markers only corroborate. Matched text is never copied into a finding.

| Vendor | Category | Strong markers | Weak markers | False positive the rule avoids |
|---|---|---|---|---|
| Google Tag Manager | analytics | `googletagmanager.com/gtm.js` loader | `GTM-XXXXXXX` container ID | a container ID in documentation text |
| Google tag / Analytics (gtag.js) | analytics | `googletagmanager.com/gtag/js` loader, `google-analytics.com/(analytics\|ga\|collect)`, `gtag('config'` | GA4 measurement ID string | the bare word "analytics" |
| Sentry | error-monitoring | `ingest.sentry.io` host, `Sentry.init(` | `@sentry/*` package name | a package name in a license list |
| Amplitude | analytics | `cdn.amplitude.com` / `api2.amplitude.com`, `amplitude.init(` | `@amplitude/analytics` | **"amplitude" as an SVG attribute name** |
| PostHog | analytics | `*.i.posthog.com`, `posthog.init(`, `posthogApiKey` config field, `phc_…` project key | `_posthogChunkIds` source-map marker | a build-tool comment mentioning PostHog |
| Segment | analytics | `cdn.segment.com/analytics.js` | `analytics.load(` | a generic `analytics` variable |
| Mixpanel | analytics | `cdn.mxpnl.com`, `api.mixpanel.com`, `mixpanel.init(` | | |
| Heap | analytics | `cdn.heapanalytics.com`, `heap.load(` | | |
| Microsoft Clarity | session-replay | `clarity.ms/tag` | | |
| Hotjar | session-replay | `static.hotjar.com`, `_hjSettings` | | |
| FullStory | session-replay | `fullstory.com/s/fs.js`, `_fs_host` | | |
| LogRocket | session-replay | `cdn.logrocket.io`, `LogRocket.init(` | | |
| Datadog RUM | session-replay | `datadoghq-browser-agent.com`, `DD_RUM.init(` / `datadogRum.init(` | | |
| Meta (Facebook) Pixel | advertising | `connect.facebook.net/…/fbevents.js`, `fbq('init'` | | |
| LinkedIn Insight Tag | advertising | `snap.licdn.com/li.lms-analytics`, `_linkedin_partner_id` | | |
| X (Twitter) Pixel | advertising | `static.ads-twitter.com/uwt.js`, `twq('config'` | | |
| TikTok Pixel | advertising | `analytics.tiktok.com`, `ttq.load(` | | |
| HubSpot | advertising | `js.hs-scripts.com`, `js.hs-analytics.net` | `_hsq` queue | |
| Intercom | support-chat | `widget.intercom.io`, `js.intercomcdn.com`, `window.intercomSettings`, `Intercom('boot'` | | **"Intercom" as a hardware product name** |
| Google reCAPTCHA | captcha | `google.com/recaptcha/api.js` (or `enterprise.js`), `recaptcha.net/recaptcha` | `grecaptcha.execute(` | |
| hCaptcha / Turnstile | captcha | `hcaptcha.com/1/api.js`, `challenges.cloudflare.com/turnstile` | | |

## Consent-management signals

Any one of these anywhere in the captured evidence counts as a consent signal: OneTrust
(`cdn.cookielaw.org`, `OptanonConsent`), Cookiebot, Osano, Usercentrics, TrustArc, Didomi, Quantcast Choice,
Termly, Klaro, `cookieconsent`, the IAB TCF API (`__tcfapi`), and Google Consent Mode
(`gtag('consent'`). Their absence is reported as `consent:no-cmp-signal` and worded as a limit of static
evidence.
