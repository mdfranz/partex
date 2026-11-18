# Source skill synthesis for web applications and APIs

This is a synthesis backlog for authorized offensive security assessments. The
order below is the order for reviewing sources and drafting skill content.
It prioritizes reusable inputs and assessment coverage before specialized topics.
The previous [priorities draft](WEB_API_SKILL_PRIORITIES.md) records possible
implementation milestones in the offline review engine.

| Order | Synthesis topic | Existing source skills | What to carry forward |
| --- | --- | --- | --- |
| 1 | Assessment intake and coverage | Strix application-security-testing and web-app-penetration-testing, communitytools pentest-engagement | A common assessment brief covering authorized applications, API specifications, available roles, workflow inventory, and coverage limits. Keep one inventory across browser and API surfaces. |
| 2 | API inventory and protocols | ARTEX api-recon across the three forks, BaaRai api-security, Strix api-security-testing, communitytools api-security | Use ARTEX's distinction between declared and observed routes, Strix's input checklist, and communitytools' protocol taxonomy. Start with REST and add protocol-specific references when the engagement calls for them. Record provenance and completeness for each operation. |
| 3 | Authorization and application logic | BaaRai api-security, communitytools web-app-logic and api-security | Combine the API operation inventory with a shared role, tenant, resource, and workflow vocabulary. Cover both API-level controls and browser-mediated workflows. Record missing role or workflow coverage explicitly. |
| 4 | Authentication, sessions, and browser controls | communitytools authentication and client-side, ARTEX playwright-cli | Give identity and session policy its own coverage section. Use the Playwright companion docs for trace and test-artifact conventions. Link browser evidence to existing API operations where possible. |
| 5 | Evidence, triage, and regression | Strix fix-security-vulnerabilities-with-strix and ci-security-scanning-with-strix, communitytools regression-sweep, risk-prioritiser, and transilience-report-style | Give each finding a stable evidence reference and owner-facing impact statement. Keep regression outcomes distinct from missing evidence. Use the communitytools report schema and its example and tests as concrete packaging references. Design these fields alongside item 1 so the other drafts can reuse them. |
| 6 | Specialized web and API coverage | communitytools server-side and injection, BaaRai api-security and codeaudit, Strix find-security-vulnerabilities-in-code | Add assessment coverage categories for server-side input handling, uploads, and source-assisted review. Keep protocol-specific coverage separate from the common REST and browser vocabulary. |

## Differences that matter for synthesis

- **ARTEX forks**. The three forks contain 16 manifest instances representing
  10 names. All have api-recon, playwright-cli, and scopesentry. The BaaRai
  API security skill covers REST, GraphQL, WebSocket, and SOAP in a single
  manifest. Its API recon manifest and the artex-global manifest have the
  same line count but differ in language and content. FailSafe has additional
  runtime setup files. Use BaaRai as the English starting point and consult
  FailSafe for packaging differences. All three Playwright skills have nine
  companion references. Treat ScopeSentry as an integration dependency.
- **Strix**. Its nine skill manifests include application-wide planning,
  web app and API assessment, CI, and remediation. These are the best source
  for concise intake, result review, and handoff structure. The web app and
  API skill directories have no companion files, so use communitytools for
  topic depth.
- **communitytools**. There are 49 manifests under its skills directory,
  including nested specializations. Its API, authentication, browser,
  server-side, and application-logic skills have extensive companion
  references. Use the indexes as coverage catalogs. The reporting skill's
  schema, sample data, and generator test are concrete artifacts for the
  evidence format. Regression sweep has a companion on diff normalization.
- **Python ARTEX and Pydantic AI**. Python ARTEX has no skill manifests under
  a skills directory. Pydantic AI's agent skills concern its own framework
  and development workflows. Neither supplies web app or API assessment
  coverage for this backlog.

## First three drafts

1. **Assessment brief and coverage matrix.** Include surface, role, workflow,
   evidence reference, and status. Use distinct statuses for assessed,
   unassessed, and inapplicable.
2. **API operation inventory.** Capture operation identity, protocol, contract
   revision, provenance, and linked application workflows. Use this draft to
   determine whether the existing bundle format can represent both declared
   and observed operations.
3. **Authorization and workflow coverage guide.** Use the operation inventory
   and test evidence to map roles and tenants to expected outcomes. Review one
   ordinary browser workflow and one API-only workflow to verify that the same
   vocabulary covers both.

Wider reconnaissance, binary reverse engineering, and infrastructure
specializations sit outside this web app and API synthesis backlog.
