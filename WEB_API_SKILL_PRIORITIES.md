# Web application and API skill priorities

Prioritize skills that help application teams review evidence and validate their
own security controls in CI. Use synthetic evidence and application-owned test
suites. Rank by impact on the application, breadth of coverage, and readiness
of the existing evidence model.

The milestone labels below describe where work fits into the [project plan](PLAN.md).
P0 establishes the evidence contract and ships the first skill. P1 and P2 are
backlog priorities.

| Priority | Skill | First deliverable | Acceptance criteria |
| --- | --- | --- | --- |
| P0 | Web response policy review | Extend the M1 header-review fixture with separate HTML, API, and redirect examples. Document when each policy applies. | A compliant response and a policy violation produce distinct outcomes. Inapplicable and incomplete evidence are distinguishable. Findings cite the response and redact cookie values. |
| P1.1 | API contract and data exposure review | Compare recorded API responses against an application-owned OpenAPI contract and an explicit field exposure policy. Start with JSON responses. | Fixtures cover a conforming response, a disallowed field, and a response without a matching contract. Sensitive values stay out of findings and exports. |
| P1.2 | Authorization policy coverage | Compare an owner-defined role and tenant access matrix with results from the application's integration tests. | Distinguish a policy mismatch from a missing test. Identify the operation, expected policy, and supporting test result. |
| P1.3 | Browser session and identity controls | Review cookie configuration and app-owned test results for session expiration, logout, and CSRF protection. | Distinguish controls visible in a response from controls that require application test evidence. Fixtures cover an expected result, a failing control, and missing evidence. |
| P2.1 | API gateway policy coverage | Review gateway policy and existing CI results for request size limits, rate limits, and error response handling. | Distinguish a declared limit, a limit verified by CI, and a limit with no evidence. |
| P2.2 | API inventory and lifecycle review | Compare the published contract, owner-maintained route inventory, and recorded traffic. | Flag contract drift and deprecated operations still present in evidence. Describe unobserved operations as a coverage gap. |

Authorization coverage has high impact. API contract review comes first because
it establishes stable operation identifiers and evidence references that the
authorization skill can reuse. Authorization coverage can proceed in parallel
if the application already exports operation-keyed integration test results.

## First development slice

1. Keep the M1 header-review fixture as the initial implementation target. Define
   expected behavior by response type and add compliant, failing, and
   insufficient-evidence cases.
2. Use M2 to prove the skill manifest and check registry contract. Keep
   descriptions, applicability guidance, and evidence interpretation in the
   skill. Keep deterministic evaluation in registered check code.
3. Prototype API contract review against an offline bundle and a synthetic
   OpenAPI document. Use that prototype to decide how the bundle links an
   operation and a contract revision to captured evidence.
4. Define an import format for application-owned CI results before building
   authorization or session coverage. Include policy revision, operation or
   test identifier, expected outcome, observed outcome, and evidence reference.

A skill is ready when its fixtures demonstrate compliant behavior, a supported
finding, and insufficient evidence. Findings should reference the evidence and
name the relevant application control. Broader reconnaissance and reverse
engineering have lower priority for this web application and API backlog. The
existing [ARTEX skill inventory](SKILLS.md) provides examples of skill packaging.
