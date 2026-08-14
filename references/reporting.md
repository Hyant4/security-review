# Severity and report format

## Severity

Score by realistic impact and exploitability in the assessed deployment. Do not assign a CVSS score without sufficient inputs; if using CVSS, state the vector/version and assumptions.

| Severity | Typical meaning | Expected response |
|---|---|---|
| Critical | Unauthenticated/low-friction compromise of many users, sensitive systems, or high-value data; active exploitation likely. | Contain and fix immediately; consider incident response. |
| High | Material account/data/privilege impact with feasible preconditions, or reliable bypass of a major control. | Prioritize remediation before release or under an explicit risk acceptance. |
| Medium | Meaningful but bounded impact, or notable weakness requiring nontrivial conditions. | Fix in the near-term planned cycle and add regression coverage. |
| Low | Limited impact, defense-in-depth gap, or difficult-to-exploit condition. | Track and fix opportunistically. |
| Informational | Improvement, observation, or insufficient evidence for a vulnerability. | Record context; do not present as a confirmed security defect. |

Adjust upward for cross-tenant access, privileged accounts, regulated/sensitive data, external side effects, broad exposure, and easy automation. Adjust downward only with verified compensating controls. Never hide conditional risks: name their preconditions.

## Report

```markdown
# Security review — <system/revision>

## Scope and method
- Revision/environment:
- Review type and authorized techniques:
- In scope / exclusions:
- Evidence sources and date:

## Executive summary
<risk posture, number of findings by severity, release recommendation, major limitations>

## Findings
| ID | Severity | Status | Area | Title | Affected asset | OWASP/ASVS mapping |
|---|---|---|---|---|---|---|

### SEC-001 — <title>
- Severity and rationale:
- Status: Verified / Conditional / Not assessed
- Affected asset:
- Evidence: <redacted file:line, configuration, or safe test result>
- Preconditions:
- Impact:
- Safe reproduction:
- Remediation:
- Verification after fix:
- Mapping: <OWASP Top 10:2025 and/or ASVS 5.0 requirement>

## Controls observed or passed
<control, scope, evidence, caveat>

## Not assessed and residual risk
<asset/reason/next evidence required>

## Remediation plan
1. <owner, action, target date/dependency>

## Evidence appendix
<commands/configuration/requests; redact sensitive values>
```

Keep remediation specific, ownership-ready, and testable. A finding is complete only when its verification step can distinguish the fix from the vulnerable behavior.
