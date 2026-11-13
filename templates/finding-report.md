# Finding: <short title>

| Field | Value |
|-------|-------|
| ID | F-00X |
| Date found | YYYY-MM-DD |
| Source | Security Hub / Prowler / Config / manual |
| Severity | Critical / High / Medium / Low |
| Framework mapping | CIS x.y / FSBP control / NIST AC-6 |
| Resource | `<type>:<name>` (ID redacted) |
| Owner | role or team |
| Status | Open / Remediated / Accepted |

## What is wrong

Two or three sentences a non-specialist can follow. State the exposure, not the tool output.

## Why it matters

Concrete blast radius. What can an attacker do, what data is reachable, what compliance requirement
fails. One paragraph maximum.

## Evidence

- Command or console path used:
- Observed output (redacted):

```
<paste>
```

- Screenshot: `evidence/<project>/<file>.png`

## Risk rating

| Factor | Assessment |
|--------|------------|
| Likelihood | |
| Impact | |
| Exposure | internet / cross-account / internal |
| Data sensitivity | |

## Remediation

Steps actually taken, in order, with commands where useful. Note anything that had to be sequenced to
avoid downtime.

## Validation

Proof the fix worked, including the legitimate path that must keep working.

## Residual risk and follow-up

What remains, what compensating control exists, and what would prevent recurrence (pipeline rule, SCP,
policy).
