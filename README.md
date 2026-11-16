# AWS Cloud Security Engineering Portfolio

**Matthew Mumbach** - Cloud security engineer with a detection and incident response background,
implementing NIST 800-53 controls and building AWS-native posture, detection, and response automation.

CISSP, GPEN, GCIA, AWS Certified Cloud Practitioner
[mattmumbach@protonmail.com](mailto:mattmumbach@protonmail.com) | [linkedin.com/in/mattmumbach](https://linkedin.com/in/mattmumbach)

Hands-on AWS security work, built and documented one project at a time. Done: a posture audit of a
live account with Prowler and Security Hub, remediation proven with before/after evidence, and the
account's admin moved from a long-lived IAM user to Identity Center with MFA. Next: threat detection,
policy as code against NIST 800-53, IAM least privilege, and incident response.

Every project follows the same evidence-driven loop:

**build it -> break it -> detect it -> fix it -> prove it**

Each folder contains the walkthrough, the raw evidence (sanitized), and a short write-up written for
a hiring manager rather than for a lab notebook.

## Portfolio at a glance

| # | Project | Status | Core AWS services | Evidence a reviewer opens first |
|---|---------|--------|-------------------|----------------------------------|
| 1 | Cloud security posture audit | Done | Security Hub, Config, Prowler | Before/after CIS scorecard |
| 2 | Threat detection and monitoring | Planned | CloudTrail, GuardDuty, EventBridge | Triage sheet for one finding |
| 3 | S3 hardening and data exposure | Cut (folded into 1) | S3, IAM, KMS, CloudTrail | Public-access before/after proof |
| 4 | IAM audit and least privilege | Planned | IAM, Access Analyzer, CloudTrail | Permissions reduced, access still works |
| 5 | Multi-cloud detection | Cut | GuardDuty, Defender for Cloud | Side-by-side detection comparison |
| 6 | Threat hunting with logs | Cut | CloudTrail, Athena, VPC Flow Logs | Hypothesis -> query -> timeline |
| 7 | Incident response runbook | Planned | IAM, EC2, GuardDuty, CloudTrail | Timestamped IR timeline |
| 8 | Compliance with policy as code | Planned | Config, conformance packs, cfn-guard | Non-compliant -> auto-remediated |
| 9 | Secrets and key protection | Cut | Secrets Manager, KMS, CloudTrail | Rotation and access-audit proof |
| 10 | Multi-cloud architecture comparison | Cut | AWS baseline vs Azure/GCP | Control-by-control trade-off matrix |
| 11 | Agentic AI workload hardening (capstone) | Cut (bounded version folded into 2) | Amazon Bedrock, Lambda tool roles, Guardrails | Injection test matrix plus tool-scope policy diff |

## Start here

1. `docs/00-how-to-run-this-portfolio.md` - account setup, budget guardrails, evidence discipline,
   6-week schedule, sanitization rules. Read this before touching the console.
2. Work the project docs in order. Projects 1, 2, 4, and 7 form the strongest interview narrative and
   can be finished in about three weekends.
3. `templates/` - finding report, incident runbook, evidence index. Copy, do not invent a new format.

## Repository layout

```
.
├── README.md
├── docs/
│   ├── 00-how-to-run-this-portfolio.md
│   ├── 01-posture-audit.md
│   ├── 02-threat-detection.md
│   ├── 03-s3-hardening.md
│   ├── 04-iam-least-privilege.md
│   ├── 05-multicloud-detection.md
│   ├── 06-threat-hunting.md
│   ├── 07-incident-response.md
│   ├── 08-policy-as-code.md
│   ├── 09-secrets-and-keys.md
│   ├── 10-architecture-comparison.md
│   ├── 11-agentic-ai-security.md
│   └── 12-ai-retrofit-notes.md
├── templates/
│   ├── finding-report.md
│   ├── ir-runbook.md
│   └── evidence-index.md
└── evidence/
    └── <project>/            # sanitized screenshots, CLI output, findings CSVs
```

## How each project is documented

Every write-up answers the same six questions. Hiring managers scan for these, not for tool names.

1. **Objective** - the risk being addressed, in business terms.
2. **Environment** - account shape, region, resources, starting state.
3. **What I did** - commands and decisions, including the ones that failed.
4. **Evidence** - what proves it worked.
5. **Result** - measurable reduction in risk, with numbers.
6. **What I would change at scale** - multi-account, IaC, automation, cost, ownership.

## Safety and hygiene

- Use a dedicated AWS account or sandbox. Never run destructive tests in a shared or work account.
- Root: MFA on, no access keys, no daily use. Admin work goes through IAM Identity Center.
- Cap spend: AWS Budgets with a 10 USD alarm and a hard-stop check before each lab.
- No real customer data, no real credentials, no production account IDs, no full ARNs of third
  parties. Redact account numbers to the last four digits.
- Tear down after each project. Detection services are cheap; NAT gateways and idle instances are not.
- Document the teardown itself - "left nothing running" is an operational maturity signal.
