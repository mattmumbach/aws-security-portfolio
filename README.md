# AWS Cloud Security Engineering Portfolio

**Matthew Mumbach** - Cloud security engineer with a detection and incident response background,
implementing NIST 800-53 controls and building AWS-native posture, detection, and response automation.

CISSP, GPEN, GCIA, AWS Certified Cloud Practitioner
[mattmumbach@protonmail.com](mailto:mattmumbach@protonmail.com) | [linkedin.com/in/mattmumbach](https://linkedin.com/in/mattmumbach)

Hands-on AWS security work in a live account, built and documented one project at a time. This
repository holds finished work only: a project appears here when it has been run, measured, and
written up, and every number in a write-up has an evidence file behind it.

Every project follows the same loop:

**build it -> break it -> detect it -> fix it -> prove it**

## Finished work

### 1. Cloud security posture audit

Write-up: [`docs/01-posture-audit.md`](docs/01-posture-audit.md)

I deployed four deliberately weak resources, measured the account with Prowler and Security Hub,
fixed what mattered, and proved each fix with a before/after pair. The audit also found resources
left behind by a 2024 course, which were documented and removed, and it ended with the account's
admin moved from a long-lived IAM user to IAM Identity Center with MFA.

| Open this | To see |
|---|---|
| [`docs/01-posture-audit.md`](docs/01-posture-audit.md) | The write-up: findings fixed, results, what was accepted and why, what I got wrong |
| [`docs/00-account-inventory.md`](docs/00-account-inventory.md) | What exists in the account, verified by command rather than by console checkmarks |
| [`evidence/01-posture/before-after.csv`](evidence/01-posture/before-after.csv) | Check-by-check comparison of the two Prowler scans |
| [`evidence/01-posture/raw/`](evidence/01-posture/raw/) | Before/after CLI output for each fix, and the teardown record |
| [`scripts/`](scripts/) | The deploy, scan, remediate, compare, and teardown scripts, and the redaction gate |

### 2. Threat detection and triage

Write-up: [`docs/02-threat-detection.md`](docs/02-threat-detection.md)

I enabled GuardDuty and built the path from a finding to a person: an EventBridge rule that passes
high-severity findings to an SNS topic, with a topic policy that lets only that rule publish. Then
I tested it with sample findings and with real actions in the account, and triaged the results
against CloudTrail by hand and with a script. One of two real actions was never detected, and the
one that was detected was rated too low to send an alert.

Because detection took 18 minutes and told nobody, I then built an automatic restart for the trail:
a Lambda function started by an EventBridge rule, with a five-minute scheduled check behind it,
first by hand and then as a CloudFormation stack. The rule restarted the trail in about five
seconds when the stop event reached it, which it did in 5 of 7 trials; the scheduled check caught
the stop when the rule was switched off.

| Open this | To see |
|---|---|
| [`docs/02-threat-detection.md`](docs/02-threat-detection.md) | The write-up: what was built, the measurements, what I got wrong, what was not built and why |
| [`evidence/02-detection/finding-report-cloudtrail-logging-disabled.md`](evidence/02-detection/finding-report-cloudtrail-logging-disabled.md) | A finding report for the one real finding |
| [`evidence/02-detection/triage-finding3.md`](evidence/02-detection/triage-finding3.md) | The triage record: the alert checked against CloudTrail, and the verdict |
| [`evidence/02-detection/triage-times.md`](evidence/02-detection/triage-times.md) | Every timing, with what each one does and does not measure |
| [`scripts/02-triage.py`](scripts/02-triage.py) | The script that pulls a finding and the CloudTrail activity behind it |
| [`scripts/02-remediate/trail-restart.yaml`](scripts/02-remediate/trail-restart.yaml) | The CloudFormation template for the automatic restart: function, rule, schedule and least-privilege roles |

## Roadmap

These are not started or not finished. Each one is added here when it is done.

| Project | Core AWS services |
|---|---|
| IAM audit and least privilege | IAM, Access Analyzer, CloudTrail |
| Incident response runbook | IAM, EC2, GuardDuty, CloudTrail |
| Compliance with policy as code, mapped to NIST 800-53 | Config, conformance packs, cfn-guard |

## Repository layout

```
.
├── README.md
├── docs/           one write-up per finished project, plus the account inventory
├── evidence/       sanitized scan output and before/after CLI captures, one folder per project
├── scripts/        idempotent bash and Python, one script per phase of a project
├── templates/      finding report, evidence index, incident response runbook
└── .githooks/      pre-commit hook that runs the redaction gate
```

## How each project is documented

Every write-up answers the same six questions.

1. **Objective** - the risk being addressed, in business terms.
2. **Environment** - account shape, region, resources, starting state.
3. **What I did** - commands and decisions, including the ones that failed.
4. **Evidence** - what proves it worked.
5. **Result** - measured change, with numbers taken from the evidence files.
6. **What I would change at scale** - multi-account, IaC, automation, cost, ownership.

## Safety and hygiene

- The lab runs in a dedicated AWS account. Nothing here touches a shared or work account.
- Root has MFA and no access keys. Admin work goes through IAM Identity Center with short sessions.
- Spend is capped with an AWS Budgets alarm at 10 USD, and each project is torn down when it ends.
  The teardown is captured as evidence.
- Nothing sensitive is committed. `scripts/redact-audit.sh` runs as a pre-commit hook and blocks
  account IDs, access key IDs, IAM unique IDs that encode the account ID, secrets, private keys,
  home directory paths, and phone numbers. The account ID is written as `58********27` throughout.
