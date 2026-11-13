# Account baseline inventory

What actually exists in account `58********27` as of 2026-11-12, verified by command rather than by
console green checkmarks. Region of record: `us-east-1`.

## Identity

| Item | State |
|---|---|
| Working principal | `project_admin` (IAM user, long-lived admin key) |
| Root | MFA enabled, no root access keys (`AccountAccessKeysPresent = 0`) |
| Identity Center | not configured - project 4 remediates this |
| CLI profile | `default`, region `us-east-1` |

Known risk, deliberate for now: an admin IAM user with a standing access key is the finding that
project 4 fixes. Do not describe this account as hardened.

## Logging and detection

| Resource | Name | Verified state |
|---|---|---|
| Log bucket | `sec-lab-logs-58********27-us-east-1` | BPA all four true, SSE-S3, versioning on, TLS-deny policy |
| Trail | `org-trail` | multi-region, log file validation on, `IsLogging: true`, delivery current |
| Trail event scope | management events only | no data events, no Insights |
| Security Hub | hub enabled 2026-11-12T20:21Z | `AutoEnableControls: true`, findings per security control |
| Standards | FSBP v1.0.0, CIS v5.0.0, NIST 800-53 r5 | see below |
| Config recorder | `default`, `us-east-1` | `allSupported: true`, global types on, no exclusions, recording |
| GuardDuty | not enabled | project 2 |

### Standards: what was enabled, and how it went wrong

Initial run subscribed `cis-aws-foundations-benchmark/v/1.2.0`, which is the deprecated
`securityhub:::` ruleset rather than a current standard. Cause: the bootstrap script took the first
alphabetical CIS match. Corrected to `v/5.0.0`. The ruleset subscription was removed with
`batch-disable-standards` using the **subscription** ARN.

Lesson worth keeping: `batch-enable-standards` takes a standards ARN, `batch-disable-standards`
takes a subscription ARN, and passing the wrong one returns `AccessDeniedException` rather than a
validation error - so the error message points at IAM when the real problem is the ARN shape.

`NIST Special Publication 800-53 Revision 5` is enabled on purpose. It is the same framework as the
FY27 control work, evaluated continuously against live resources instead of by spreadsheet.

## Cost control

| Item | State |
|---|---|
| Budget | `sec-lab-monthly`, 10 USD/month, `COST`, `ACTUAL` |
| Notifications | `ACTUAL > 80%`, `FORECASTED > 100%` |
| SNS topic | `sec-lab-budget` |
| Subscription | `mwm*****@pm.me`, confirmed |

Stale `you@example.com` subscription remains as `PendingConfirmation`; SNS removes unconfirmed
subscriptions automatically after 3 days, so it needs no cleanup command.

AWS Budgets notifies, it does not stop spend.

## Deliberately not built yet

AWS CloudTrail data events, GuardDuty, EventBridge alert routing, CloudWatch alarms on findings,
customer-managed KMS keys, SCPs/Organizations, Identity Center, cross-region aggregation, Config
rules and conformance packs (project 8).

## Detours encountered, and why they are useful

1. **CIS legacy ruleset subscribed instead of a current standard.** Automation that selects by
   substring picks deprecated ARNs.
2. **First Config recorder created in `us-east-2`.** Deleted and rebuilt in `us-east-1`; deleting a
   recorder discards its collected history.
3. **"Record all resource types" excluded `AWS::IAM::User`, `Role`, `Policy`, `Group`.** The newer
   `EXCLUSION_BY_RESOURCE_TYPES` strategy silently scoped the recorder. Detected by reading
   `recordingGroup` rather than trusting the console, then corrected.
4. **`recordingStrategy.useOnly` enum is `ALL_SUPPORTED_RESOURCE_TYPES`**, and combining it with the
   legacy `allSupported`/`includeGlobalResourceTypes` booleans returns
   `InvalidRecordingGroupException`. The legacy shape on its own works.

These are better interview material than a clean run: each one is a case of a control reporting
healthy while doing less than assumed.

## Verification commands used

```bash
aws sts get-caller-identity
aws iam get-account-summary
aws s3api get-public-access-block --bucket <log-bucket>
aws s3api get-bucket-policy --bucket <log-bucket>
aws cloudtrail get-trail-status --name org-trail
aws cloudtrail describe-trails --trail-name-list org-trail
aws cloudtrail get-event-selectors --trail-name org-trail
aws securityhub describe-hub
aws securityhub get-enabled-standards
aws configservice describe-configuration-recorders
aws configservice describe-configuration-recorder-status
aws configservice describe-delivery-channels
aws budgets describe-budgets --account-id <account>
aws sns list-subscriptions-by-topic --topic-arn <budget-topic>
```

## 2024 course leftovers, found and removed

The project 1 baseline audit surfaced resources from a 2024 S3/Beanstalk/Lambda course that were
never cleaned up. They were invisible until a scanner enumerated them, which is the point: a
console tour does not find what nobody remembers creating.

Removed:

| Type | Name |
|---|---|
| S3 bucket | `vertidel-demo-s3` (world-readable, versioned, required delete markers) |
| S3 bucket | `vertidel-bucket-demo-storage-classes` |
| S3 bucket | `vertidel-demo-replication-bucket-origin` (replication rule removed first) |
| S3 bucket | `vertidel-demo-bucket-replication-target` |
| Beanstalk app | `MyApplication` (no environments, no compute attached) |
| IAM role | `AWS-Beanstalk-EC2-Role` (+ its same-named instance profile) |
| IAM role | `aws-elasticbeanstalk-service-role` |
| IAM role | `s3crr_role_for_vertidel-demo-replication-bucket-origin` |
| IAM role | `s3crr_role_for_vertidel-demo-replication-origin` (+ `_1` variant) |
| IAM role | `EC2_Demo-role` |
| IAM policy | `s3crr_for_vertidel-demo-replication-bucket-origin_fc84ce` |
| IAM policy | `s3crr_for_vertidel-demo-replication-origin_e57016`, `_e992b9` |
| IAM policy | `AWSLambdaBasicExecutionRole-37f52f1e-...` |
| IAM policy | `SnowFamilyS3Import-demo-job-1-1-policy` |

Billable resources found: none. No EC2, RDS, ALB, NAT gateway, Lambda, CloudFormation stack or
Beanstalk environment survived the course; the leftovers were buckets, roles and policies only.

Retained on purpose:

| Resource | Reason |
|---|---|
| `elasticbeanstalk-us-east-1-58********27` | Empty, no public access block at all, and its bucket policy carries `Sid eb-58950a8c-...` denying `s3:DeleteBucket` to `Principal: *`. An explicit resource-policy deny cannot be overridden by `AdministratorAccess`. Removal would need the policy stripped first, or root in the console; tidiness did not justify either. |
| `cf-templates-1sx1audeebn9n-us-east-1` | 1.5 KB of CloudFormation templates, all four public access blocks on. CloudFormation recreates it on the next deploy. |
| 2 `alias/aws/*` KMS keys | `KeyManager: AWS`, service-managed, not deletable, created on first RDS and import/export use in Dec 2024. |

### The deny that beat administrator rights

Attempting `s3api delete-bucket` on the Beanstalk bucket as `project_admin` (with
`AdministratorAccess`) returned:

```
AccessDenied ... s3:DeleteBucket ... with an explicit deny in a resource-based policy
```

AWS evaluates identity-based grants and resource-based denies separately, and a deny always wins.
The bucket policy only denied `s3:DeleteBucket`, not `s3:DeleteBucketPolicy`, so
`delete-bucket-policy` followed by `delete-bucket` would have worked. Left as-is deliberately, and
recorded here because "we have admin, therefore we have control" is false in AWS and this is the
proof.

Detection described in `evidence/01-posture/raw/decommission-2024-course.txt`,
`stale-buckets-before.json`, and `stale-iam-before.json`.

## Open items

- Delete the orphaned `config-bucket-*` left in `us-east-2`.
- Re-check Security Hub standards until `READY` before capturing the project 1 "before" scan.
- Sanitize `58********27` and the SNS endpoint in every screenshot saved to `evidence/`.
