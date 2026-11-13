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

## Open items

- Delete the orphaned `config-bucket-*` left in `us-east-2`.
- Re-check Security Hub standards until `READY` before capturing the project 1 "before" scan.
- Sanitize `58********27` and the SNS endpoint in every screenshot saved to `evidence/`.
