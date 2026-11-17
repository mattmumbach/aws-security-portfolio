# Finding: CloudTrail logging was stopped on the account's only trail

| Field | Value |
|-------|-------|
| ID | F-201 |
| Date found | 2026-11-17 |
| Source | GuardDuty, `Stealth:IAMUser/CloudTrailLoggingDisabled` |
| Severity | Low (GuardDuty 2.0) |
| Framework mapping | CIS AWS Foundations 5.0 control 3.1; NIST 800-53 rev. 5 AU-2(b), AU-12(a), AU-12(c) (as mapped by Prowler 5.49.0 for `cloudtrail_multi_region_enabled`) |
| Resource | `AWS::CloudTrail::Trail:org-trail` (account ID redacted) |
| Owner | Account administrator (`lab_admin`) |
| Status | Closed - expected test; logging restored in the same second |

## What is wrong

At 14:00:17 UTC on 17 November 2026, logging was switched off on `org-trail`, the only CloudTrail
trail in the account. While a trail is stopped, CloudTrail suspends recording and log file delivery
for it, so the account stops building its long-term record of who did what. An audit of that
period cannot be relied on. Logging was switched back on within the same second.

## Why it matters

While logging is off, an intruder can take any action their credentials allow - copy data out,
change or destroy resources - without it reaching the log files. Defenders can no longer trust
those logs, because they cannot tell what did not happen from what was never recorded.

Two things limit the damage. CloudTrail's event history is separate from trails and keeps the last
90 days of management events, and GuardDuty reads CloudTrail events through its own stream, so
neither was blinded by the stop. What is lost is the durable, validated copy in S3, which is the
record an investigation or an audit depends on once the 90 days have passed.

The requirement that stops being met is the one for continuous audit logging: CIS AWS Foundations
Benchmark 5.0 control 3.1, "Ensure CloudTrail is enabled in all regions", and NIST 800-53
revision 5 AU-2 and AU-12.

## Evidence

- GuardDuty finding: `raw/finding3-cloudtrail-logging-disabled.json`
- CloudTrail records of the stop and the start: `raw/finding3-cloudtrail-StopLogging.json`,
  `raw/finding3-cloudtrail-StartLogging.json`
- Every call made with the same access key, 13:55 to 14:05 UTC: `raw/finding3-cloudtrail-same-key.json`
- Triage sheet produced by `scripts/02-triage.py`: `triage-sheet-finding3.txt`
- Full triage record and verdict: `triage-finding3.md`

Observed, from the triage sheet (identifying values masked):

```
type                       Stealth:IAMUser/CloudTrailLoggingDisabled
severity                   2.0
api called                 StopLogging on cloudtrail.amazonaws.com
event first seen           2026-11-17T14:00:17.000Z
finding created            2026-11-17T14:18:35.303Z
time to detect             18 min 18 s
session name               lab_admin
source ip = finding ip     YES
command (user agent)       cloudtrail.stop-logging
result                     succeeded (no error code)
calls that change something StopLogging, StartLogging
```

## Risk rating

| Factor | Assessment |
|--------|------------|
| Likelihood | Low for an outsider, who would have to steal an Identity Center sign-in together with its MFA. An insider is the more likely source. Either way the caller needs permission to call `cloudtrail:StopLogging`, which in this account only the administrator role has. |
| Impact | Depends on how long logging stays off. Half a second, as here, is negligible. A day unnoticed would be serious, with compliance and audit consequences on top of the lost visibility. |
| Exposure | internal - the call was made with the account's own administrator session |
| Data sensitivity | Low. This is a lab account holding nothing sensitive beyond its billing relationship. In a production account the concern would be customer data, proprietary data and business processes. |

## Remediation

Logging was restarted by the same command that stopped it. CloudTrail records `StopLogging` and
`StartLogging` in the same second, 14:00:17 UTC, and the trail status saved straight afterwards
shows stop and start times about half a second apart (`raw/finding3-trail-status.json`).

Nothing restarted the trail automatically. Had the stop been hostile, logging would have stayed
off until someone noticed: GuardDuty took 18 min 18 s to raise the finding, and at severity 2.0 the
finding is below the threshold of the email rule, so no alert was sent.

## Validation

`raw/finding3-trail-status.json` shows `IsLogging: true` after the test.

## Residual risk and follow-up

The risk that remains is that the administrator can still stop the trail and nothing prevents it.
GuardDuty catches it, but took 18 min 18 s, and because it rates the finding 2.0 the email rule
held it back, so nobody was told.

GuardDuty's rating and the impact above are different judgments. GuardDuty describes low severity
as "attempted suspicious activity that did not compromise your environment". That is a statement
about evidence of compromise, not about what it costs the organization to lose its audit log.

Follow-up:

- Alert on this finding by type as well as by severity, so that a stopped trail reaches a person
  whatever GuardDuty rates it.
- Restart the trail automatically when the finding fires. Planned as phase 2 of this project.
- Prevention is limited in this account. A service control policy could deny the call, but this is
  the organization's management account, and AWS states that "SCPs don't affect users or roles in
  the management account". In a multi-account organization the answer is an organization trail,
  which users in member accounts cannot turn off, with the management account used as little as
  possible. A permissions boundary on the administrator permission set is another option that has
  not been tested here.
