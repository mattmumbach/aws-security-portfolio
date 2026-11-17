# Triage record - finding 3: CloudTrail logging disabled

| Field | Value |
|---|---|
| Finding type | `Stealth:IAMUser/CloudTrailLoggingDisabled` |
| Kind | Real finding, produced by an action taken in the account (not a sample) |
| Severity | 2.0 (low) |
| Action taken | 2026-11-17 14:00:17 UTC (`StopLogging` on `org-trail`) |
| Finding created | 2026-11-17 14:18:35 UTC |
| Time to detect | 18 min 18 s (action to finding) |
| Verdict stated | 2026-11-17 15:13 UTC |
| Time to triage | about 54 minutes (finding created to verdict) |
| How it was triaged | By hand in the GuardDuty and CloudTrail consoles, guided, first time through |
| Email alert | None arrived. Severity 2.0 is below the rule's threshold of 7, so the rule held it back as designed |
| Verdict | Expected test. The activity is real and the alert is accurate; it was an authorized lab action |

## Verdict, in my words

This was an expected test. In a production account the same alert would be a true positive: the
alert said CloudTrail logging was stopped, and it was.

The alert on its own only said that the administrator role stopped the trail. The CloudTrail record
filled in the rest. Logging was stopped by the Identity Center user `lab_admin`, using a session of
the `AWSReservedSSO_AdministratorAccess` role, from the AWS CLI on my own machine and from my own
IP address. The same session started logging again within the same second.

I ran this as part of a lab, so I already know who did it and why. In a real environment I would
not know that yet, and I would not close the alert on the strength of the identity alone. I would
document what the evidence shows and tell my management what is known and what is still open:

- Did the employee tied to this identity really take this action?
- Was it authorized, and for what reason?

If the employee did not do it, or it was not authorized, the next step is a further investigation,
either into an insider threat or into a compromised credential.

## What the evidence shows

| Question | Answer | Where it comes from |
|---|---|---|
| What happened? | `StopLogging` was called on `org-trail` | Finding, `Service.Action.AwsApiCallAction.Api`; CloudTrail `eventName` |
| How bad? | Severity 2.0, low | Finding, `Severity` |
| Who? | Role `AWSReservedSSO_AdministratorAccess_...`, session name `lab_admin` | Finding names the role; CloudTrail `userIdentity.arn` and `onBehalfOf` name the person |
| From where? | One public IP address (masked), the same in the finding and in CloudTrail | Finding `RemoteIpDetails`; CloudTrail `sourceIPAddress` |
| With what? | AWS CLI 2.34.20 on macOS; the user agent ends `command#cloudtrail.stop-logging` | CloudTrail `userAgent` |
| When, in order? | 14:00:17 `StopLogging`, 14:00:17 `StartLogging`, 14:18:35 finding created | CloudTrail `eventTime`; finding `CreatedAt` |
| What else did the credential do? | Read-only calls to CloudTrail, S3, IAM and GuardDuty either side of the stop, all by `lab_admin` | `raw/finding3-cloudtrail-same-key.json` |

The finding did not link to CloudTrail in the console. The correlation was done by hand: the event
name and the access key ID were taken from the finding and searched for in CloudTrail event history.

## Open points

- `mfaAuthenticated` is `"false"` in the CloudTrail record although the Identity Center sign-in
  requires MFA. Not yet explained from AWS documentation.
- The GuardDuty documentation lists "deletion or update of a trail" as the trigger for this finding
  and does not mention `StopLogging`. This finding shows that a stop call does trigger it.

## Evidence files

- `raw/finding3-action-time.txt` - when the stop command was run
- `raw/finding3-trail-status.json` - trail status straight after: logging, with stop and start times
- `raw/finding3-cloudtrail-logging-disabled.json` - the GuardDuty finding
- `raw/finding3-cloudtrail-StopLogging.json`, `raw/finding3-cloudtrail-StartLogging.json` - the two CloudTrail records
- `raw/finding3-cloudtrail-same-key.json` - every call made with the same access key, 13:55 to 14:05 UTC

Account ID, access key ID, role ID, IP address, IP location and network owner, and Identity Center
IDs are masked in these files by `scripts/02-redact.py`.
