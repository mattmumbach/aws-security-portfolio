# 02 - Threat detection and triage (AWS)

**Status:** phase 1 complete, 2026-11-17 | **Account:** 58********27 | **Region:** us-east-1
**Cost:** GuardDuty is inside its 30-day free trial (`evidence/02-detection/raw/free-trial-days.txt`)

## Summary

I turned on GuardDuty, then built the path that gets a finding to a person: an EventBridge rule that
catches high and critical findings and sends them to an SNS topic, which publishes them by email. I
changed the topic's access policy so that the rule was allowed to publish to it.

Then I tested it. High-severity findings reached my inbox in under a minute and a low-severity one
was held back, both as designed. I took two real actions in the account to see what GuardDuty
would notice, and triaged the result against CloudTrail by hand and with a script.

The most important result is that detections do not always behave the way you expect, and they
need to be tested before anyone relies on them. One of my two real actions was never caught by
GuardDuty at all. The other was caught, but its severity was too low to reach my email rule, so
nobody was told.

## Environment

| Piece | State at the start | What was built |
|---|---|---|
| CloudTrail trail `org-trail` | Already present: multi-region, log file validation on, logging | Left as it was |
| GuardDuty | Off (`raw/guardduty-before.json`) | Enabled in us-east-1, updates published every 15 minutes |
| SNS topic `gd-alerts` | Did not exist | Created, one confirmed email subscriber |
| EventBridge rule `guardduty-high` | Did not exist | Passes GuardDuty findings with severity 7 or higher to the topic |
| Topic access policy | Default statement only | Second statement lets that one rule publish (`scripts/02-topic-policy.sh`) |

Everything was built one command at a time from the CLI, with a read-only check before and after
each change. All paths below are under `evidence/02-detection/`.

## What I did

### 1. Recorded the starting point

GuardDuty had no detector. The existing trail was multi-region, validating its log files, and
logging, with no delivery error (`raw/trail-before.json`, `raw/trail-status-before.json`).

### 2. Built the alert path

GuardDuty publishes each finding to EventBridge. A rule there filters on severity and forwards
matches to an SNS topic, which emails the subscriber.

The severity filter was tested before the rule was created, with `aws events test-event-pattern`:
it matched severities 8 and 7 and did not match 6.9 or 2.

The step that is easy to miss is the topic's access policy. The console adds a statement for
EventBridge when a topic is chosen as a target; the CLI does not. Without it the rule fires and the
message is dropped. The statement added here names the EventBridge service as principal, allows
`sns:Publish` only, and carries an `aws:SourceArn` condition so that only this rule can use it.

### 3. Tested delivery in both directions

- A sample finding rated 8.0 was created at 21:02:23 UTC on 16 November and the email arrived
  within the same minute. A second, at 13:36:57 UTC on 17 November, did the same. The inbox times
  are known to the minute only, so the result is "under a minute", not a figure in seconds.
- A real finding rated 2.0 produced no email. The rule held it back as designed.

### 4. Produced real findings

| Action | Documented trigger? | Result |
|---|---|---|
| Stopped `org-trail` and restarted it within the same second | No - the documentation names deletion or update of a trail, not a stop | `Stealth:IAMUser/CloudTrailLoggingDisabled`, severity 2.0, raised 18 min 18 s after the action |
| Lowered the minimum password length from 14 to 8 and restored it a second later | Yes - "updated to require fewer characters" | No finding. None had appeared 33 minutes later, or at a second check 185 minutes after the action (`raw/finding4-check.txt`) |

### 5. Triaged them

Each finding was checked against independent records: does CloudTrail show the call, from the same
address, by the same identity, and what else did that credential do. The two samples had nothing
behind them - no such user, bucket or access key, and no CloudTrail events - and were closed as
test alerts. The real finding was corroborated on every point; the full record is
`triage-finding3.md` and the report is `finding-report-cloudtrail-logging-disabled.md`.

The GuardDuty finding names only the role. CloudTrail supplied the rest: the session name, the
Identity Center user behind it, the tool, and the exact command.

### 6. Measured

Handling time - from starting work on a finding to having the answers to the six triage questions -
was measured twice on the real finding, once by hand in the console and once with
`scripts/02-triage.py`.

## Result

These numbers show that the pipeline does what it was built to do, and that this is not the same
as being protected. The alert path worked in both directions. The detection behind it worked once
out of two real attempts, took 18 minutes when it did, and alerted nobody. Triage was quicker with
a script than by hand, and more complete.

They do not show how GuardDuty performs in general. Two real actions in a quiet lab account is a
test, not a sample, and one of the two results is an absence that I cannot explain. They also do
not show how long triage takes when the answer is unknown: every finding here was one I caused.

| Measure | Value | Evidence |
|---|---|---|
| Findings handled | 3: two samples and one real | `triage-times.md` |
| Classified true positive | 0. The real finding was accurate and was an authorized test; the two samples were test alerts | `triage-times.md`, `triage-finding3.md` |
| Delivery, high severity | Under a minute from creation to inbox, twice | `raw/sample-finding-*.txt`, `raw/finding2-*.txt` |
| Delivery, low severity | No email, as designed | `triage-finding3.md` |
| Time to detect, trail stop | 18 min 18 s | `raw/finding3-cloudtrail-logging-disabled.json` |
| Time to detect, password policy change | Not detected | `raw/finding4-check.txt` |
| Handling time, console by hand | 3 min 26 s | `raw/timing-console-*.txt` |
| Handling time, script | 2 min 4 s | `raw/timing-script-*.txt`, `triage-sheet-finding3.txt` |

The handling times come from one finding, one run of each method, the console run first, with the
answer already known. They show the direction of the difference, not its size. The scripted run
also captured two things the console run missed: the numeric severity and the session name.

Two earlier created-to-verdict times are on record and are not used: 19 min 23 s for a sample,
interrupted partway, and about 54 minutes for the real finding, a guided first run in the console.

## What I got wrong, and what it cost

Recorded because these are the parts I would otherwise forget:

- **I stopped the trail expecting a finding without a documented trigger.** The documentation does
  not list a stop as a trigger. It worked, but only after an 18-minute wait with no way to know
  whether it would.
- **I assumed a documented trigger would fire.** The password policy change matched the
  documentation word for word and produced nothing. A detection is a claim until it has been tested
  in the account it is meant to protect.
- **I first called a sample finding a false positive.** A sample is a test alert. Counting it as a
  false positive would distort any later review of how often a detection misfires.
- **My first two triage timings measured the wrong thing.** One was interrupted and the other
  included being taught the console. Created-to-verdict also mixes waiting time with working time,
  so handling time was measured separately.
- **The console run missed two answers** that were one screen away, and the script did not. Speed
  was the smaller difference; consistency was the larger one.

## Not built in the lab, and how I would do it in production

These were left out on purpose. Nothing in this section was performed, and it carries no results.

- **Encryption of the `gd-alerts` topic.** Prowler flags the topic as unencrypted. Encrypting it
  needs a customer-managed KMS key whose key policy lets the EventBridge service use it, which
  carries a monthly charge.
- **Amazon Detective.** The GuardDuty console links to it for investigation. It was not enabled.
- **Preventing the trail from being stopped.** A service control policy cannot do it here, because
  this is the organization's management account and SCPs do not apply to it. In a multi-account
  organization: an organization trail, which member accounts cannot turn off, and minimal use of
  the management account.
- **Alerting on the trail finding by type.** At severity 2.0 it never reaches the email rule.
- **Automatic restart of the trail.** Planned as phase 2 of this project.

## Evidence index

| File | Supports |
|---|---|
| `raw/guardduty-before.json`, `raw/guardduty-after.json` | GuardDuty off, then on |
| `raw/trail-before.json`, `raw/trail-status-before.json` | The trail's settings and health before any change |
| `raw/free-trial-days.txt` | 30 free-trial days on every GuardDuty feature on the day it was enabled |
| `raw/sns-subscription.json` | The topic has a confirmed email subscriber |
| `raw/eventbridge-rule.json`, `raw/eventbridge-targets.json` | The rule, its severity pattern and its target |
| `raw/sample-finding-*.txt`, `raw/finding1-*.json` | First sample: request time, inbox time, the finding |
| `raw/finding2-*` | Second sample: request and inbox times, the finding, the correlation checks |
| `raw/finding3-*` | The trail stop: action time, trail status, the finding, CloudTrail records |
| `raw/finding4-*` | The password policy change: action time, restored policy, CloudTrail records, absence of a finding |
| `raw/timing-*.txt` | Start and stop times of the two handling-time runs |
| `triage-times.md` | Every timing, with what each one does and does not measure |
| `triage-finding3.md`, `triage-sheet-finding3.txt` | Triage record and scripted sheet for the real finding |
| `finding-report-cloudtrail-logging-disabled.md` | Finding report F-201 |

Redaction: account ID, access key IDs, role IDs, IP addresses, IP location and network owner, and
Identity Center IDs are masked in the real finding and its CloudTrail records by
`scripts/02-redact.py`. Inbox arrival times were reported by hand and are marked as such.

## At scale

- **Many accounts.** Findings have to come together in one place. GuardDuty and Security Hub each
  support a delegated administrator account that manages the service for, and sees findings from,
  the organization's member accounts; both are set up per Region. AWS Control Tower sets up and
  governs the multi-account environment itself. Service control policies and permissions boundaries
  then limit what insiders and honest mistakes can do in member accounts.
- **Hundreds of findings a day, or more.** The work shifts from reading alerts to detection logic:
  deciding what is worth alerting on, and cutting noise so that the real problems are visible.
  GuardDuty suppression rules archive new findings that match set criteria; each one is a decision
  that should be written down and reviewed.
- **A team instead of one person.** Triage needs a written process, so that a finding is handled
  the same way whoever picks it up, and so that knowledge survives shift changes and turnover. A
  script that gathers the same evidence every time is part of that.
- **Test every detection that matters.** The lesson of this project applies more at scale, not
  less: a rule that has never been seen to fire in the environment it protects is an assumption.
