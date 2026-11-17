# Triage times - project 2

Times are UTC. "Created" is the finding's own `CreatedAt` field. "Email seen" is the inbox arrival
time as reported by Matt, known to the minute only. "Verdict" is when the verdict was stated.
Time to triage = verdict minus created.

| # | Finding type | Kind | Severity | Created | Email seen | Verdict | Time to triage | Verdict given |
|---|---|---|---|---|---|---|---|---|
| 1 | `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` | sample | 8.0 | 2026-11-16 21:02:23 | 21:02 | not timed | not timed | Used as the end-to-end delivery test only |
| 2 | `Discovery:S3/MaliciousIPCaller` | sample | 8.0 | 2026-11-17 13:36:57 | 13:37 | 2026-11-17 13:56:20 | 19 min 23 s | Test alert (expected): a sample generated on request; the activity it describes did not happen in this account |
| 3 | `Stealth:IAMUser/CloudTrailLoggingDisabled` | real | 2.0 | 2026-11-17 14:18:35 | none (below threshold) | 2026-11-17 15:13 | about 54 min | Expected test: real activity, accurate alert, authorized lab action |

## Notes

- Finding 1 was created at the end of a session and left overnight, so timing it would have measured
  the break, not the triage. It proves delivery (under a minute from creation to inbox) and nothing else.
- Finding 2 was the first triage done start to finish. It was manual, done for the first time, and
  included reading an explanation of what a verdict is. It was also interrupted: Matt stepped away
  partway through, for a length of time that was not recorded. The 19 min 23 s is therefore an upper
  bound on a first run, not a measure of working time, and it is not used in any average.
- Finding 2 evidence: `raw/finding2-s3-malicious-ip.json` (the finding, account ID masked),
  `raw/finding2-correlation.txt` (CloudTrail, S3 and IAM checks, all zero),
  `raw/finding2-requested.txt`, `raw/finding2-email-observed.txt`.
- Verdict labels: "false positive" is kept for a detection that fires on real activity and misjudges
  it. A sample finding is a test alert, not a false positive, so it does not count against the
  detection when tuning. Matt first called finding 2 a false positive and corrected the label to
  test alert on 2026-11-17.
- Finding 3 was the first real finding and the first triage done in the console. The action was at
  14:00:17 and the finding was created at 14:18:35, so GuardDuty took 18 min 18 s to detect it. The
  54 minutes of triage include discussion of how to work in the console and what the fields mean; it
  is a guided first run. Full record: `triage-finding3.md`.
- No timed triage has yet been done unguided or with a script. Those are the two numbers the
  write-up needs.

## Handling time: console against script

Created-to-verdict mixes two things: how long a finding waits before someone picks it up, and how
long the work takes. To compare methods, handling time was measured on its own: from starting work
on a finding to having the answers to the six triage questions. Both runs use finding 3, the one
real finding. The answer was already known, so these runs measure how long each method takes to
produce the evidence, not how long the analysis takes.

| Method | Start (UTC) | Stop (UTC) | Handling time | Files |
|---|---|---|---|---|
| Console, by hand, unguided | 2026-11-17 18:15:40 | 18:19:06 | 3 min 26 s | `raw/timing-console-start.txt`, `raw/timing-console-stop.txt` |
| Script (`scripts/02-triage.py`) | 2026-11-17 18:20:40 | 18:22:44 | 2 min 4 s | `raw/timing-script-start.txt`, `raw/timing-script-stop.txt`, `triage-sheet-finding3.txt` |

Console run, what was written down: CloudTrail logging disabled; severity shown as "Low" with no
number; caller an assumed role, `AWSReservedSSO_AdministratorAccess_...`, from one remote IP
address, with the address's city and network owner shown; event first and last seen 14:00:17 UTC;
finding created 14:18:35 UTC; the same key restarted logging at 14:00:17 UTC. Not written down in
this run: the session name (`lab_admin`) and the tool used, both of which are in the CloudTrail
event record. An earlier attempt at this run was interrupted and discarded.

Script run, what was written down: CloudTrail logging disabled on `org-trail`; severity 2.0; IP
address masked on the sheet; assumed role `AWSReservedSSO_AdministratorAccess_...` with session name
`lab_admin`; event first and last seen 14:00:17 UTC; finding created 14:18:35 UTC; the same key
restarted logging at 14:00:17 UTC. The script run captured the numeric severity and the session
name, which the console run did not. The script itself ran in about three seconds; the rest of the
time was reading the sheet.

Limits of this comparison: one finding, one run of each method, the console run done first, and
the answer known in advance. It shows the direction of the difference, not its size.
