# Cloud Security Incident Response Runbook

Version: 1.0 | Owner: <name/team> | Last exercised: YYYY-MM-DD

## 1. Scope and severity

| Level | Definition | Response target |
|-------|------------|-----------------|
| SEV1 | Root/admin credential compromise, confirmed data exfiltration, production outage from attack | Page immediately; contain within 15 min |
| SEV2 | Single workload credential compromised, no confirmed data access | Contain within 1 hour |
| SEV3 | Exposure with non-sensitive data, misconfiguration | Fix within 24 hours |
| SEV4 | Posture finding, no exposure | Normal backlog |

## 2. Roles

| Role | Responsibility | Named person |
|------|----------------|--------------|
| Incident commander | Decisions, communication, timeline ownership | |
| Investigator | Log analysis, scope determination | |
| Responder | Containment and eradication actions | |
| Scribe | Timestamped notes, evidence index | |
| Comms | Executives, customers, legal as required | |

## 3. Detection and validation

- [ ] Record `date -u` and open the incident record
- [ ] Pull the finding (`guardduty get-findings`, Defender alert, SIEM case)
- [ ] Confirm credential is active and identify its owner
- [ ] Confirm source IP/ASN is outside expected range
- [ ] Identify first and last malicious API call from CloudTrail
- [ ] Classify: true positive / benign-but-notable / false positive

## 4. Containment

Order matters; record a timestamp per action.

1. Revoke sessions for the affected principal:
   `aws iam put-role-policy` with a `Deny *` statement conditioned on
   `aws:TokenIssueTime < <incident start>`.
2. Isolate compute: replace security groups with a no-rule forensic group (do not terminate).
3. Disable or delete compromised access keys.
4. Preserve evidence: EBS snapshots, log exports, `finding.json`, flow log slices.
5. Block known-bad infrastructure only if it will not impede investigation.

## 5. Eradication

- [ ] Determine root cause (exposed metadata, leaked key, over-broad role, vulnerable app)
- [ ] Rotate every credential the identity could reach
- [ ] Patch or reconfigure the vulnerable path
- [ ] Remove persistence: new keys, new users, trust policy changes, modified logging settings

## 6. Recovery

- [ ] Rebuild from trusted image where possible rather than cleaning in place
- [ ] Reattach a least-privilege identity
- [ ] Verify application health and security telemetry
- [ ] Monitor for 24-72 hours with elevated scrutiny
- [ ] Restore network access last, and document who approved it

## 7. Post-incident

- [ ] Timeline with UTC timestamps and evidence source per event
- [ ] Impact statement with counts (objects read, API calls, duration)
- [ ] Metrics: MTTD, MTTA, MTTContain, total recovery time
- [ ] Three to five recommendations, each with an owner and a due date
- [ ] Runbook updates from what actually went wrong
- [ ] Tabletop scheduled to validate changes

## 8. Evidence index

| # | Artifact | Location | Collected by | Time (UTC) |
|---|----------|----------|--------------|------------|
| 1 | GuardDuty finding JSON | | | |
| 2 | CloudTrail correlation export | | | |
| 3 | VPC Flow Log slice | | | |
| 4 | EBS snapshot ID | | | |
| 5 | Timeline CSV | | | |
