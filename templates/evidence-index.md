# Evidence index - <project number and name>

Date: YYYY-MM-DD | Account: 12********89 | Region: us-east-1 | Operator: <name>

## Claims and proof

Every result statement in the write-up should map to a row here. If a claim has no artifact, delete
the claim.

| # | Claim | Artifact | Type | Path |
|---|-------|----------|------|------|
| 1 | Bucket was publicly readable | `curl` returned HTTP 200 before remediation | text | `evidence/03-s3/raw/curl-before.txt` |
| 2 | Bucket is now private | `curl` returned HTTP 403 after remediation | text | `evidence/03-s3/raw/curl-after.txt` |
| 3 | Public access blocked at all four layers | `get-public-access-block` output | json | `evidence/03-s3/raw/pab.json` |
| 4 | Encryption enforced | `get-bucket-encryption` output | json | `evidence/03-s3/raw/sse.json` |
| 5 | Access Analyzer finding resolved | finding status ACTIVE -> ARCHIVED | json | `evidence/03-s3/raw/analyzer.json` |

## Redaction log

| File | What was redacted | Method |
|------|-------------------|--------|
| `curl-before.txt` | bucket name suffix | renamed to `s3-lab-REDACTED` |
| `pab.json` | account ID | replaced with `12********89` |

## Environment snapshot

```bash
aws sts get-caller-identity
aws --version
prowler --version
date -u
```

Paste output here (account ID redacted). Reviewers use this to judge reproducibility.

## Teardown

| Resource | Action | Verified |
|----------|--------|----------|
| S3 bucket + versions | deleted (including all versions) | `aws s3 ls` empty |
| EC2 instance | terminated | `describe-instances` shows terminated |
| Config recorder | stopped | |
| GuardDuty detector | kept (cheap, needed for later projects) | |
| Budget | unchanged | |
