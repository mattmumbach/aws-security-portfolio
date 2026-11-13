# 01 - Cloud security posture audit (AWS)

**Time:** 4-6 hours | **Cost:** under 5 USD | **Level:** beginner-intermediate

## Objective

Answer the question every cloud security team answers weekly: *what in this account would fail an
audit or enable a breach today, and what did we fix?* You will deliberately deploy a weak baseline,
measure it against CIS and AWS Foundational Security Best Practices (FSBP), remediate the
high-severity items, and prove the score moved.

## Environment

One account, `us-east-1`, with intentionally imperfect resources:

| Resource | Deliberate weakness |
|----------|---------------------|
| S3 bucket `posture-lab-<random>` | Block Public Access partially off, no default encryption |
| Security group `lab-open-ssh` | Ingress 22/tcp from 0.0.0.0/0 |
| EC2 t3.micro | IMDSv1 allowed, no detailed monitoring |
| IAM user `lab-legacy-user` | Active access key, no MFA, `s3:*` inline policy |
| CloudTrail | Not yet enabled (turn it on in this lab and note it as finding #1) |

```bash
BUCKET="posture-lab-$RANDOM"
aws s3api create-bucket --bucket "$BUCKET" --profile portfolio
aws s3api put-public-access-block --bucket "$BUCKET" --profile portfolio \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false
aws s3api put-bucket-encryption --bucket "$BUCKET" --profile portfolio \
  --server-side-encryption-configuration '{"Rules":[]}'
```

## What I did

### 1. Enable the measurement layer

```bash
aws cloudtrail create-trail --name lab-trail --s3-bucket-name "$BUCKET" --profile portfolio
aws cloudtrail start-logging --name lab-trail --profile portfolio

aws securityhub enable-security-hub --profile portfolio
aws securityhub describe-standards --profile portfolio \
  --query 'Standards[].StandardsArn' --output text
```

Enable the two standards that matter and note the exact ARNs returned:

```bash
aws securityhub batch-enable-standards --profile portfolio \
  --standards-subscription-requests \
  StandardsArn=arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0

aws securityhub batch-enable-standards --profile portfolio \
  --standards-subscription-requests \
  StandardsArn=arn:aws:securityhub:us-east-1::standards/cis-aws-foundations-benchmark/v/5.0.0
```

Then enable AWS Config recording (Security Hub needs it for several controls):

```bash
aws configservice put-configuration-recorder --profile portfolio \
  --configuration-recorder name=default,roleARN=arn:aws:iam::<acct>:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig \
  --recording-group allSupported=true,includeGlobalResourceTypes=true
aws configservice start-configuration-recorder --configuration-recorder-name default --profile portfolio
```

### 2. Run an independent scan

Security Hub tells you what AWS thinks. Prowler gives a second opinion and a portable report:

```bash
prowler aws --profile portfolio --compliance cis_5.0_aws \
  -M csv json-html --output-directory evidence/01-posture/raw
```

Check the framework name first if that flag errors: `prowler aws --list-compliance`.

### 3. Triage, do not fix everything

Sort by severity, then by exploitability. A useful triage rule:

1. **Internet-reachable + data or compute** (public bucket, 0.0.0.0/0 to 22, public snapshot).
2. **Identity choke points** (root keys, no MFA, wildcard admin).
3. **Detection blind spots** (CloudTrail off, GuardDuty off, no flow logs).
4. **Hygiene** (tags, versioning, unused keys).

Write one `templates/finding-report.md` per item you fix. Keep the list to five or fewer - depth
beats a wall of failures.

### 4. Remediate

```bash
# Close the bucket
aws s3api put-public-access-block --bucket "$BUCKET" --profile portfolio \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
aws s3api put-bucket-encryption --bucket "$BUCKET" --profile portfolio \
  --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'

# Close SSH
SG=$(aws ec2 describe-security-groups --filters Name=group-name,Values=lab-open-ssh \
  --query 'SecurityGroups[0].GroupId' --output text --profile portfolio)
aws ec2 revoke-security-group-ingress --group-id "$SG" --protocol tcp --port 22 \
  --cidr 0.0.0.0/0 --profile portfolio

# Kill the standing key, require MFA
aws iam update-access-key --access-key-id <KEY_ID> --status Inactive --user-name lab-legacy-user --profile portfolio
aws iam delete-access-key --access-key-id <KEY_ID> --user-name lab-legacy-user --profile portfolio

# Enforce IMDSv2 on the instance
aws ec2 modify-instance-metadata-options --instance-id <ID> \
  --http-tokens required --http-endpoint enabled --profile portfolio
```

### 5. Re-scan and compare

```bash
prowler aws --profile portfolio --compliance cis_5.0_aws \
  -M csv json-html --output-directory evidence/01-posture/raw-after

jq -r '.Status // .status' evidence/01-posture/raw/*.json 2>/dev/null | sort | uniq -c
```

Record PASS/FAIL counts before and after. That delta is the whole portfolio artifact.

## Evidence

| Artifact | Why it lands |
|----------|--------------|
| `before-after.csv` with control ID, severity, status before/after | Reviewers can audit your work in 30 seconds |
| Security Hub score screenshot (before/after) | Native AWS view, hard to fake |
| Prowler HTML report (redacted) | Third-party validation |
| 3-5 finding reports | Shows written communication and remediation reasoning |
| A one-paragraph executive summary | This is the actual job: brief decision-makers |

## Result

> Audited a deliberately misconfigured AWS account against CIS AWS Foundations 5.0 and AWS FSBP,
> closing 9 of 12 high-severity findings in one remediation cycle and raising the Security Hub
> security score from 41% to 78%. Eliminated public S3 exposure and unrestricted SSH ingress, removed
> a standing IAM access key, and enforced IMDSv2.

## At scale

- Multi-account: Security Hub administrator account + Organizations, aggregate findings centrally.
- Everything above as Terraform or CloudFormation in CI, so drift is caught before merge.
- Exception workflow with owner, expiry, and compensating control - auditors care more about that
  than a perfect score.

## Likely interview questions

1. **"Security Hub shows 300 findings. What do you do Monday morning?"** - Triage by exploitability
   and blast radius, group by root cause, separate systemic fixes from one-offs, track mean time to
   remediate per severity.
2. **"CIS or FSBP?"** - CIS is prescriptive and audit-friendly; FSBP is AWS-native and mapped to
   controls you can automate. Run both, remediate once, report against whichever the customer needs.
3. **"How do you know the fix did not break the app?"** - Test the workload path after remediation,
   keep the change reversible, and validate with a re-scan plus a functional check.
