# 01 - Cloud security posture audit (AWS)

**Status:** complete, 2026-11-13 | **Account:** 58********27 | **Region:** us-east-1
**Cost of the whole project:** under 5 USD

## Summary

I deployed four deliberately weak resources, measured the account with two independent tools, fixed
what mattered, and proved each fix with a before/after pair rather than a claim.

Five deliberate findings were closed, plus two account-level gaps that the lab did not plant but the
audit found: no account-level S3 Block Public Access, and a password policy that had never been set
at all. Separately, the same audit surfaced five S3 buckets, six IAM roles and four policies left
behind by a 2024 course - documented in `00-account-inventory.md` and
`evidence/01-posture/raw/decommission-2024-course.txt`.

The most useful result is not the remediation. It is the disagreement between the two tools: Prowler
reported 80 failing findings across 53 failing checks, Security Hub reported 8 failing findings out of 10 it could evaluate. A
scanner's score is a claim about coverage, not a measurement of the account.

## Environment

| Resource | Deliberate weakness |
|---|---|
| S3 `posture-lab-e7c1774f` | 3 of 4 public access blocks off, public `GetObject` policy, no default encryption, no versioning |
| SG `sg-06ca5b1936920267e` (`lab-open-ssh-bbea`) | 22/tcp from 0.0.0.0/0 |
| EC2 `i-09bc37f318059ae62` (t3.micro, `posture-lab`) | IMDSv1 permitted, no instance profile |
| IAM user `lab-legacy-user` | active access key, no MFA, inline `s3:*` on `*` |

Deployed by `scripts/01-deploy-baseline.sh`, remediated by `scripts/01-remediate.sh`. IDs live in
`.lab-env` (gitignored, mode 600).

## Measurement, before remediation

| Tool / framework | Result |
|---|---|
| Prowler 5.49.0, full scan | **80 FAIL / 92 PASS / 4 MANUAL** findings (53.5% pass); 53 of 82 checks failing |
| Prowler, CIS AWS Foundations 5.0 export | 57 fail / 56 pass, 113 check rows |
| Prowler, NIST 800-53 Rev 5 export | 1,312 fail / 2,004 pass, 3,316 check rows |
| Security Hub, AWS FSBP 1.0.0 | **8 FAILED, 2 PASSED, 306 NOT_AVAILABLE** |

The compliance exports count rows, which expand per resource, so they are larger than the 176 findings (82 distinct checks)
in the primary scan. Prowler's own summary panel reports framework percentages at control level; the
numbers above are counts from the exported CSVs so they can be re-derived with grep.

### Why the two tools disagree, and why that matters

`NOT_AVAILABLE` is not a pass and not a failure. It means the control could not be evaluated: no
AWS Config recorder at baseline, standards only partially enabled, or a service the account does not
use. That leaves Security Hub with an honest denominator of **10**, not 316 - a pass rate of 20%,
against Prowler's 53.5% over a much wider rule set.

Three consequences worth stating in an interview:

1. A dashboard percentage is meaningless without the denominator. `306 NOT_AVAILABLE` is the number a
   reviewer should ask about first, and the number a slide deck usually hides.
2. Security Hub is an aggregation and prioritisation layer. Prowler is a rule engine. Neither replaces
   the other, and an account that looks green in one can be red in the other.
3. Controls that cannot evaluate are a detection blind spot, not a clean bill of health. The fix is
   enabling the prerequisite (Config, the standard, the service), not muting the finding.

## Findings fixed

| # | Finding | Before | After | Evidence |
|---|---|---|---|---|
| 1 | Bucket readable by anyone on the internet | `BlockPublicAcls=true` only; other three blocks off; public `GetObject` statement; `curl` **200** | all four blocks true; `BucketOwnerEnforced`; public statement deleted; `curl` **403** | `bpa-before.json`, `bpa-after.json`, `curl-before.txt`, `curl-after.txt` |
| 2 | SSH open to 0.0.0.0/0 | `IpPermissions` containing 22/tcp 0.0.0.0/0 | `IpPermissions: []`; rule `sgr-0bea3bb32ad3e868a` revoked | `sg-before.json`, `sg-after.json` |
| 3 | Standing key and wildcard user | key `Active`, inline `s3:*` on `*` | key inactive then deleted; user and inline policy deleted | `access-keys-before.json`, `keys-after.json` (`[]`) |
| 4 | IMDSv1 permitted | `HttpTokens: optional` | `HttpTokens: required`, `State: applied` | `imds-before.json`, `imds-after.json` |
| 5 | No password policy (AWS default: 6 characters, no complexity) | `get-account-password-policy` returned `NoSuchEntity` | 14 chars, all four classes, reuse prevention 24, max age 90 | `password-policy-before.json`, `password-policy-after.json` |
| 6 | No account-level Block Public Access | absent | all four true, account-wide | `bpa-account-after.json` |

Finding 1 has a detail worth keeping: `BlockPublicAcls` was already true. Partial public access
blocking is the failure mode that makes a bucket *look* protected in the console while
`IgnorePublicAcls`, `BlockPublicPolicy` and `RestrictPublicBuckets` are all doing nothing. Three of
four is not a passing grade here.

Finding 3 is the one the original script got wrong. It deleted the access key and left the user with
`s3:*` on `*` still attached. The key is a credential; the user's permissions are the finding. Deleting
only the key removes the symptom and leaves the account failing the same control on the next scan.

Finding 5 is stronger than "weak policy". `NoSuchEntity` means AWS was applying its default of a
6-character minimum with no character requirements at all.

## Result: measurement after remediation

The raw pass rate fell because I removed stale objects that were passing. Measured on the same
resources in both scans, failing findings dropped from 57 to 50. I'd rather reduce attack surface and
report a lower raw number than keep stale passes that make the account look better than it is.

| Measure | Before | After | Comparable? |
|---|---|---|---|
| Findings, raw (FAIL / PASS / MANUAL) | 80 / 92 / 4 (176) | 50 / 53 / 4 (107) | No - population changed |
| Finding-level pass rate, raw | 53.5% | 51.5% | No - population changed |
| Same 106 resource-checks in both scans: FAIL | 57 | **50** | Yes |
| Same 106 resource-checks: pass rate | 44.1% | **51.0%** | Yes |
| Checks failing, worst resource wins | 53 of 82 | **45 of 78** | Mostly - 4 checks had no resources left |

Prowler 5.49.0, same frameworks both phases (CIS 5.0, NIST 800-53 Rev 5). Derived by
`scripts/01-compare.py` into `before-after.csv` (per check) and `before-after-findings.csv`
(per check and resource).

**Why the raw number moved the wrong way.** 70 findings disappeared between scans - 47 of them
passes - because the 2024 course buckets and roles they described no longer exist. One more effect:
with account-level Block Public Access on, Prowler stopped evaluating `s3_bucket_public_access` per
bucket (8 rows, 2 FAIL) and recorded a single account-level PASS. Eight findings became one, with no
change in what any bucket exposes. A finding-level pass rate rewards keeping correctly configured
junk; it is the same denominator problem as Security Hub's 306 `NOT_AVAILABLE`.

**Checks fixed (8), none regressed:** `ec2_instance_imdsv2_enabled`,
`ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22`, `iam_password_policy_minimum_length_14`,
`iam_password_policy_reuse_24`, `iam_policy_attached_only_to_group_or_roles`,
`s3_account_level_public_access_blocks`, `s3_bucket_level_public_access_block`,
`s3_bucket_public_access`.

**Still failing at critical or high (8)** - each is accepted below or belongs to a later project:

| Severity | Check | Where it is handled |
|---|---|---|
| Critical | `iam_aws_attached_policy_no_administrative_privileges` | Fixed 2026-11-13: admin moved to Identity Center; `project_admin` has no key and no password, deletion pending. Not yet re-scanned |
| High | `iam_user_mfa_enabled_console_access` | Fixed 2026-11-13: `project_admin` login profile removed; Identity Center requires MFA. Not yet re-scanned |
| High | `iam_avoid_root_usage` | Reviewed, accepted - see below |
| High | `guardduty_is_enabled` | project 2 |
| High | `ec2_ebs_default_encryption` | Fixed 2026-11-13: enabled in us-east-1 (`raw/ebs-default-encryption-after.json`) |
| High | `ec2_ebs_volume_encryption` | lab instance root volume; default encryption does not apply to existing volumes, so this closes at teardown |
| High | `ec2_networkacl_allow_ingress_any_port` | Accepted - see below |
| High | `sns_topics_kms_encryption_at_rest_enabled` | Accepted - see below |

## Accepted, not fixed

| Item | Why it stays |
|---|---|
| Root usage (`iam_avoid_root_usage`, High) | Root was used on 2026-11-12, 15:05-15:08, to delete an old IAM user and create the first admin before Identity Center existed - 84 events, all in that window (`raw/root-usage-review.json`). All administration since then goes through Identity Center. Root keeps MFA and has no access keys, and is reserved for root-only tasks. The check looks back over recent history, so it will keep failing for a while. |
| Default VPC NACL allows all inbound (`ec2_networkacl_allow_ingress_any_port`, High; also the port 22 and 3389 NACL checks) | Tightening it adds friction without adding security this environment needs: security groups already filter at the instance, there is no sensitive data, and nothing operational depends on the account, so a redundant defense-in-depth layer is not warranted here. A working NACL would still need inbound 1024-65535 for return traffic, which keeps the 3389 check failing unless explicit denies are numbered ahead of it, and NACL drops show up as silent timeouts in later labs. Accepted 2026-11-13. Revisit if the account ever holds sensitive data or production workloads; use a dedicated NACL on that subnet rather than editing the default one. |
| SNS topic `sec-lab-budget` not KMS-encrypted (`sns_topics_kms_encryption_at_rest_enabled`, High) | The topic carries budget alerts only - a dollar amount and a threshold, no sensitive data. AWS Budgets can only publish to an encrypted topic through a customer-managed KMS key whose policy grants it access (the AWS-managed `aws/sns` key policy cannot be edited), so the fix costs ~1 USD/month and adds a way for alerts to fail silently. Accepted 2026-11-13. Revisit if the topic ever carries anything beyond budget alerts. |
| GuardDuty off, no organization trail, 16 missing CloudWatch alarms | Real findings, but they belong to project 2 (detection) and project 7 (response), where enabling them is the point rather than a side effect. |

An audit that fixes everything is not an audit, it is a rebuild. Deciding what to leave, and being
able to defend the choice, is the job.

## What I got wrong, and what it cost

Recorded because these are the parts I would otherwise forget:

- **`s3api put-public-access-block` cannot set the account-level block.** It requires `--bucket`
  because it is namespaced to a bucket. The account switch lives in `s3control`, a different service
  endpoint. The console shows one page with one set of switches and writes to both, which is exactly
  why this is easy to get wrong.
- **`get-account-password-policy` returns `NoSuchEntity`** when no policy has ever been set, not a
  defaulted weak policy. The distinction changes the finding from "length 8" to "length 6, no
  complexity".
- **There is no `describe-instance-metadata-options` subcommand.** Metadata options are a field on
  `describe-instances`.
- **The password policy flags are `--require-uppercase-characters`**, not `-letters`.
- **A name filter is not an inventory.** When cleaning up the 2024 leftovers, filtering roles by name
  matched four of six; the two that were missed (`demo-lambda-role-dy1niio2`,
  `SnowFamilyS3Import-demo-job-1-1`) only appeared when I enumerated every role's `CreateDate` and
  looked for the year.
- **I reported the fail rate as the pass rate.** The first draft said "46.5% pass". 80 of 172
  PASS/FAIL findings failed, so 46.5% was the fail rate; the pass rate was 53.5%. It also said "172
  checks" when there were 176 findings across 82 checks. Re-derived from the CSV, not the console.
- **The scan script would have dropped both frameworks silently.** It confirmed a framework existed by
  matching a whole line of `prowler aws --list-compliance`, but that output prints `- cis_5.0_aws`
  with a banner and colour codes, so the match never succeeded. The after-scan would have run with no
  CIS or NIST export and no error. The script now checks for the framework definition file Prowler
  ships, which is an exact match by construction.
- **The comparison script reported nothing, and would have said so calmly.** Prowler 5 CSV is
  `;`-delimited; read with the default comma, the header became two nonsense columns, no `CHECK_ID`
  was found, and every row was skipped. It also kept only the last resource per check, so a check
  failing on one bucket and passing on seven could score either way depending on row order.
  Same pattern as the Config recorder: a tool reporting success while doing less than assumed.

## Evidence index

| File | Supports |
|---|---|
| `raw/bpa-before.json`, `raw/bpa-after.json` | partial to complete public access blocking |
| `raw/curl-before.txt` (200), `raw/curl-after.txt` (403) | the bucket was anonymously readable and no longer is |
| `raw/acl-before.json` | ACL posture before `BucketOwnerEnforced` |
| `raw/sg-before.json`, `raw/sg-after.json` | SSH rule present, then absent |
| `raw/encryption-after.json` | SSE-S3 (`AES256`) applied by default, SSE-C blocked |
| `raw/versioning-after.json` | versioning `Enabled` |
| `raw/bucket-policy-after.txt` | `NoSuchBucketPolicy` - the public statement is gone, not hidden |
| `raw/access-keys-before.json`, `raw/keys-after.json` | key existed, then none |
| `raw/imds-before.json`, `raw/imds-after.json` | IMDSv1 permitted, then required |
| `raw/password-policy-before.json` (`{"absent":true}`), `raw/password-policy-after.json` | no policy, then a strict one |
| `raw/bpa-account-after.json` | account-level block, all four true |
| `raw/account-summary-after.json` | users, MFA devices, no root keys, role counts |
| `prowler-before/prowler-before.{csv,html,ocsf.json}` | full scan, redacted |
| `prowler-before/compliance/cis_5.0_aws.csv`, `nist_800_53_r5.csv` | framework exports |
| `raw/securityhub-before.json` | 8 FAILED / 2 PASSED / 306 NOT_AVAILABLE |
| `prowler-after/prowler-after.{csv,html,ocsf.json}`, `prowler-after/compliance/` | after-scan, same frameworks, redacted |
| `before-after.csv` | per-check delta: 8 fixed, 0 regressed, 4 gone |
| `before-after-findings.csv` | per check and resource: 7 fixed, 70 gone, 1 new |

Redaction: account ID masked in filenames and contents; the key ID and the SNS subscription email are
masked in the Prowler exports; the instance public IP is masked. `scripts/redact-audit.sh` enforces
this at commit time via `.githooks/pre-commit`.

## Interview questions

1. **"Security Hub says 306 NOT_AVAILABLE. Is the account secure?"** - It is unevaluated. `NOT_AVAILABLE`
   means a missing prerequisite, usually Config or a partially enabled standard. The question I would
   ask back is what the denominator is, because 8 failures out of 10 evaluated and 8 out of 316 are
   very different claims.
2. **"Your bucket had BlockPublicAcls on. Why was it still public?"** - Because the other three blocks
   were off, and an ACL block does not stop a public bucket policy. Bucket policy grants and ACLs are
   separate paths, which is why all four switches exist and why three of four is not partial credit.
3. **"You deleted the access key. Was the finding closed?"** - No, and that was my first bug. The
   user's inline `s3:*` was the finding. I had to delete the policy and the user too, and re-verify.
4. **"How do you know your fix did not break anything?"** - For the bucket, the proof is the object
   still exists and returns 403 anonymously while remaining readable to the owner; the application
   path is validated separately. For SSH, closing the rule assumes you have another path in - here,
   SSM Session Manager - and that assumption is the thing that gets checked before the rule is closed.

## At scale

- Aggregate Prowler across accounts with `--organizations-role`, and treat Security Hub as the
  triage surface rather than the source of truth.
- Everything here belongs in CI as Terraform or cfn-guard, so `BlockPublicPolicy=false` cannot merge.
- An exception register with owner, expiry and compensating control matters more to an auditor than a
  perfect score, because it proves someone is thinking rather than muting.
