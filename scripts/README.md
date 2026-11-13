# Scripts - project 1

Run order on a fresh machine and a fresh AWS account.

## 1. Tooling (15 min)

`aws`, `brew`, and `pipx` are not installed on this Mac yet. `git`, `jq`, and system Python are.

```bash
# AWS CLI v2 (official pkg; needs admin password)
curl -fsSL "https://awscli.amazonaws.com/AWSCLIV2.pkg" -o /tmp/AWSCLIV2.pkg
sudo installer -pkg /tmp/AWSCLIV2.pkg -target /
aws --version

# Prowler in an isolated venv (avoids touching system Python)
python3 -m venv ~/.venvs/prowler
~/.venvs/prowler/bin/pip install --upgrade pip prowler
echo 'export PATH="$HOME/.venvs/prowler/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
prowler --version
```

If the venv fails, fall back to AWS CloudShell for the Prowler scan only and download the reports.

## 2. Console tasks (10 min, cannot be scripted safely)

1. Root account: enable hardware MFA, confirm no access keys exist.
2. IAM Identity Center: create an admin user, set MFA, assign AdministratorAccess.
3. Log in as that user, then locally:

```bash
aws configure sso --profile portfolio
# SSO start URL + region from the portal, then: aws sso login --profile portfolio
```

## 3. Baseline

```bash
chmod +x scripts/*.sh
AWS_PROFILE=portfolio BUDGET_EMAIL=you@example.com bash scripts/00-bootstrap.sh
```

Then enable AWS Config in the console (Config -> Get started -> record all resource types).
Confirm the SNS budget email subscription.

## 4. Project 1 run

```bash
bash scripts/01-deploy-baseline.sh     # deliberately weak resources
bash scripts/01-prowler.sh before      # full scan, ~5-15 min

# while the scan runs, wait 15 min and check Security Hub in the console

bash scripts/01-remediate.sh           # five fixes + before/after evidence
sleep 900                              # let Security Hub / Config re-evaluate
bash scripts/01-prowler.sh after
python3 scripts/01-compare.py          # -> evidence/01-posture/before-after.csv
```

## 5. Write-up and teardown

```bash
# paste the numbers from 01-compare.py into docs/01-posture-audit.md "Result"
git add -A && git commit -m "project 1: posture audit with before/after evidence"
bash scripts/01-teardown.sh
```

## Notes

- `.lab-env` holds resource IDs and is gitignored. Never commit it.
- The access key secret is never written to disk by these scripts. If you need a screenshot of a
  key, take it in the console and never save the image.
- Expect `curl before: 200` and `curl after: 403`. If the before state is 403, the bucket policy did
  not land - re-run the deploy step in a fresh account rather than editing evidence.
- Teardown keeps CloudTrail and Security Hub on; they cost little and later projects need them.

## Housekeeping scripts

### `delete-bucket.sh <bucket>`

Empties a bucket of every object, version and delete marker in 1000-object batches, then deletes the
bucket. Refuses to run against `config-bucket`, `sec-lab-logs`, `posture-lab` or `cf-templates`, so a
typo cannot destroy the lab.

Versioning is the usual reason a "bucket is not empty" error appears when a console listing shows
zero objects: delete markers and non-current versions still count. `aws s3 rb --force` does not
remove them.

### `redact-audit.sh [--staged|--tree|--all]`

Scans for identifiers that must not reach a public repository and exits non-zero on anything at
BLOCK level. Run it before every commit; the `.githooks/pre-commit` hook runs the `--staged` mode
automatically.

```bash
git config core.hooksPath .githooks   # once per clone
./scripts/redact-audit.sh --all       # manual sweep of the whole tree
git commit --no-verify                # escape hatch, use only with a stated reason
```

| Level | Detects |
|---|---|
| BLOCK | 12-digit account IDs, ARNs containing one, `AKIA`/`ASIA` access key IDs, secret access key field names, PEM private key blocks, personal email addresses, `/Users/<name>` paths |
| WARN | IAM unique IDs (`AROA`, `AIDA`, ...), EC2 resource IDs, IPv4 addresses, internal hostnames |

Both filenames and contents are scanned - a Prowler export leaked the account ID in the filename
while its contents had already been cleaned, which is the case that motivated the check.

`scripts/redaction-allowlist.txt` lists path exemptions, optionally scoped to one rule
(`^README\.md$|personal-email`). Every entry is a blind spot, so keep the file short.

### Committed evidence conventions

- Account ID always appears as `58********27`, never in full, in both filenames and contents.
- Prowler artifacts are renamed to `prowler-before.*` / `prowler-after.*`; framework exports to
  `compliance/cis_5.0_aws.csv` and `compliance/nist_800_53_r5.csv`.
- ARNs and resource IDs may stay in evidence when the account ID is masked - they are needed to
  prove the finding.

