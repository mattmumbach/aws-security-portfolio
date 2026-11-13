#!/usr/bin/env bash
# Project 1 remediation: five deliberate fixes plus the account-level hygiene
# that keeps Prowler and Security Hub red if you skip it. Every step captures
# its own before/after so the doc can cite evidence instead of memory.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/.lab-env"

# .lab-env was written by hand in an earlier session and may be missing the
# profile/region. Default to what the CLI is actually configured with rather
# than failing three steps in.
LAB_PROFILE="${LAB_PROFILE:-${AWS_PROFILE:-default}}"
LAB_REGION="${LAB_REGION:-${AWS_REGION:-us-east-1}}"

for v in LAB_BUCKET LAB_SG LAB_USER LAB_INSTANCE; do
  [[ -n "${!v:-}" ]] || { printf 'ERROR: %s missing from .lab-env\n' "$v" >&2; exit 1; }
done

P=(--profile "$LAB_PROFILE" --region "$LAB_REGION")
EVID="$ROOT/evidence/01-posture/raw"

echo "==> 0. Preserve the before state"
mkdir -p "$EVID"
aws s3api get-public-access-block --bucket "$LAB_BUCKET" "${P[@]}" > "$EVID/bpa-before.json" || true
aws s3api get-bucket-acl --bucket "$LAB_BUCKET" "${P[@]}" > "$EVID/acl-before.json" || true
curl -s -o /dev/null -w 'before: %{http_code}\n' \
  "https://$LAB_BUCKET.s3.amazonaws.com/customer-export.csv" | tee "$EVID/curl-before.txt"

echo "==> 1. Block Public Access (all four) and disable ACLs"
aws s3api put-public-access-block --bucket "$LAB_BUCKET" "${P[@]}" \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
aws s3api put-bucket-ownership-controls --bucket "$LAB_BUCKET" "${P[@]}" \
  --ownership-controls 'Rules=[{ObjectOwnership=BucketOwnerEnforced}]'
# Remove the public statement itself. Block Public Access already overrides it,
# but leaving a public policy behind is a finding waiting to resurface.
aws s3api delete-bucket-policy --bucket "$LAB_BUCKET" "${P[@]}" 2>/dev/null || true

echo "==> 2. Default encryption (SSE-S3; switch to KMS in project 3)"
aws s3api put-bucket-encryption --bucket "$LAB_BUCKET" "${P[@]}" \
  --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'

echo "==> 3. Versioning (needed for the audit trail story)"
aws s3api put-bucket-versioning --bucket "$LAB_BUCKET" "${P[@]}" \
  --versioning-configuration Status=Enabled

echo "==> 4. Close SSH from the internet"
aws ec2 revoke-security-group-ingress --group-id "$LAB_SG" --protocol tcp --port 22 \
  --cidr 0.0.0.0/0 "${P[@]}"
aws ec2 describe-security-groups --group-ids "$LAB_SG" "${P[@]}" \
  > "$EVID/sg-after.json"

echo "==> 5. Kill every standing access key"
# Enumerate instead of trusting LAB_KEY_ID. The ID stored in the repo evidence
# is masked on purpose, and a remediation that needs a secret to identify what
# it is deleting is fragile. Listing is the reliable move.
KEYS=$(aws iam list-access-keys --user-name "$LAB_USER" --profile "$LAB_PROFILE" \
  --query 'AccessKeyMetadata[].AccessKeyId' --output text)
if [[ -z "$KEYS" ]]; then
  echo "    no access keys on $LAB_USER"
else
  for k in $KEYS; do
    echo "    rotating out ${k:0:4}...${k: -4}"
    aws iam update-access-key --access-key-id "$k" --status Inactive \
      --user-name "$LAB_USER" --profile "$LAB_PROFILE"
    aws iam delete-access-key --access-key-id "$k" \
      --user-name "$LAB_USER" --profile "$LAB_PROFILE"
  done
fi
aws iam list-access-keys --user-name "$LAB_USER" --profile "$LAB_PROFILE" \
  > "$EVID/keys-after.json"

echo "==> 6. Enforce IMDSv2 on the instance"
aws ec2 modify-instance-metadata-options --instance-id "$LAB_INSTANCE" \
  --http-tokens required --http-endpoint enabled "${P[@]}"

echo "==> 7. Delete the user, not just the key"
# A key with no user behind it is the fix. The user with s3:* inline is the
# finding. Deleting only the key leaves the finding in place and the next scan
# still fails.
aws iam delete-user-policy --user-name "$LAB_USER" --policy-name lab-s3-wildcard \
  --profile "$LAB_PROFILE"
aws iam delete-user --user-name "$LAB_USER" --profile "$LAB_PROFILE"

echo "==> 8. Account-level Block Public Access"
# Per-bucket settings do not stop the next bucket someone creates in a hurry.
# The account-level switch is the one that survives a mistake.
# This is S3 *Control*, not s3api: s3api's put-public-access-block always
# requires --bucket, which is exactly the trap that hid this setting from me.
ACCT=$(aws sts get-caller-identity --profile "$LAB_PROFILE" --query Account --output text)
aws s3control put-public-access-block --account-id "$ACCT" --profile "$LAB_PROFILE" \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

echo "==> 9. Password policy"
aws iam get-account-password-policy --profile "$LAB_PROFILE" \
  > "$EVID/password-policy-before.json" 2>/dev/null || echo '{"absent":true}' \
  > "$EVID/password-policy-before.json"
aws iam update-account-password-policy --profile "$LAB_PROFILE" \
  --minimum-password-length 14 \
  --require-symbols --require-numbers \
  --require-uppercase-characters --require-lowercase-characters \
  --allow-users-to-change-password \
  --password-reuse-prevention 24 \
  --max-password-age 90

echo "==> 10. Verify the fixes"
aws s3api get-public-access-block --bucket "$LAB_BUCKET" "${P[@]}" > "$EVID/bpa-after.json"
aws s3control get-public-access-block --account-id "$ACCT" --profile "$LAB_PROFILE" \
  > "$EVID/bpa-account-after.json"
aws s3api get-bucket-policy-status --bucket "$LAB_BUCKET" "${P[@]}" > "$EVID/policy-status-after.json" 2>/dev/null || true
curl -s -o /dev/null -w 'after:  %{http_code}\n' \
  "https://$LAB_BUCKET.s3.amazonaws.com/customer-export.csv" | tee "$EVID/curl-after.txt"
aws ec2 describe-instances --instance-ids "$LAB_INSTANCE" "${P[@]}" \
  --query 'Reservations[0].Instances[0].MetadataOptions' > "$EVID/imds-after.json"
cat "$EVID/imds-after.json"
aws iam get-account-password-policy --profile "$LAB_PROFILE" \
  > "$EVID/password-policy-after.json"
aws iam get-account-summary --profile "$LAB_PROFILE" > "$EVID/account-summary-after.json"
aws iam get-user --user-name "$LAB_USER" --profile "$LAB_PROFILE" \
  > /dev/null 2>&1 && echo "    WARNING: $LAB_USER still exists" \
  || echo "    $LAB_USER confirmed deleted"

cat <<'EOF'

Expect: curl before 200, after 403. IMDSv2 HttpTokens "required". No active keys.
User absent. Account-level block all true. Password policy length 14.

Still console-only, and worth doing today:
  - MFA on project_admin (or delete its console login and use SSO instead)
  - MFA on root, and no root access keys
  These are not scriptable without an authenticator device.

Wait 10-15 minutes for Security Hub / Config to re-evaluate, then:
  bash scripts/01-prowler.sh after
EOF
