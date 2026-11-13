#!/usr/bin/env bash
# Project 1 remediation: five fixes, each with a before/after you can screenshot.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/.lab-env"

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

echo "==> 5. Kill the standing access key"
aws iam update-access-key --access-key-id "$LAB_KEY_ID" --status Inactive \
  --user-name "$LAB_USER" --profile "$LAB_PROFILE"
aws iam delete-access-key --access-key-id "$LAB_KEY_ID" \
  --user-name "$LAB_USER" --profile "$LAB_PROFILE"

echo "==> 6. Enforce IMDSv2 on the instance"
aws ec2 modify-instance-metadata-options --instance-id "$LAB_INSTANCE" \
  --http-tokens required --http-endpoint enabled "${P[@]}"

echo "==> 7. Verify the fixes"
aws s3api get-public-access-block --bucket "$LAB_BUCKET" "${P[@]}" > "$EVID/bpa-after.json"
aws s3api get-bucket-policy-status --bucket "$LAB_BUCKET" "${P[@]}" > "$EVID/policy-status-after.json" 2>/dev/null || true
curl -s -o /dev/null -w 'after:  %{http_code}\n' \
  "https://$LAB_BUCKET.s3.amazonaws.com/customer-export.csv" | tee "$EVID/curl-after.txt"
aws ec2 describe-instance-metadata-options --instance-id "$LAB_INSTANCE" "${P[@]}" \
  --query 'InstanceMetadataOptions' > "$EVID/imds-after.json"
aws iam list-access-keys --user-name "$LAB_USER" --profile "$LAB_PROFILE" \
  > "$EVID/keys-after.json"

cat <<'EOF'

Expect: curl before 200, after 403. IMDSv2 sentence "required". No active keys.

Wait 10-15 minutes for Security Hub / Config to re-evaluate, then:
  bash scripts/01-prowler.sh after
EOF
