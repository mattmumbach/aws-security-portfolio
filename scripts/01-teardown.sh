#!/usr/bin/env bash
# Project 1 teardown. Keeps the CloudTrail trail and Security Hub enabled.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/.lab-env"
P=(--profile "$LAB_PROFILE" --region "$LAB_REGION")

echo "==> Emptying and deleting $LAB_BUCKET (including all versions)"
while IFS= read -r obj; do
  aws s3api delete-objects --bucket "$LAB_BUCKET" "${P[@]}" \
    --delete "{\"Objects\":[$obj]}" >/dev/null
done < <(aws s3api list-object-versions --bucket "$LAB_BUCKET" "${P[@]}" \
  --output json 2>/dev/null \
  | jq -c '[.Versions[]?, .DeleteMarkers[]?] | map({Key: .Key, VersionId: .VersionId}) | .[]')
aws s3api delete-bucket --bucket "$LAB_BUCKET" "${P[@]}"

echo "==> Terminating $LAB_INSTANCE"
aws ec2 terminate-instances --instance-ids "$LAB_INSTANCE" "${P[@]}" >/dev/null
aws ec2 wait instance-terminated --instance-ids "$LAB_INSTANCE" "${P[@]}"

echo "==> Deleting security group $LAB_SG"
for _ in 1 2 3 4 5 6; do
  if aws ec2 delete-security-group --group-id "$LAB_SG" "${P[@]}" 2>/dev/null; then break; fi
  sleep 10
done

echo "==> Removing IAM user $LAB_USER"
for key in $(aws iam list-access-keys --user-name "$LAB_USER" --profile "$LAB_PROFILE" \
             --query 'AccessKeyMetadata[].AccessKeyId' --output text); do
  aws iam delete-access-key --access-key-id "$key" --user-name "$LAB_USER" --profile "$LAB_PROFILE"
done
aws iam delete-user-policy --user-name "$LAB_USER" --policy-name lab-s3-wildcard --profile "$LAB_PROFILE" 2>/dev/null || true
aws iam delete-user --user-name "$LAB_USER" --profile "$LAB_PROFILE"

rm -f "$ROOT/.lab-env"
echo "Teardown complete. CloudTrail and Security Hub intentionally left on."
