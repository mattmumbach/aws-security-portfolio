#!/usr/bin/env bash
# Project 1 teardown. Keeps the CloudTrail trail and Security Hub enabled.
#
# Safe to re-run: every step checks whether its resource still exists and
# prints "already gone" instead of failing. It ends with read-only checks
# saved to evidence/01-posture/raw/teardown-after.txt, and only removes
# .lab-env once every check has passed.
#
# Fixed 2026-11-13: the first version died at `delete-user` because the lab
# user had already been deleted during remediation, so .lab-env was never
# removed; and its security-group retry loop could give up without saying so.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/.lab-env"
P=(--profile "$LAB_PROFILE" --region "$LAB_REGION")
EVID="$ROOT/evidence/01-posture/raw/teardown-after.txt"

# --- existence checks (read-only; each returns 0 if the resource still exists)
bucket_exists()   { aws s3api head-bucket --bucket "$LAB_BUCKET" "${P[@]}" >/dev/null 2>&1; }
instance_state()  {
  aws ec2 describe-instances --instance-ids "$LAB_INSTANCE" "${P[@]}" \
    --query 'Reservations[0].Instances[0].State.Name' --output text 2>/dev/null || echo "not-found"
}
# Terminated instances stay visible for about an hour, then describe returns
# NotFound (or None); all three mean gone.
instance_exists() { local s; s=$(instance_state); [[ "$s" != "terminated" && "$s" != "not-found" && "$s" != "None" ]]; }
sg_exists()       { aws ec2 describe-security-groups --group-ids "$LAB_SG" "${P[@]}" >/dev/null 2>&1; }
user_exists()     { aws iam get-user --user-name "$LAB_USER" --profile "$LAB_PROFILE" >/dev/null 2>&1; }

echo "==> 1. Bucket $LAB_BUCKET (every version and delete marker, then the bucket)"
if bucket_exists; then
  # Versioned buckets keep old versions and delete markers; delete-bucket
  # refuses until all of them are gone.
  while IFS= read -r obj; do
    aws s3api delete-objects --bucket "$LAB_BUCKET" "${P[@]}" \
      --delete "{\"Objects\":[$obj]}" >/dev/null
  done < <(aws s3api list-object-versions --bucket "$LAB_BUCKET" "${P[@]}" --output json \
    | jq -c '[.Versions[]?, .DeleteMarkers[]?] | map({Key: .Key, VersionId: .VersionId}) | .[]')
  aws s3api delete-bucket --bucket "$LAB_BUCKET" "${P[@]}"
  echo "    deleted"
else
  echo "    already gone"
fi

echo "==> 2. Instance $LAB_INSTANCE (its root volume is DeleteOnTermination)"
if instance_exists; then
  aws ec2 terminate-instances --instance-ids "$LAB_INSTANCE" "${P[@]}" >/dev/null
  echo "    terminating, waiting for AWS to confirm..."
  aws ec2 wait instance-terminated --instance-ids "$LAB_INSTANCE" "${P[@]}"
  echo "    terminated"
else
  echo "    already gone ($(instance_state))"
fi

echo "==> 3. Security group $LAB_SG"
if sg_exists; then
  # The instance's network interface can take a minute to release the group
  # after termination, so retry - but fail loudly if it never lets go.
  for attempt in 1 2 3 4 5 6 7 8 9 10 11 12; do
    if aws ec2 delete-security-group --group-id "$LAB_SG" "${P[@]}" >/dev/null 2>&1; then
      echo "    deleted (attempt $attempt)"
      break
    fi
    sleep 10
  done
  if sg_exists; then
    echo "ERROR: $LAB_SG still exists after 2 minutes. Something still uses it:" >&2
    aws ec2 describe-network-interfaces --filters Name=group-id,Values="$LAB_SG" "${P[@]}" \
      --query 'NetworkInterfaces[].[NetworkInterfaceId,Status,Description]' --output text >&2
    exit 1
  fi
else
  echo "    already gone"
fi

echo "==> 4. IAM user $LAB_USER"
if user_exists; then
  for key in $(aws iam list-access-keys --user-name "$LAB_USER" --profile "$LAB_PROFILE" \
               --query 'AccessKeyMetadata[].AccessKeyId' --output text); do
    aws iam delete-access-key --access-key-id "$key" --user-name "$LAB_USER" --profile "$LAB_PROFILE"
  done
  aws iam delete-user-policy --user-name "$LAB_USER" --policy-name lab-s3-wildcard \
    --profile "$LAB_PROFILE" 2>/dev/null || true
  aws iam delete-user --user-name "$LAB_USER" --profile "$LAB_PROFILE"
  echo "    deleted"
else
  echo "    already gone (deleted during remediation)"
fi

echo "==> 5. Verify, and save the proof"
fail=0
check() {  # check <label> <command...>: passes when the command reports the resource is gone
  local label="$1"; shift
  if "$@"; then
    printf '%-16s STILL EXISTS\n' "$label"; fail=1
  else
    printf '%-16s gone\n' "$label"
  fi
}
{
  echo "# Project 1 teardown verification"
  echo "# $(date -u +%FT%TZ), profile $LAB_PROFILE, region $LAB_REGION"
  check "bucket"         bucket_exists
  check "instance"       instance_exists
  check "security-group" sg_exists
  check "iam-user"       user_exists
  echo "instance state:  $(instance_state)"
} | tee "$EVID"
# fail is set inside the pipeline's subshell, so re-derive it from the file.
grep -q 'STILL EXISTS' "$EVID" && fail=1

if (( fail )); then
  echo "ERROR: something is still there - .lab-env kept so you can re-run this script." >&2
  exit 1
fi

rm -f "$ROOT/.lab-env"
echo
echo "Teardown complete. Proof: evidence/01-posture/raw/teardown-after.txt"
echo "CloudTrail, Security Hub and Config intentionally left on for later projects."
