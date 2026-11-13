#!/usr/bin/env bash
# Empty a bucket of every object, version and delete marker, then delete the bucket.
# Usage: ./scripts/delete-bucket.sh <bucket-name>
set -euo pipefail

BUCKET="${1:-}"

die() { echo "error: $*" >&2; exit 1; }

[[ -z "$BUCKET" ]] && die "usage: $0 <bucket-name>"

for protected in config-bucket sec-lab-logs posture-lab cf-templates; do
  case "$BUCKET" in
    *"$protected"*) die "refusing to delete $BUCKET - matches protected pattern '$protected'" ;;
  esac
done

aws s3api head-bucket --bucket "$BUCKET" >/dev/null 2>&1 \
  || die "$BUCKET not found or not accessible"

echo "== $BUCKET"

total=0
while :; do
  payload=$(aws s3api list-object-versions --bucket "$BUCKET" --output json 2>/dev/null \
    | jq -c '{Objects: ([.Versions[]? | {Key,VersionId}] + [.DeleteMarkers[]? | {Key,VersionId}])[0:1000]}')

  count=$(printf '%s' "$payload" | jq '.Objects | length')
  [[ "$count" -eq 0 ]] && break

  aws s3api delete-objects --bucket "$BUCKET" --delete "$payload" >/dev/null
  total=$((total + count))
  echo "  deleted $count objects/versions"
done

if [[ "$total" -gt 0 ]]; then
  echo "  total removed: $total"
else
  echo "  already empty"
fi

aws s3api delete-bucket --bucket "$BUCKET"
echo "  bucket deleted"
