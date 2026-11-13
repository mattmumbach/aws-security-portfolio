#!/usr/bin/env bash
# Run a Prowler scan into evidence/01-posture/raw-<phase>/
# Usage: bash scripts/01-prowler.sh before|after
set -euo pipefail

PHASE="${1:-before}"
PROFILE="${AWS_PROFILE:-portfolio}"
REGION="${AWS_REGION:-us-east-1}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/evidence/01-posture/raw-$PHASE"

command -v prowler >/dev/null || { echo "prowler not installed: see scripts/README.md"; exit 1; }
mkdir -p "$OUT"

ARGS=(aws --profile "$PROFILE" --region "$REGION" -M csv json-html --output-directory "$OUT")
if prowler aws --list-compliance 2>/dev/null | grep -q 'cis_5.0_aws'; then
  ARGS+=(--compliance cis_5.0_aws)
  echo "    using CIS 5.0 framework"
else
  echo "    CIS 5.0 framework not found in this Prowler version; running full checks"
fi

echo "==> scanning ($PHASE) -> $OUT"
date -u
prowler "${ARGS[@]}" || echo "prowler exited non-zero (findings present is normal)"

echo
echo "Saved files:"
ls -1 "$OUT" | sed 's/^/  /'
cat <<EOF

Next:
  python3 scripts/01-compare.py   # after you have run both phases
EOF
