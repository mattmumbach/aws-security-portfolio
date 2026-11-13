#!/usr/bin/env bash
# Run a Prowler scan into evidence/01-posture/prowler-<phase>/
# Usage: bash scripts/01-prowler.sh before|after
set -euo pipefail

PHASE="${1:-before}"
PROFILE="${AWS_PROFILE:-${LAB_PROFILE:-default}}"
REGION="${AWS_REGION:-${LAB_REGION:-us-east-1}}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/evidence/01-posture/prowler-$PHASE"

command -v prowler >/dev/null || { echo "prowler not installed: see scripts/README.md"; exit 1; }
mkdir -p "$OUT"

# Prowler 5.x output formats: csv, json-asff, json-ocsf, html, sarif.
# "json-html" was never a valid choice - it is the reason the first after-scan failed.
ARGS=(aws --profile "$PROFILE" --region "$REGION"
      -M csv json-ocsf html
      --output-directory "$OUT")

# Keep the same frameworks in both phases, or the before/after delta is meaningless.
# Names must be exact - these are argparse choices, not substrings.
# Check the framework definition files Prowler ships rather than parsing
# --list-compliance: that output carries a banner and colour codes, prints
# "- <name>" lines, and was seen returning a truncated list. A file named
# exactly <fw>.json is an exact match by construction.
PY="$ROOT/.venv/bin/python3"; [[ -x "$PY" ]] || PY=python3
COMPLIANCE_DIR="$("$PY" -c 'import os, prowler; print(os.path.join(os.path.dirname(prowler.__file__), "compliance", "aws"))' 2>/dev/null || true)"
FRAMEWORKS=()
for fw in cis_5.0_aws nist_800_53_revision_5_aws; do
  if [[ -n "$COMPLIANCE_DIR" && -f "$COMPLIANCE_DIR/$fw.json" ]]; then
    FRAMEWORKS+=("$fw")
  else
    echo "    framework not available in this Prowler version: $fw"
  fi
done
if [ ${#FRAMEWORKS[@]} -gt 0 ]; then
  ARGS+=(--compliance "${FRAMEWORKS[@]}")
  echo "    using: ${FRAMEWORKS[*]}"
else
  echo "    no framework matched; running the full check set"
fi

echo "==> scanning ($PHASE) -> $OUT"
date -u
prowler "${ARGS[@]}" || echo "prowler exited non-zero (exit 3 with findings is normal)"

echo
echo "Saved files:"
ls -1 "$OUT" | sed 's/^/  /'
cat <<EOF

Next:
  python3 scripts/01-compare.py   # after you have run both phases
EOF
