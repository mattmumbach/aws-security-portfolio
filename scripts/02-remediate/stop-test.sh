#!/usr/bin/env bash
# One trial of the automatic restart: stop org-trail, watch for a set time (60 seconds unless told
# otherwise), and say who restarted it.
#
# If the trail is still off when the time runs out, this script restarts it itself and says so, so
# that a failed trial never leaves the trail off for longer than the watch time.
#
# Usage:
#   bash scripts/02-remediate/stop-test.sh 3        trial number; output is saved to
#                                                   evidence/02-detection/raw/phase2-test3-watch.txt
#   bash scripts/02-remediate/stop-test.sh 7 360    the same, watching for 360 seconds - long enough
#                                                   for the five-minute scheduled check to act
#
# What it prints holds times and True/False only - no account ID, address or identity.
set -euo pipefail

N="${1:?usage: $0 <trial-number> [watch-seconds]}"
WATCH="${2:-60}"
TRAIL="org-trail"
OUT="evidence/02-detection/raw/phase2-test${N}-watch.txt"
[[ -e "$OUT" ]] && { echo "$OUT already exists; pick another trial number" >&2; exit 2; }

status() { aws cloudtrail get-trail-status --name "$TRAIL" --query "$1" --output text; }

{
  [[ "$(status IsLogging)" == "True" ]] || { echo "trail is not logging at the start; not running the trial"; exit 1; }

  echo "trial $N: stop requested $(date -u +%FT%TZ), watching for up to $WATCH s"
  aws cloudtrail stop-logging --name "$TRAIL"

  outcome="NOT restarted automatically within $WATCH s"
  for _ in $(seq 1 $((WATCH / 2))); do
    s="$(status IsLogging)"
    echo "$(date -u +%T) IsLogging=$s"
    if [[ "$s" == "True" ]]; then outcome="restarted automatically"; break; fi
    sleep 2
  done

  if [[ "$outcome" != "restarted automatically" ]]; then
    aws cloudtrail start-logging --name "$TRAIL"
    echo "$(date -u +%T) restarted by this script (start-logging called by hand)"
  fi

  echo "outcome: $outcome"
  echo "trail status, UTC:"
  TZ=UTC aws cloudtrail get-trail-status --name "$TRAIL" \
    --query '{IsLogging:IsLogging,Stopped:TimeLoggingStopped,Restarted:TimeLoggingStarted}' --output json
} | tee "$OUT"
