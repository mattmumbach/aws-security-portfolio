#!/usr/bin/env bash
# Create or update the schedule "trail-logging-check": every five minutes, EventBridge Scheduler
# invokes the function "trail-restart" with the input {"check":"scheduled"}.
#
# This is the backstop for the fast path. It does not depend on any event arriving: it asks whether
# the trail is logging and restarts it if it is not. A stopped trail therefore stays off for at most
# about five minutes, however it was stopped and whether or not the event path fired.
#
# The target holds two ARNs with the account ID in them, so it is built at run time and never
# stored in the repository. Everything this script prints has the account ID masked.
#
# Usage:
#   bash scripts/02-remediate/schedule.sh --print    show the schedule that would be set, change nothing
#   bash scripts/02-remediate/schedule.sh --apply    create or update it, then read it back
set -euo pipefail

MODE="${1:---print}"
case "$MODE" in --print|--apply) ;; *) echo "usage: $0 --print|--apply" >&2; exit 2 ;; esac

SCHEDULE_NAME="trail-logging-check"
EXPRESSION="rate(5 minutes)"
FUNCTION_NAME="trail-restart"
ROLE_NAME="trail-restart-scheduler"

ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
FUNCTION_ARN="$(aws lambda get-function-configuration --function-name "$FUNCTION_NAME" --query FunctionArn --output text)"
ROLE_ARN="$(aws iam get-role --role-name "$ROLE_NAME" --query Role.Arn --output text)"

mask() { sed -E "s/${ACCOUNT}/58********27/g"; }

# Input is the JSON the function receives; it is what sends the function down its scheduled-check
# path. Retries are turned off: a failed check is replaced by the next one five minutes later, so
# retrying an old one would only add duplicate runs.
TARGET="$(cat <<EOF
{
  "Arn": "${FUNCTION_ARN}",
  "RoleArn": "${ROLE_ARN}",
  "Input": "{\"check\":\"scheduled\"}",
  "RetryPolicy": { "MaximumRetryAttempts": 0 }
}
EOF
)"

if [[ "$MODE" == "--print" ]]; then
  echo "==> schedule that --apply would set (nothing changed):"
  echo "name:       $SCHEDULE_NAME"
  echo "expression: $EXPRESSION"
  echo "window:     flexible time window OFF (run on the minute, not within a range)"
  echo "target:"
  echo "$TARGET" | mask
  exit 0
fi

if aws scheduler get-schedule --name "$SCHEDULE_NAME" >/dev/null 2>&1; then VERB="update-schedule"; else VERB="create-schedule"; fi
aws scheduler "$VERB" --name "$SCHEDULE_NAME" --schedule-expression "$EXPRESSION" \
  --flexible-time-window Mode=OFF --state ENABLED --target "$TARGET" \
  --description "Every five minutes: is org-trail logging? Restart it if not." >/dev/null
echo "==> $VERB done at $(date -u +%FT%TZ)"

echo "==> schedule now in EventBridge Scheduler, read back:"
aws scheduler get-schedule --name "$SCHEDULE_NAME" \
  --query '{Name:Name,State:State,ScheduleExpression:ScheduleExpression,FlexibleTimeWindow:FlexibleTimeWindow,Target:Target}' \
  --output json | mask
