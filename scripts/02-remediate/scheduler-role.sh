#!/usr/bin/env bash
# Create or update the role "trail-restart-scheduler": the role EventBridge Scheduler assumes in
# order to invoke the function "trail-restart" on a schedule.
#
# This is a second role, separate from the function's own. The function's role says what the
# function may do. This one says what the Scheduler may do, which is one thing: invoke that function.
#
# Both policies hold the account ID, so they are built at run time and never stored in the
# repository. Everything this script prints has the account ID masked.
#
# Usage:
#   bash scripts/02-remediate/scheduler-role.sh --print    show both policies, change nothing
#   bash scripts/02-remediate/scheduler-role.sh --apply    create or update the role, then read it back
#
# Idempotent: an existing role has its trust policy and inline policy replaced with the same text.
set -euo pipefail

MODE="${1:---print}"
case "$MODE" in --print|--apply) ;; *) echo "usage: $0 --print|--apply" >&2; exit 2 ;; esac

ROLE_NAME="trail-restart-scheduler"
POLICY_NAME="invoke-trail-restart"
FUNCTION_NAME="trail-restart"
SCHEDULE_GROUP="default"

ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
REGION="$(aws configure get region)"
FUNCTION_ARN="$(aws lambda get-function-configuration --function-name "$FUNCTION_NAME" --query FunctionArn --output text)"

[[ "$FUNCTION_ARN" == arn:aws:lambda:* ]] || { echo "function $FUNCTION_NAME not found" >&2; exit 1; }

mask() { sed -E "s/${ACCOUNT}/58********27/g"; }

# Trust policy: who may become this role. The Scheduler service, and only when it is acting for a
# schedule in this account's own schedule group. The two conditions are the ones the EventBridge
# Scheduler User Guide recommends ("Confused deputy prevention in EventBridge Scheduler"); the guide
# says aws:SourceArn must name a schedule group, not a single schedule.
TRUST="$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SchedulerMayAssumeForThisAccountsSchedules",
      "Effect": "Allow",
      "Principal": { "Service": "scheduler.amazonaws.com" },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "aws:SourceAccount": "${ACCOUNT}",
          "aws:SourceArn": "arn:aws:scheduler:${REGION}:${ACCOUNT}:schedule-group/${SCHEDULE_GROUP}"
        }
      }
    }
  ]
}
EOF
)"

# Permissions policy: what the role may do once assumed. Invoke one function.
PERMISSIONS="$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "InvokeTheOneFunction",
      "Effect": "Allow",
      "Action": "lambda:InvokeFunction",
      "Resource": "${FUNCTION_ARN}"
    }
  ]
}
EOF
)"

if [[ "$MODE" == "--print" ]]; then
  echo "==> trust policy that --apply would set on $ROLE_NAME (nothing changed):"
  echo "$TRUST" | mask
  echo "==> permissions policy that --apply would set on $ROLE_NAME (nothing changed):"
  echo "$PERMISSIONS" | mask
  exit 0
fi

if aws iam get-role --role-name "$ROLE_NAME" >/dev/null 2>&1; then
  aws iam update-assume-role-policy --role-name "$ROLE_NAME" --policy-document "$TRUST"
  echo "==> role $ROLE_NAME already existed; trust policy replaced"
else
  aws iam create-role --role-name "$ROLE_NAME" --assume-role-policy-document "$TRUST" \
    --description "Lets EventBridge Scheduler invoke the trail-restart function" >/dev/null
  echo "==> role $ROLE_NAME created"
fi
aws iam put-role-policy --role-name "$ROLE_NAME" --policy-name "$POLICY_NAME" --policy-document "$PERMISSIONS"

echo "==> trust policy now on $ROLE_NAME, read back from IAM:"
aws iam get-role --role-name "$ROLE_NAME" --query Role.AssumeRolePolicyDocument --output json | mask
echo "==> permissions policy now on $ROLE_NAME, read back from IAM:"
aws iam get-role-policy --role-name "$ROLE_NAME" --policy-name "$POLICY_NAME" --query PolicyDocument --output json | mask
