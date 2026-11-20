#!/usr/bin/env bash
# Give the role "trail-restart-lambda" the only things its function needs:
# write its own logs, and read the status of one trail and call StartLogging on it.
#
# The policy holds the account ID inside its ARNs, so it is built at run time and never stored in
# the repository. Everything this script prints has the account ID masked.
#
# Usage:
#   bash scripts/02-remediate/role-policy.sh --print    show the policy that would be set, change nothing
#   bash scripts/02-remediate/role-policy.sh --apply    set it, then read it back from IAM
#
# Idempotent: put-role-policy replaces the inline policy of the same name each time.
set -euo pipefail

MODE="${1:---print}"
case "$MODE" in --print|--apply) ;; *) echo "usage: $0 --print|--apply" >&2; exit 2 ;; esac

ROLE_NAME="trail-restart-lambda"
POLICY_NAME="restart-org-trail"
FUNCTION_NAME="trail-restart"
TRAIL_NAME="org-trail"

ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
REGION="$(aws configure get region)"
TRAIL_ARN="$(aws cloudtrail describe-trails --trail-name-list "$TRAIL_NAME" --query 'trailList[0].TrailARN' --output text)"

[[ "$TRAIL_ARN" == arn:aws:cloudtrail:* ]] || { echo "trail $TRAIL_NAME not found" >&2; exit 1; }

LOG_GROUP_ARN="arn:aws:logs:${REGION}:${ACCOUNT}:log-group:/aws/lambda/${FUNCTION_NAME}"

mask() { sed -E "s/${ACCOUNT}/58********27/g"; }

# Statement 1: the two actions this function exists to perform, on the one trail it protects:
#   ask whether the trail is logging (for the scheduled check) and turn it back on.
#   Both accept a trail ARN as their resource (Service Authorization Reference, AWS CloudTrail),
#   so the role cannot read, start, stop or change any other trail.
# Statements 2 and 3: the function's own log group and nothing else. The managed policy
#   AWSLambdaBasicExecutionRole grants the same three actions on Resource "*".
POLICY="$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CheckAndRestartTheOneTrail",
      "Effect": "Allow",
      "Action": [ "cloudtrail:GetTrailStatus", "cloudtrail:StartLogging" ],
      "Resource": "${TRAIL_ARN}"
    },
    {
      "Sid": "CreateOwnLogGroup",
      "Effect": "Allow",
      "Action": "logs:CreateLogGroup",
      "Resource": "${LOG_GROUP_ARN}:*"
    },
    {
      "Sid": "WriteOwnLogs",
      "Effect": "Allow",
      "Action": [ "logs:CreateLogStream", "logs:PutLogEvents" ],
      "Resource": "${LOG_GROUP_ARN}:*"
    }
  ]
}
EOF
)"

if [[ "$MODE" == "--print" ]]; then
  echo "==> inline policy that --apply would set on $ROLE_NAME (nothing changed):"
  echo "$POLICY" | mask
  exit 0
fi

aws iam put-role-policy --role-name "$ROLE_NAME" --policy-name "$POLICY_NAME" --policy-document "$POLICY"

echo "==> inline policy now on $ROLE_NAME, read back from IAM:"
aws iam get-role-policy --role-name "$ROLE_NAME" --policy-name "$POLICY_NAME" --query PolicyDocument --output json | mask
