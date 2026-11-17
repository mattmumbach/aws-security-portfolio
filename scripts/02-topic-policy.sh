#!/usr/bin/env bash
# Allow the EventBridge rule "guardduty-high" to publish to the SNS topic "gd-alerts".
#
# The console adds this permission silently when you pick an SNS target. The CLI does not, and
# without it the rule fires and SNS drops the message with no error anywhere you would look.
#
# Usage:
#   bash scripts/02-topic-policy.sh --print    show the policy that would be set, change nothing
#   bash scripts/02-topic-policy.sh --apply    set it, then read it back
#
# Idempotent: it writes the whole policy each time, so running it twice leaves the same result.
# The account ID is looked up at run time and masked in everything this script prints.
set -euo pipefail

MODE="${1:---print}"
case "$MODE" in --print|--apply) ;; *) echo "usage: $0 --print|--apply" >&2; exit 2 ;; esac

TOPIC_NAME="gd-alerts"
RULE_NAME="guardduty-high"

ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
TOPIC_ARN="$(aws sns list-topics --query "Topics[?ends_with(TopicArn, ':${TOPIC_NAME}')].TopicArn | [0]" --output text)"
RULE_ARN="$(aws events describe-rule --name "$RULE_NAME" --query Arn --output text)"

[[ "$TOPIC_ARN" == arn:aws:sns:* ]]  || { echo "topic $TOPIC_NAME not found" >&2; exit 1; }
[[ "$RULE_ARN"  == arn:aws:events:* ]] || { echo "rule $RULE_NAME not found" >&2; exit 1; }

mask() { sed -E "s/${ACCOUNT}/58********27/g"; }

# Statement 1 is the default SNS writes for every new topic: any principal, but only when the
# request comes from this account. It is kept unchanged.
# Statement 2 is the addition. The principal is the EventBridge service. The condition pins it to
# one rule, so no other rule - in this account or any other - can publish through the service.
POLICY="$(cat <<EOF
{
  "Version": "2008-10-17",
  "Id": "__default_policy_ID",
  "Statement": [
    {
      "Sid": "__default_statement_ID",
      "Effect": "Allow",
      "Principal": { "AWS": "*" },
      "Action": [
        "SNS:GetTopicAttributes",
        "SNS:SetTopicAttributes",
        "SNS:AddPermission",
        "SNS:RemovePermission",
        "SNS:DeleteTopic",
        "SNS:Subscribe",
        "SNS:ListSubscriptionsByTopic",
        "SNS:Publish"
      ],
      "Resource": "${TOPIC_ARN}",
      "Condition": { "StringEquals": { "AWS:SourceOwner": "${ACCOUNT}" } }
    },
    {
      "Sid": "AllowEventBridgeGuardDutyHigh",
      "Effect": "Allow",
      "Principal": { "Service": "events.amazonaws.com" },
      "Action": "sns:Publish",
      "Resource": "${TOPIC_ARN}",
      "Condition": { "ArnEquals": { "aws:SourceArn": "${RULE_ARN}" } }
    }
  ]
}
EOF
)"

if [[ "$MODE" == "--print" ]]; then
  echo "==> policy that --apply would set (nothing changed):"
  echo "$POLICY" | mask
  exit 0
fi

aws sns set-topic-attributes --topic-arn "$TOPIC_ARN" --attribute-name Policy --attribute-value "$POLICY"

echo "==> policy now on $TOPIC_NAME, read back from SNS:"
aws sns get-topic-attributes --topic-arn "$TOPIC_ARN" --query Attributes.Policy --output text \
  | python3 -m json.tool | mask
