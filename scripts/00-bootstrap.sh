#!/usr/bin/env bash
# Account baseline: log bucket, trail, Security Hub standards, budget alarm.
# Prereqs: awscli v2, jq, an SSO profile. Run once per account.
set -euo pipefail

PROFILE="${AWS_PROFILE:-portfolio}"
REGION="${AWS_REGION:-us-east-1}"
BUDGET_EMAIL="${BUDGET_EMAIL:-}"

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

command -v aws >/dev/null || die "awscli not installed"
command -v jq  >/dev/null || die "jq not installed"

ACCT=$(aws sts get-caller-identity --profile "$PROFILE" --query Account --output text)
ARN=$(aws sts get-caller-identity --profile "$PROFILE" --query Arn --output text)

case "$ARN" in
  *":root") die "You are authenticated as root. Create an Identity Center admin and use that." ;;
esac

echo "Account : $ACCT"
echo "Caller  : $ARN"
echo "Region  : $REGION"
read -r -p "Proceed with baseline setup? [y/N] " ok
[[ "$ok" == "y" || "$ok" == "Y" ]] || exit 1

LOG_BUCKET="sec-lab-logs-${ACCT}-${REGION}"
echo "==> Log bucket: $LOG_BUCKET"
if ! aws s3api head-bucket --bucket "$LOG_BUCKET" --profile "$PROFILE" 2>/dev/null; then
  aws s3api create-bucket --bucket "$LOG_BUCKET" --profile "$PROFILE" --region "$REGION"
fi
aws s3api put-public-access-block --bucket "$LOG_BUCKET" --profile "$PROFILE" \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
aws s3api put-bucket-encryption --bucket "$LOG_BUCKET" --profile "$PROFILE" \
  --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"},"BucketKeyEnabled":true}]}'
aws s3api put-bucket-versioning --bucket "$LOG_BUCKET" --profile "$PROFILE" \
  --versioning-configuration Status=Enabled

# Bucket policy: CloudTrail + Config delivery, TLS only.
POLICY=$(cat <<EOF
{"Version":"2012-10-17","Statement":[
 {"Sid":"DenyInsecureTransport","Effect":"Deny","Principal":"*","Action":"s3:*",
  "Resource":["arn:aws:s3:::${LOG_BUCKET}","arn:aws:s3:::${LOG_BUCKET}/*"],
  "Condition":{"Bool":{"aws:SecureTransport":"false"}}},
 {"Sid":"CloudTrailAclCheck","Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},
  "Action":"s3:GetBucketAcl","Resource":"arn:aws:s3:::${LOG_BUCKET}"},
 {"Sid":"CloudTrailWrite","Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},
  "Action":"s3:PutObject","Resource":"arn:aws:s3:::${LOG_BUCKET}/AWSLogs/${ACCT}/*",
  "Condition":{"StringEquals":{"s3:x-amz-acl":"bucket-owner-full-control"}}},
 {"Sid":"ConfigAclCheck","Effect":"Allow","Principal":{"Service":"config.amazonaws.com"},
  "Action":"s3:GetBucketAcl","Resource":"arn:aws:s3:::${LOG_BUCKET}"},
 {"Sid":"ConfigWrite","Effect":"Allow","Principal":{"Service":"config.amazonaws.com"},
  "Action":"s3:PutObject","Resource":"arn:aws:s3:::${LOG_BUCKET}/AWSLogs/${ACCT}/Config/*",
  "Condition":{"StringEquals":{"s3:x-amz-acl":"bucket-owner-full-control"}}}]}
EOF
)
aws s3api put-bucket-policy --bucket "$LOG_BUCKET" --profile "$PROFILE" --policy "$POLICY"

echo "==> CloudTrail"
if aws cloudtrail describe-trails --profile "$PROFILE" --region "$REGION" \
     --trail-name-list org-trail --query 'trailList[0].Name' --output text 2>/dev/null | grep -q org-trail; then
  echo "    trail exists"
else
  aws cloudtrail create-trail --name org-trail --s3-bucket-name "$LOG_BUCKET" \
    --is-multi-region-trail --enable-log-file-validation --profile "$PROFILE" --region "$REGION"
fi
aws cloudtrail start-logging --name org-trail --profile "$PROFILE" --region "$REGION"

echo "==> Security Hub"
aws securityhub enable-security-hub --profile "$PROFILE" --region "$REGION" 2>/dev/null || true
STD_ARNS=$(aws securityhub describe-standards --profile "$PROFILE" --region "$REGION" \
  --query 'Standards[].StandardsArn' --output text)

FSBP=$(echo "$STD_ARNS" | tr '\t' '\n' | grep -i 'foundational-security-best-practices' | head -1 || true)
# CIS: take the newest modern standard. The legacy ":::" ruleset ARNs sort first
# alphabetically and are deprecated, so filter them out, then sort by version.
CIS=$(echo "$STD_ARNS" | tr '\t' '\n' \
  | grep -i 'cis-aws-foundations' | grep '/standards/' \
  | sort -t/ -k2,2V | tail -1 || true)
NIST53=$(echo "$STD_ARNS" | tr '\t' '\n' | grep -i 'nist-800-53' | tail -1 || true)

REQS=()
[[ -n "$FSBP"   ]] && REQS+=("StandardsArn=$FSBP")
[[ -n "$CIS"    ]] && REQS+=("StandardsArn=$CIS")
[[ -n "$NIST53" ]] && REQS+=("StandardsArn=$NIST53")
if (( ${#REQS[@]} > 0 )); then
  aws securityhub batch-enable-standards --profile "$PROFILE" --region "$REGION" \
    --standards-subscription-requests "${REQS[@]}"
  echo "    enabled: $FSBP $CIS"
else
  echo "    WARN: no matching standards found; list them with:"
  echo "    aws securityhub describe-standards --profile $PROFILE --region $REGION"
fi

if [[ -n "$BUDGET_EMAIL" ]]; then
  echo "==> Budget alarm -> $BUDGET_EMAIL"
  TOPIC=$(aws sns create-topic --name sec-lab-budget --profile "$PROFILE" --region "$REGION" \
    --query TopicArn --output text)
  aws sns subscribe --topic-arn "$TOPIC" --protocol email \
    --notification-endpoint "$BUDGET_EMAIL" --profile "$PROFILE" --region "$REGION" >/dev/null
  BUDGET_DEF='{"BudgetName":"sec-lab-monthly","BudgetLimit":{"Amount":"10","Unit":"USD"},"TimeUnit":"MONTHLY","BudgetType":"COST"}'
  NOTIFS=$(cat <<EOF
[{"Notification":{"NotificationType":"ACTUAL","ComparisonOperator":"GREATER_THAN","Threshold":80},
  "Subscribers":[{"SubscriptionType":"SNS","Address":"$TOPIC"}]}]
EOF
)
  if aws budgets describe-budgets --profile "$PROFILE" --account-id "$ACCT" \
       --query 'Budgets[?BudgetName==`sec-lab-monthly`].BudgetName' --output text | grep -q .; then
    echo "    budget exists, left unchanged"
  else
    aws budgets create-budget --profile "$PROFILE" --account-id "$ACCT" \
      --budget "$BUDGET_DEF" --notifications-with-subscribers "$NOTIFS"
  fi
  echo "    confirm the SNS email subscription in the inbox before trusting the alarm"
else
  echo "==> Budget skipped (re-run with BUDGET_EMAIL=you@example.com)"
fi

cat <<'NEXT'

Next:
  1. Enable AWS Config from the console (one click; it creates the service role and bucket):
     Config -> Get started -> Record all resource types -> Create
     Do not hand-roll this under time pressure.
     TRAP: "record all" can still exclude IAM types. After setup, confirm:
       aws configservice describe-configuration-recorders --output json
     The recording group must show no exclusionByResourceTypes. If IAM types are
     excluded, IAM rules report INSUFFICIENT_DATA forever. Fix with:
       stop-configuration-recorder, then put-configuration-recorder with
       --recording-group '{"allSupported":true,"includeGlobalResourceTypes":true}',
       then start-configuration-recorder.
     The new strategy enum is ALL_SUPPORTED_RESOURCE_TYPES (not ALL_SUPPORTED), and
     sending legacy booleans together with recordingStrategy is rejected.
  2. Verify:
     aws cloudtrail get-trail-status --name org-trail --profile portfolio --region us-east-1
     aws securityhub get-enabled-standards --profile portfolio --region us-east-1
  3. Wait 15-30 minutes for controls to evaluate before scanning.
NEXT
