#!/usr/bin/env bash
# Project 1: deploy the deliberately weak baseline. Saves IDs to .lab-env (gitignored).
set -euo pipefail

PROFILE="${AWS_PROFILE:-portfolio}"
REGION="${AWS_REGION:-us-east-1}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="$ROOT/.lab-env"

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

ACCT=$(aws sts get-caller-identity --profile "$PROFILE" --query Account --output text)
[[ -f "$ENV_FILE" ]] && die "$ENV_FILE exists. Run 01-teardown.sh first, or remove it deliberately."

echo "==> S3 bucket with weakened public access block"
BUCKET="posture-lab-$(openssl rand -hex 4)"
aws s3api create-bucket --bucket "$BUCKET" --profile "$PROFILE" --region "$REGION" >/dev/null
aws s3api put-public-access-block --bucket "$BUCKET" --profile "$PROFILE" \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false

PUBLIC_POLICY=$(cat <<EOF
{"Version":"2012-10-17","Statement":[{"Sid":"oops-public-read","Effect":"Allow",
 "Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::${BUCKET}/*"}]}
EOF
)
aws s3api put-bucket-policy --bucket "$BUCKET" --profile "$PROFILE" --policy "$PUBLIC_POLICY"

printf 'email,ssn\njane@example.com,000-00-0000\n' > /tmp/sample.csv
aws s3 cp /tmp/sample.csv "s3://$BUCKET/customer-export.csv" --profile "$PROFILE" >/dev/null
echo "    $BUCKET (no default encryption)"

echo "==> Security group open to the internet on 22"
VPC=$(aws ec2 describe-vpcs --profile "$PROFILE" --region "$REGION" \
  --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)
if [[ "$VPC" == "None" || -z "$VPC" ]]; then
  echo "    no default VPC; creating one (this takes ~45s)"
  VPC=$(aws ec2 create-default-vpc --profile "$PROFILE" --region "$REGION" \
    --query 'Vpc.VpcId' --output text)
  aws ec2 wait vpc-available --vpc-ids "$VPC" --profile "$PROFILE" --region "$REGION"
fi
[[ "$VPC" == "None" || -z "$VPC" ]] && die "could not create a default VPC"
SG=$(aws ec2 create-security-group --group-name "lab-open-ssh-$(openssl rand -hex 2)" \
  --description "project1 deliberate finding" --vpc-id "$VPC" \
  --profile "$PROFILE" --region "$REGION" --query GroupId --output text)
aws ec2 authorize-security-group-ingress --group-id "$SG" --protocol tcp --port 22 \
  --cidr 0.0.0.0/0 --profile "$PROFILE" --region "$REGION" >/dev/null

echo "==> IAM user with a standing key and s3:*"
USER="lab-legacy-user"
aws iam create-user --user-name "$USER" --profile "$PROFILE" >/dev/null 2>&1 || true
aws iam put-user-policy --user-name "$USER" --policy-name lab-s3-wildcard --profile "$PROFILE" \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}'
KEY_JSON=$(aws iam create-access-key --user-name "$USER" --profile "$PROFILE")
KEY_ID=$(echo "$KEY_JSON" | jq -r '.AccessKey.AccessKeyId')

echo "==> EC2 instance with IMDSv1 allowed"
AMI=$(aws ssm get-parameter --profile "$PROFILE" --region "$REGION" \
  --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 \
  --query 'Parameter.Value' --output text)
INSTANCE=$(aws ec2 run-instances --image-id "$AMI" --instance-type t3.micro \
  --security-group-ids "$SG" --profile "$PROFILE" --region "$REGION" \
  --metadata-options HttpTokens=optional,HttpEndpoint=enabled \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=posture-lab}]' \
  --query 'Instances[0].InstanceId' --output text)

cat > "$ENV_FILE" <<EOF
# generated $(date -u +%FT%TZ) - do not commit
export LAB_PROFILE=$PROFILE
export LAB_REGION=$REGION
export LAB_ACCOUNT=$ACCT
export LAB_BUCKET=$BUCKET
export LAB_SG=$SG
export LAB_USER=$USER
export LAB_KEY_ID=$KEY_ID
export LAB_INSTANCE=$INSTANCE
EOF
chmod 600 "$ENV_FILE"

cat <<EOF
Baseline deployed. IDs saved to .lab-env (mode 600, gitignored).

Do not paste the secret access key into any file tracked by git.
Capture the before state next:
  bash scripts/01-prowler.sh before
EOF
