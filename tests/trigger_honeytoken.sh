#!/usr/bin/env bash
set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"
TERRAFORM_DIR="$PROJECT_ROOT/terraform"

echo "=== Aegis v4 Local Verification Test ==="

# 1. Extract Honeytoken details from Terraform Output
HONEY_KEY_ID=$(tflocal -chdir="$TERRAFORM_DIR" output -raw honeytoken_access_key_id 2>/dev/null || true)
HONEY_USER=$(tflocal -chdir="$TERRAFORM_DIR" output -raw honeytoken_user_name 2>/dev/null || true)

if [ -z "$HONEY_KEY_ID" ] || [ -z "$HONEY_USER" ]; then
  echo "Error: Could not retrieve honeytoken details from Terraform output."
  exit 1
fi

echo "[1/3] Planted Honeytoken User: $HONEY_USER"
echo "[1/3] Planted Honeytoken Access Key: $HONEY_KEY_ID"
echo "[2/3] Publishing Honeytoken breach event to EventBridge..."

# Build JSON payload cleanly
EVENT_DETAIL=$(cat <<EOF
{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "IAMUser",
    "userName": "$HONEY_USER",
    "accessKeyId": "$HONEY_KEY_ID"
  },
  "eventSource": "s3.amazonaws.com",
  "eventName": "ListBuckets",
  "sourceIPAddress": "192.0.2.1"
}
EOF
)

# Escape JSON for put-events string parameter
ESCAPED_DETAIL=$(echo "$EVENT_DETAIL" | jq -c . | sed 's/"/\\"/g')

awslocal events put-events --entries "[
  {
    \"Source\": \"aws.s3\",
    \"DetailType\": \"AWS API Call via CloudTrail\",
    \"Detail\": \"$ESCAPED_DETAIL\"
  }
]" --endpoint-url=http://localhost:4566 > /dev/null

echo "[3/3] Waiting for Immune Worker Lambda execution..."

# Polling loop: Wait up to 10 seconds for Lambda to execute and attach quarantine policy
ATTEMPTS=0
MAX_ATTEMPTS=5
SUCCESS=0

while [ $ATTEMPTS -lt $MAX_ATTEMPTS ]; do
  sleep 2
  ATTEMPTS=$((ATTEMPTS+1))

  QUARANTINE_POLICY=$(awslocal iam get-user-policy \
    --user-name "$HONEY_USER" \
    --policy-name AegisQuarantinePolicy \
    --endpoint-url=http://localhost:4566 2>/dev/null || echo "NOT_FOUND")

  if [[ "$QUARANTINE_POLICY" == *"AegisInstantQuarantine"* ]] || [[ "$QUARANTINE_POLICY" == *"Deny"* ]]; then
    SUCCESS=1
    break
  fi
  echo "   Attempt $ATTEMPTS/$MAX_ATTEMPTS: Policy not attached yet, retrying..."
done

if [ $SUCCESS -eq 1 ]; then
  echo ""
  echo "==========================================================="
  echo "  SUCCESS: Aegis v4 Auto-Remediation Loop Executed!"
  echo "  Quarantine Policy (Explicit Deny) attached to $HONEY_USER."
  echo "==========================================================="
  exit 0
else
  echo ""
  echo "FAILURE: AegisQuarantinePolicy not found on '$HONEY_USER' after retries."
  echo "Checking Lambda logs..."
  awslocal logs tail /aws/lambda/aegis-v4-immune-worker --endpoint-url=http://localhost:4566 || true
  exit 1
fi
