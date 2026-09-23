import os
import time
import logging
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

iam_client = boto3.client('iam')
dynamodb_client = boto3.client('dynamodb')

DYNAMODB_TABLE = os.environ.get('DYNAMODB_TABLE', 'aegis-v4-circuit-breaker-state')

# SAFETY INTERLOCK 1: Protected Identities Denylist
PROTECTED_IDENTITIES = {
    "aegis-production-ecs-task-role",
    "AWSServiceRoleForECS",
    "AWSReservedSSO_AdministratorAccess",
    "aegis-immune-worker-execution-role"
}

MAX_REMEDIATIONS_PER_MINUTE = 5

def check_and_increment_circuit_breaker() -> bool:
    """
    SAFETY INTERLOCK 2: DynamoDB Leaky Bucket Rate Limiter.
    Returns True if execution is permitted, False if Circuit Breaker TRIPPED.
    """
    current_minute = str(int(time.time() // 60))
    metric_key = f"RATE_LIMIT#{current_minute}"
    ttl_timestamp = int(time.time()) + 300  # Expire after 5 minutes

    try:
        response = dynamodb_client.update_item(
            TableName=DYNAMODB_TABLE,
            Key={'MetricName': {'S': metric_key}},
            UpdateExpression="ADD ExecutionCount :inc SET #ttl = :ttl",
            ExpressionAttributeNames={'#ttl': 'ttl'},
            ExpressionAttributeValues={
                ':inc': {'N': '1'},
                ':ttl': {'N': str(ttl_timestamp)}
            },
            ReturnValues="UPDATED_NEW"
        )
        count = int(response['Attributes']['ExecutionCount']['N'])
        logger.info(f"Circuit Breaker Count for minute {current_minute}: {count}")

        if count > MAX_REMEDIATIONS_PER_MINUTE:
            logger.critical("⛔ CIRCUIT BREAKER TRIPPED! Rate threshold exceeded. Switching to PASSIVE ALERT MODE.")
            return False
        return True

    except ClientError as e:
        logger.error(f"DynamoDB Circuit Breaker error: {str(e)}")
        # Fail safe: allow execution if DynamoDB check fails, but log error
        return True

def lambda_handler(event, context):
    logger.info(f"Received Security Event Payload: {event}")

    # Extract Identity Context from EventBridge Detail
    detail = event.get('detail', {})
    user_identity = detail.get('userIdentity', {})
    principal_id = user_identity.get('principalId', 'UNKNOWN')
    user_name = user_identity.get('userName', principal_id.split(':')[-1])

    logger.warning(f"🚨 HONEYTOKEN TRIPWIRE TRIGGERED BY PRINCIPAL: {user_name}")

    # Safety Interlock 1 Check
    if user_name in PROTECTED_IDENTITIES:
        logger.critical(f"⛔ SAFETY INTERLOCK TRIGGERED: Attempted action on PROTECTED identity '{user_name}'. Action Aborted.")
        return {"status": "ABORTED", "reason": "Protected identity"}

    # Safety Interlock 2 Check
    if not check_and_increment_circuit_breaker():
        return {"status": "HALTED", "reason": "Circuit breaker rate limit exceeded"}

    # Execute Instant Identity Containment
    try:
        deny_policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AegisInstantQuarantine",
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*"
                }
            ]
        }

        # Apply Explicit Deny Inline Policy to User
        iam_client.put_user_policy(
            UserName=user_name,
            PolicyName="AegisQuarantinePolicy",
            PolicyDocument=str(deny_policy_document).replace("'", '"')
        )

        logger.info(f"✅ SUCCESSFULLY ATTACHED EXPLICIT DENY (*) POLICY TO: {user_name}")
        return {"status": "SUCCESS", "isolated_principal": user_name}

    except ClientError as e:
        logger.error(f"Failed to isolate principal {user_name}: {str(e)}")
        raise e
