import os
import time
import json
import logging
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

iam_client = boto3.client('iam')
dynamodb_client = boto3.client('dynamodb')

DYNAMODB_TABLE = os.environ.get('DYNAMODB_TABLE', 'aegis-v4-circuit-breaker-state')

PROTECTED_IDENTITIES = {
    "aegis-production-ecs-task-role",
    "AWSServiceRoleForECS",
    "AWSReservedSSO_AdministratorAccess",
    "aegis-immune-worker-execution-role"
}

MAX_REMEDIATIONS_PER_MINUTE = 5

def check_circuit_breaker() -> bool:
    """DynamoDB Leaky Bucket Rate Limiter."""
    current_minute = str(int(time.time() // 60))
    metric_key = f"RATE_LIMIT#{current_minute}"
    ttl_timestamp = int(time.time()) + 300

    try:
        response = dynamodb_client.update_item(
            TableName=DYNAMODB_TABLE,
            Key={'MetricName': {'S': metric_key}},
            UpdateExpression="ADD ExecutionCount :inc SET #ttl = if_not_exists(#ttl, :ttl)",
            ExpressionAttributeNames={'#ttl': 'ttl'},
            ExpressionAttributeValues={':inc': {'N': '1'}, ':ttl': {'N': str(ttl_timestamp)}},
            ReturnValues="UPDATED_NEW"
        )
        count = int(response['Attributes']['ExecutionCount']['N'])
        if count > MAX_REMEDIATIONS_PER_MINUTE:
            logger.critical("⛔ CIRCUIT BREAKER TRIPPED! Threshold exceeded. Switching to PASSIVE MODE.")
            return False
        return True
    except ClientError as e:
        logger.error(f"DynamoDB Circuit Breaker error: {str(e)}")
        return True  # Fail-open for safety

def lambda_handler(event, context):
    logger.info(f"Received Security Event: {event}")

    # Extract target IAM principal name
    detail = event.get('detail', {})
    user_identity = detail.get('userIdentity', {})
    user_name = user_identity.get('userName') or user_identity.get('principalId', 'UNKNOWN').split(':')[-1]

    logger.warning(f"🚨 HONEYTOKEN TRIPWIRE TRIGGERED BY: {user_name}")

    # Interlock 1: Protected Identity Check
    if user_name in PROTECTED_IDENTITIES:
        logger.critical(f"⛔ SAFETY INTERLOCK: Action aborted on PROTECTED identity '{user_name}'.")
        return {"status": "ABORTED", "reason": "Protected identity"}

    # Interlock 2: Rate Limit Check
    if not check_circuit_breaker():
        return {"status": "HALTED", "reason": "Circuit breaker rate limit exceeded"}

    # Attach Explicit Deny Quarantine Policy
    try:
        iam_client.put_user_policy(
            UserName=user_name,
            PolicyName="AegisQuarantinePolicy",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Sid": "AegisInstantQuarantine", "Effect": "Deny", "Action": "*", "Resource": "*"}]
            })
        )
        logger.info(f"✅ SUCCESSFULLY QUARANTINED: {user_name}")
        return {"status": "SUCCESS", "isolated_principal": user_name}

    except ClientError as e:
        logger.error(f"Failed to isolate principal {user_name}: {str(e)}")
        raise e
