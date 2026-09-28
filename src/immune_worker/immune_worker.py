import os, time, json, logging, boto3
from datetime import datetime, timezone
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

iam, dynamodb = boto3.client('iam'), boto3.client('dynamodb')
DYNAMODB_TABLE = os.environ.get('DYNAMODB_TABLE', 'aegis-v4-circuit-breaker-state')

PROTECTED = {
    "aegis-production-ecs-task-role", "AWSServiceRoleForECS",
    "AWSReservedSSO_AdministratorAccess", "aegis-immune-worker-execution-role"
}

def check_circuit_breaker() -> bool:
    metric_key = f"RATE_LIMIT#{int(time.time() // 60)}"
    try:
        res = dynamodb.update_item(
            TableName=DYNAMODB_TABLE,
            Key={'MetricName': {'S': metric_key}},
            UpdateExpression="ADD ExecutionCount :inc SET #ttl = if_not_exists(#ttl, :ttl)",
            ExpressionAttributeNames={'#ttl': 'ttl'},
            ExpressionAttributeValues={':inc': {'N': '1'}, ':ttl': {'N': str(int(time.time()) + 300)}},
            ReturnValues="UPDATED_NEW"
        )
        if int(res['Attributes']['ExecutionCount']['N']) > 5:
            logger.critical("⛔ CIRCUIT BREAKER TRIPPED!")
            return False
        return True
    except ClientError as e:
        logger.error(f"DynamoDB error: {e}")
        return True

def lambda_handler(event, context):
    logger.info(f"Event: {event}")
    identity = event.get('detail', {}).get('userIdentity', {})
    is_role = identity.get('type') == "AssumedRole"
    
    # Extract principal name
    arn = identity.get('arn', '')
    if is_role and 'assumed-role' in arn:
        name = arn.split('/')[-2]
    else:
        name = identity.get('userName') or identity.get('principalId', 'UNKNOWN').split(':')[-1]

    if name in PROTECTED:
        logger.critical(f"⛔ SAFETY INTERLOCK: Protected identity '{name}'")
        return {"status": "ABORTED", "reason": "Protected identity"}

    if not check_circuit_breaker():
        return {"status": "HALTED", "reason": "Circuit breaker limit reached"}

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    # Policy document (includes session revocation if it's a role)
    statements = [{"Sid": "AegisDeny", "Effect": "Deny", "Action": "*", "Resource": "*"}]
    if is_role:
        statements.append({
            "Sid": "AegisRevokeSTS", "Effect": "Deny", "Action": "*", "Resource": "*",
            "Condition": {"DateLessThan": {"aws:TokenIssueTime": now}}
        })
    
    policy_doc = json.dumps({"Version": "2012-10-17", "Statement": statements})

    try:
        if is_role:
            iam.put_role_policy(RoleName=name, PolicyName="AegisQuarantinePolicy", PolicyDocument=policy_doc)
        else:
            iam.put_user_policy(UserName=name, PolicyName="AegisQuarantinePolicy", PolicyDocument=policy_doc)
            
        logger.info(f"✅ QUARANTINED: {name} (Role: {is_role})")
        return {"status": "SUCCESS", "isolated": name}
    except ClientError as e:
        logger.error(f"Failed to isolate {name}: {e}")
        raise e
