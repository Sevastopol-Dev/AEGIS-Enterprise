#Phase 4: Event-Driven Immune Engine

# 1. DynamoDB Table for Circuit Breaker Rate-Limiting
resource "aws_dynamodb_table" "circuit_breaker" {
  name         = "aegis-v4-circuit-breaker-state"
  billing_mode = "PAY_PER_REQUEST" # Cost-optimized: $0 idle cost
  hash_key     = "MetricName"

  attribute {
    name = "MetricName"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = { Name = "aegis-circuit-breaker" }
}

# 2. IAM Role for Immune Lambda Worker
resource "aws_iam_role" "lambda_immune_role" {
  name = "aegis-immune-worker-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_policy" "lambda_immune_policy" {
  name        = "aegis-immune-worker-permissions"
  description = "Allows Lambda to apply inline deny policies and revoke STS sessions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "iam:PutUserPolicy",
          "iam:PutRolePolicy",
          "iam:AttachUserPolicy",
          "iam:AttachRolePolicy"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
          "dynamodb:PutItem"
        ]
        Resource = aws_dynamodb_table.circuit_breaker.arn
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_immune_attach" {
  role       = aws_iam_role.lambda_immune_role.name
  policy_arn = aws_iam_policy.lambda_immune_policy.arn
}

# 3. Immune Lambda Worker Function
resource "aws_lambda_function" "immune_worker" {
  filename      = "immune_worker.zip"
  function_name = "aegis-v4-immune-worker"
  role          = aws_iam_role.lambda_immune_role.arn
  handler       = "immune_worker.lambda_handler"
  runtime       = "python3.11"
  timeout       = 10

  environment {
    variables = {
      DYNAMODB_TABLE = aws_dynamodb_table.circuit_breaker.name
    }
  }
}

# 4. EventBridge Rule Listening for Honeytoken Access Key Trigger
resource "aws_cloudwatch_event_rule" "honeytoken_tripwire" {
  name        = "aegis-honeytoken-triggered"
  description = "Fires when API call attempts to use planted Aegis honeytoken"

  event_pattern = jsonencode({
    detail = {
      userIdentity = {
        accessKeyId = [aws_iam_access_key.honeytoken_key.id]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "trigger_lambda" {
  rule      = aws_cloudwatch_event_rule.honeytoken_tripwire.name
  target_id = "TriggerAegisImmuneLambda"
  arn       = aws_lambda_function.immune_worker.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.immune_worker.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.honeytoken_tripwire.arn
}
