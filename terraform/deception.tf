#Phase 3: Serverless Deception Labyrinth

# 1. Planted Honeytoken IAM Identity
resource "aws_iam_user" "decoy_service_account" {
  name = "bank-core-ledger-svc-admin"
  tags = {
    Environment = "production"
    Decoy       = "true"
    Purpose     = "Aegis Honeytoken Tripwire"
  }
}

# Note: Explicitly NO IAM Policies attached to this user!
# Any attempt to use this key results in implicit deny AND triggers auto-remediation.

resource "aws_iam_access_key" "honeytoken_key" {
  user = aws_iam_user.decoy_service_account.name
}

# 2. Planted Decoy S3 Bucket Target
#tfsec:ignore:AWS-0132 
resource "aws_s3_bucket" "decoy_bucket" {
  bucket        = "corp-customer-ssn-ledger-backup-prod"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "decoy_bucket_pab" {
  bucket = aws_s3_bucket.decoy_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Output the Honeytoken Key ID so we can bind it to EventBridge
output "honeytoken_access_key_id" {
  value     = aws_iam_access_key.honeytoken_key.id
  sensitive = false
}

output "honeytoken_user_name" {
  description = "Name of the planted decoy IAM identity."
  value       = aws_iam_user.decoy_service_account.name
}
