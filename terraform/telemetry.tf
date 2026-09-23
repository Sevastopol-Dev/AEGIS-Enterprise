#Phase 2: Immutable Audit & Telemetry Engine

# 1. KMS Encryption Key for Audit Storage
resource "aws_kms_key" "audit_kms" {
  description             = "KMS Key for Aegis Immutable Audit Logs"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = { Name = "aegis-audit-kms" }
}

# 2. Immutable S3 WORM Bucket
resource "aws_s3_bucket" "audit_bucket" {
  bucket              = "aegis-v4-immutable-audit-ledger-${var.aws_region}"
  force_destroy       = false
  object_lock_enabled = true
}

resource "aws_s3_bucket_versioning" "audit_versioning" {
  bucket = aws_s3_bucket.audit_bucket.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "audit_worm" {
  bucket = aws_s3_bucket.audit_bucket.id

  rule {
    default_retention {
      mode = "COMPLIANCE" # Cannot be overridden or deleted by any user
      days = 90
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_enc" {
  bucket = aws_s3_bucket.audit_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.audit_kms.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

# Block all public access at bucket level
resource "aws_s3_bucket_public_access_block" "audit_block_public" {
  bucket                  = aws_s3_bucket.audit_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# CloudTrail Resources commented out to avoid deployment errors against LocalStack (Free Tier)

# 3. AWS CloudTrail for Organization-Wide API Capture
#resource "aws_cloudtrail" "aegis_trail" {
#name                          = "aegis-v4-event-trail"
#s3_bucket_name                = aws_s3_bucket.audit_bucket.id
#kms_key_id                    = aws_kms_key.audit_kms.arn
#include_global_service_events = true
#is_multi_region_trail         = true
#enable_logging                = true

#depends_on = [aws_s3_bucket_policy.allow_cloudtrail_logging]
#}

#resource "aws_s3_bucket_policy" "allow_cloudtrail_logging" {
#bucket = aws_s3_bucket.audit_bucket.id
#policy = jsonencode({
#Version = "2012-10-17"
#Statement = [
#{
#Sid       = "AWSCloudTrailAclCheck"
#Effect    = "Allow"
#Principal = { Service = "cloudtrail.amazonaws.com" }
#Action    = "s3:GetBucketAcl"
# Resource  = aws_s3_bucket.audit_bucket.arn
#},
#{
#Sid       = "AWSCloudTrailWrite"
#Effect    = "Allow"
#Principal = { Service = "cloudtrail.amazonaws.com" }
#Action    = "s3:PutObject"
#Resource  = "${aws_s3_bucket.audit_bucket.arn}/AWSLogs/*"
#Condition = {
# StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
# }
# }
#]
#})
#}
