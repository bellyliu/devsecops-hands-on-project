# =============================================================================
# CLOUDTRAIL LOGGING
# =============================================================================

# S3 bucket for CloudTrail logs
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket        = local.cloudtrail_bucket_name
  force_destroy = true

  tags = merge(local.common_tags, {
    Name    = "${var.project_name}-cloudtrail-logs"
    Purpose = "CloudTrail logging"
  })
}

# CloudTrail S3 bucket configuration
resource "aws_s3_bucket_versioning" "cloudtrail_logs_versioning" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs_encryption" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_logs_pab" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail_logs_lifecycle" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    id     = "cloudtrail_log_retention"
    status = "Enabled"

    expiration {
      days = var.cloudtrail_log_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

# CloudTrail S3 bucket policy
resource "aws_s3_bucket_policy" "cloudtrail_logs_policy" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail_logs.arn
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = local.cloudtrail_arn
          }
        }
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control"
            "AWS:SourceArn" = local.cloudtrail_arn
          }
        }
      }
    ]
  })
}

# CloudTrail configuration
resource "aws_cloudtrail" "main_trail" {
  depends_on = [aws_s3_bucket_policy.cloudtrail_logs_policy]

  name           = "${var.project_name}-trail"
  s3_bucket_name = aws_s3_bucket.cloudtrail_logs.bucket

  # Event selectors for comprehensive logging
  event_selector {
    read_write_type                  = "All"
    include_management_events        = true
    exclude_management_event_sources = []

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::*/*"]
    }
  }

  # Insights for unusual activity patterns
  insight_selector {
    insight_type = "ApiCallRateInsight"
  }

  enable_logging                = true
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  tags = merge(local.common_tags, {
    Name    = "${var.project_name}-trail"
    Purpose = "Multi-region CloudTrail logging"
  })
}
