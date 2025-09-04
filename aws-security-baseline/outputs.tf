# =============================================================================
# OUTPUTS
# =============================================================================

# CloudTrail outputs
output "cloudtrail_arn" {
  description = "ARN of the CloudTrail trail"
  value       = aws_cloudtrail.main_trail.arn
}

output "cloudtrail_s3_bucket" {
  description = "S3 bucket name used by CloudTrail for log storage"
  value       = aws_s3_bucket.cloudtrail_logs.bucket
}

# GuardDuty outputs
output "guardduty_detector_id" {
  description = "GuardDuty detector ID"
  value       = aws_guardduty_detector.main.id
}

# Security Hub outputs
output "security_hub_arn" {
  description = "Security Hub account ARN"
  value       = aws_securityhub_account.main.arn
}

# AWS Config outputs
output "config_recorder_name" {
  description = "AWS Config configuration recorder name"
  value       = aws_config_configuration_recorder.main.name
}

output "config_s3_bucket" {
  description = "S3 bucket name used by AWS Config for log storage"
  value       = aws_s3_bucket.config_logs.bucket
}

# IAM Access Analyzer outputs
output "access_analyzer_arn" {
  description = "IAM Access Analyzer ARN"
  value       = aws_accessanalyzer_analyzer.main.arn
}

# Summary outputs
output "deployment_summary" {
  description = "Summary of deployed security services"
  value = {
    project_name = var.project_name
    environment  = var.environment
    region       = var.aws_region
    account_id   = local.account_id
    services = {
      cloudtrail      = "enabled"
      guardduty       = "enabled"
      security_hub    = "enabled"
      config          = "enabled"
      access_analyzer = "enabled"
    }
  }
}
