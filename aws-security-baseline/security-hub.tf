# =============================================================================
# AWS SECURITY HUB - CENTRALIZED SECURITY FINDINGS
# =============================================================================

# Security Hub account configuration
resource "aws_securityhub_account" "main" {
  enable_default_standards  = true
  control_finding_generator = "SECURITY_CONTROL"
}

# Enable AWS Foundational Security Best Practices standard
resource "aws_securityhub_standards_subscription" "aws_foundational" {
  standards_arn = "arn:${local.partition}:securityhub:::ruleset/finding-format/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.main]
}
