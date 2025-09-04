# =============================================================================
# AWS Security Baseline Terraform Configuration
# =============================================================================
# This configuration sets up essential AWS security services for account 
# baseline security including CloudTrail, GuardDuty, Security Hub, Config,
# and IAM Access Analyzer.
#
# Resources are organized into separate files:
# - cloudtrail.tf     - CloudTrail logging configuration
# - guardduty.tf      - GuardDuty threat detection
# - security-hub.tf   - Security Hub centralized findings
# - config.tf         - AWS Config compliance monitoring
# - access-analyzer.tf - IAM Access Analyzer
# - variables.tf      - Input variables
# - outputs.tf        - Output values
# - versions.tf       - Terraform and provider versions

# =============================================================================
# PROVIDER CONFIGURATION
# =============================================================================

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "Terraform"
      Purpose     = "Security Baseline"
    }
  }
}

# =============================================================================
# DATA SOURCES
# =============================================================================

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

# =============================================================================
# LOCAL VALUES
# =============================================================================

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.name

  # Common resource naming
  cloudtrail_bucket_name = "${var.project_name}-cloudtrail-logs-${local.account_id}"
  config_bucket_name     = "${var.project_name}-config-logs-${local.account_id}"

  # Common tags
  common_tags = {
    Name        = var.project_name
    Environment = var.environment
    Purpose     = "Security Baseline"
  }

  # ARN patterns
  cloudtrail_arn = "arn:${local.partition}:cloudtrail:${var.aws_region}:${local.account_id}:trail/${var.project_name}-trail"
}
