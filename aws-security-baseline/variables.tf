# =============================================================================
# VARIABLES
# =============================================================================

variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.aws_region))
    error_message = "AWS region must be a valid region name."
  }
}

variable "environment" {
  description = "Environment name (e.g., dev, staging, prod)"
  type        = string
  default     = "security-baseline"

  validation {
    condition     = length(var.environment) > 0 && length(var.environment) <= 20
    error_message = "Environment name must be between 1 and 20 characters."
  }
}

variable "project_name" {
  description = "Project name for resource naming and tagging"
  type        = string
  default     = "aws-security-baseline"

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.project_name))
    error_message = "Project name must contain only lowercase letters, numbers, and hyphens."
  }
}

variable "cloudtrail_log_retention_days" {
  description = "Number of days to retain CloudTrail logs in S3"
  type        = number
  default     = 90

  validation {
    condition     = var.cloudtrail_log_retention_days >= 30
    error_message = "CloudTrail log retention must be at least 30 days."
  }
}

variable "config_log_retention_days" {
  description = "Number of days to retain Config logs in S3"
  type        = number
  default     = 90

  validation {
    condition     = var.config_log_retention_days >= 30
    error_message = "Config log retention must be at least 30 days."
  }
}

variable "guardduty_finding_publishing_frequency" {
  description = "Frequency of GuardDuty finding publishing"
  type        = string
  default     = "FIFTEEN_MINUTES"

  validation {
    condition = contains([
      "FIFTEEN_MINUTES",
      "ONE_HOUR",
      "SIX_HOURS"
    ], var.guardduty_finding_publishing_frequency)
    error_message = "GuardDuty finding publishing frequency must be FIFTEEN_MINUTES, ONE_HOUR, or SIX_HOURS."
  }
}
