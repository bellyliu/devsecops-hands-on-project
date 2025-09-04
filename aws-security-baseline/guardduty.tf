# =============================================================================
# AMAZON GUARDDUTY - THREAT DETECTION
# =============================================================================

# GuardDuty detector
resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = var.guardduty_finding_publishing_frequency

  tags = merge(local.common_tags, {
    Name    = "${var.project_name}-guardduty"
    Purpose = "Threat detection"
  })
}

# GuardDuty feature configurations
resource "aws_guardduty_detector_feature" "s3_protection" {
  detector_id = aws_guardduty_detector.main.id
  name        = "S3_DATA_EVENTS"
  status      = "ENABLED"
}

resource "aws_guardduty_detector_feature" "kubernetes_protection" {
  detector_id = aws_guardduty_detector.main.id
  name        = "EKS_AUDIT_LOGS"
  status      = "ENABLED"
}

resource "aws_guardduty_detector_feature" "malware_protection" {
  detector_id = aws_guardduty_detector.main.id
  name        = "EBS_MALWARE_PROTECTION"
  status      = "ENABLED"
}
