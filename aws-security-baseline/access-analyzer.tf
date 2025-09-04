# =============================================================================
# IAM ACCESS ANALYZER - ACCESS PATTERN ANALYSIS
# =============================================================================

# IAM Access Analyzer
resource "aws_accessanalyzer_analyzer" "main" {
  analyzer_name = "${var.project_name}-access-analyzer"
  type          = "ACCOUNT"

  tags = merge(local.common_tags, {
    Name    = "${var.project_name}-access-analyzer"
    Purpose = "Monitor for unintended resource access"
  })
}
