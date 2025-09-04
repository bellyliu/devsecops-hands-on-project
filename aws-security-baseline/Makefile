# AWS Security Baseline Makefile
# Provides convenient commands for managing the modular security baseline

.PHONY: help init plan apply verify destroy clean install-deps validate fmt

# Default target
help:
	@echo "AWS Security Baseline Management"
	@echo "================================"
	@echo ""
	@echo "Project Structure:"
	@echo "  📁 cloudtrail.tf      - CloudTrail logging configuration"
	@echo "  📁 guardduty.tf       - GuardDuty threat detection"
	@echo "  📁 security-hub.tf    - Security Hub centralized findings"
	@echo "  📁 config.tf          - AWS Config compliance monitoring"
	@echo "  📁 access-analyzer.tf - IAM Access Analyzer"
	@echo ""
	@echo "Available commands:"
	@echo "  install-deps  Install Python dependencies"
	@echo "  validate      Validate Terraform configuration"
	@echo "  fmt           Format Terraform files"
	@echo "  init          Initialize Terraform"
	@echo "  plan          Plan Terraform changes"
	@echo "  apply         Apply Terraform configuration"
	@echo "  verify        Verify security services are enabled"
	@echo "  destroy       Destroy all resources"
	@echo "  clean         Clean Terraform files"
	@echo ""

# Install Python dependencies
install-deps:
	@echo "Installing Python dependencies..."
	pip install -r requirements.txt

# Validate Terraform configuration
validate:
	@echo "Validating Terraform configuration..."
	terraform validate

# Format Terraform files
fmt:
	@echo "Formatting Terraform files..."
	terraform fmt -recursive

# Initialize Terraform
init:
	@echo "Initializing Terraform..."
	terraform init

# Plan Terraform changes
plan:
	@echo "Planning Terraform changes..."
	terraform plan

# Apply Terraform configuration
apply:
	@echo "Applying Terraform configuration..."
	terraform apply

# Verify security services
verify:
	@echo "Verifying security baseline..."
	python verify_baseline.py

# Destroy all resources
destroy:
	@echo "Destroying all resources..."
	terraform destroy

# Clean Terraform files
clean:
	@echo "Cleaning Terraform files..."
	rm -rf .terraform/
	rm -f .terraform.lock.hcl
	rm -f terraform.tfstate*
	rm -f terraform.tfplan
