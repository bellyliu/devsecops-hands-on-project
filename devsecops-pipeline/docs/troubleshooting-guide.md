# Security Tools Troubleshooting and Issue Resolution Guide

## 🚨 Common Pipeline Failures and Solutions

This guide provides practical examples of how to identify, understand, and fix security issues detected by our DevSecOps pipeline tools. Each section includes real-world scenarios with step-by-step resolution instructions.

## 📋 Table of Contents

1. [SonarQube SAST Issues](#sonarqube-sast-issues)
2. [Snyk SCA Vulnerabilities](#snyk-sca-vulnerabilities)
3. [Trivy Container Vulnerabilities](#trivy-container-vulnerabilities)
4. [Hadolint Dockerfile Issues](#hadolint-dockerfile-issues)
5. [Pipeline Integration Problems](#pipeline-integration-problems)
6. [Emergency Response Procedures](#emergency-response-procedures)

---

## 🔍 SonarQube SAST Issues

### Scenario 1: SQL Injection Vulnerability

**Pipeline Failure Output:**

```
Quality Gate Status: FAILED
Security Issues: 1 Vulnerability, 2 Security Hotspots

┌──────────────────────────────────────────────────────────────┐
│ Critical Security Vulnerability Found                        │
├──────────────────────────────────────────────────────────────┤
│ File: app.py                                                │
│ Line: 45                                                     │
│ Rule: python:S3649                                          │
│ Type: SQL Injection                                         │
│ Severity: CRITICAL                                          │
│ Message: Make sure this query is safe from SQL injection.   │
└──────────────────────────────────────────────────────────────┘
```

**Vulnerable Code:**

```python
# app.py - Line 45
from flask import Flask, request
import sqlite3

@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # ❌ VULNERABLE: Direct string concatenation
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    result = cursor.fetchone()

    conn.close()
    return result
```

**Step-by-Step Fix:**

1. **Identify the Issue**: The code directly concatenates user input into SQL query
2. **Security Risk**: Allows arbitrary SQL execution
3. **Attack Vector**: `GET /user?id=1; DROP TABLE users; --`

**Fixed Code:**

```python
# app.py - Line 45
from flask import Flask, request
import sqlite3

@app.route('/user')
def get_user():
    user_id = request.args.get('id')

    # Input validation
    if not user_id or not user_id.isdigit():
        return {"error": "Invalid user ID"}, 400

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # ✅ FIXED: Using parameterized query
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    result = cursor.fetchone()

    conn.close()
    return result
```

**Verification:**

```bash
# Re-run SonarQube scan
sonar-scanner -Dsonar.projectKey=my-project

# Expected output:
# Quality Gate Status: PASSED
# Security Rating: A (0 vulnerabilities)
```

---

### Scenario 2: Hard-coded Credentials

**Pipeline Failure Output:**

```
Quality Gate Status: FAILED
Security Hotspots: 3 items require review

┌──────────────────────────────────────────────────────────────┐
│ Security Hotspot: Hard-coded Credentials                     │
├──────────────────────────────────────────────────────────────┤
│ File: config.py                                             │
│ Line: 8, 12, 15                                             │
│ Rule: python:S2068                                          │
│ Type: Authentication                                         │
│ Severity: CRITICAL                                          │
│ Message: Remove this hard-coded password.                   │
└──────────────────────────────────────────────────────────────┘
```

**Vulnerable Code:**

```python
# config.py
class Config:
    # ❌ VULNERABLE: Hard-coded credentials
    DATABASE_URL = "postgresql://admin:secretpass123@localhost/mydb"
    SECRET_KEY = "my-super-secret-key-12345"
    API_TOKEN = "sk-1234567890abcdef1234567890abcdef"

    # ❌ VULNERABLE: Hard-coded in function
    def get_db_connection(self):
        return connect(
            host="localhost",
            user="admin",
            password="admin123"  # Hard-coded password
        )
```

**Step-by-Step Fix:**

1. **Create Environment Variables File**:

```bash
# Create .env file (DO NOT commit to git)
cat > .env << EOF
DATABASE_URL=postgresql://admin:secretpass123@localhost/mydb
SECRET_KEY=my-super-secret-key-12345
API_TOKEN=sk-1234567890abcdef1234567890abcdef
DB_HOST=localhost
DB_USER=admin
DB_PASSWORD=admin123
EOF
```

2. **Update .gitignore**:

```bash
# Add to .gitignore
echo ".env" >> .gitignore
echo "*.env" >> .gitignore
```

3. **Fix Configuration Code**:

```python
# config.py
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class Config:
    # ✅ FIXED: Using environment variables
    DATABASE_URL = os.getenv('DATABASE_URL')
    SECRET_KEY = os.getenv('SECRET_KEY')
    API_TOKEN = os.getenv('API_TOKEN')

    # ✅ FIXED: Environment-based connection
    def get_db_connection(self):
        return connect(
            host=os.getenv('DB_HOST'),
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASSWORD')
        )

    # Validation
    @classmethod
    def validate_config(cls):
        required_vars = ['DATABASE_URL', 'SECRET_KEY', 'API_TOKEN']
        missing = [var for var in required_vars if not os.getenv(var)]
        if missing:
            raise ValueError(f"Missing required environment variables: {missing}")
```

4. **Update Requirements**:

```txt
# requirements.txt
python-dotenv>=1.0.0
```

**Verification:**

```bash
# Test locally
python -c "from config import Config; Config.validate_config(); print('Config OK')"

# Re-run SonarQube scan
sonar-scanner -Dsonar.projectKey=my-project
```

---

## 📦 Snyk SCA Vulnerabilities

### Scenario 1: Critical Dependency Vulnerability

**Pipeline Failure Output:**

```
Testing /home/runner/work/repo/requirements.txt...

✗ Critical severity vulnerability found in urllib3
  Path: urllib3@1.24.1
  Info: CRLF injection via HTTP request method parameter
  CVE: CVE-2020-26137
  CVSS Score: 9.8
  From: urllib3@1.24.1

✗ High severity vulnerability found in requests
  Path: requests@2.20.0
  Info: Redirect following without authentication header removal
  CVE: CVE-2018-18074
  CVSS Score: 7.5
  From: requests@2.20.0

Organization: my-org
Package manager: pip
Target file: requirements.txt
Open source: no
Project path: /home/runner/work/repo

Tested 25 dependencies for known issues, found 2 issues, 2 vulnerable paths.

Build failed due to vulnerabilities above severity threshold (high)
```

**Vulnerable Dependencies:**

```txt
# requirements.txt
Flask==1.1.0
requests==2.20.0
urllib3==1.24.1
Jinja2==2.10
```

**Step-by-Step Fix:**

1. **Check Available Updates**:

```bash
# Install Snyk CLI
npm install -g snyk

# Authenticate
snyk auth

# Check for available patches/updates
snyk test --file=requirements.txt --print-deps
```

2. **Research Vulnerabilities**:

```bash
# Get detailed vulnerability information
snyk test --json | jq '.vulnerabilities[] | {id, title, severity, cvssScore, upgradePath}'
```

3. **Update Dependencies**:

```txt
# requirements.txt - Updated with secure versions
Flask>=1.1.4              # Security patches included
requests>=2.25.1           # Fixes CVE-2018-18074
urllib3>=1.26.5            # Fixes CVE-2020-26137
Jinja2>=2.11.3             # Security updates
```

4. **Test Compatibility**:

```bash
# Create test environment
python -m venv test_env
source test_env/bin/activate

# Install updated dependencies
pip install -r requirements.txt

# Run application tests
python -m pytest tests/

# Run application locally
python app.py
```

5. **Verify Fix**:

```bash
# Re-run Snyk scan
snyk test --file=requirements.txt

# Expected output:
# ✓ Tested 25 dependencies for known issues, no vulnerable paths found.
```

---

### Scenario 2: License Compliance Issue

**Pipeline Failure Output:**

```
License Issues Found:

✗ GPL-3.0 license found in package 'some-gpl-package'
  Path: some-gpl-package@1.2.3
  License: GPL-3.0
  Severity: high

  GPL licenses may require you to open source your code
  Review your organization's license policy
```

**Step-by-Step Fix:**

1. **Check License Policy**:

```bash
# Review license compliance
snyk test --license --json > license-report.json

# Extract license information
jq '.licensesPolicy.orgLicenseRules' license-report.json
```

2. **Find Alternative Package**:

```bash
# Search for alternatives
pip search "alternative to some-gpl-package"

# Check PyPI for similar packages with compatible licenses
```

3. **Update Dependencies**:

```txt
# requirements.txt - Replace with MIT/Apache licensed alternative
# some-gpl-package==1.2.3  # GPL-3.0 - removed
mit-alternative-package>=2.1.0  # MIT license
```

4. **Create License Policy**:

```yaml
# .snyk
version: v1.0.0
license:
  ignore:
    "GPL-3.0":
      - "*":
          reason: "Alternative package found"
          expires: "2024-12-31T23:59:59.999Z"
```

---

## 🐳 Trivy Container Vulnerabilities

### Scenario 1: Critical Base Image Vulnerabilities

**Pipeline Failure Output:**

```
my-app:latest (alpine 3.14.2)
=============================
Total: 58 (UNKNOWN: 0, LOW: 12, MEDIUM: 18, HIGH: 20, CRITICAL: 8)

┌─────────────────┬────────────────┬──────────┬───────────────────┬───────────────┬────────────────────────────────────┐
│     Library     │ Vulnerability  │ Severity │ Installed Version │ Fixed Version │               Title                │
├─────────────────┼────────────────┼──────────┼───────────────────┼───────────────┼────────────────────────────────────┤
│ libssl1.1       │ CVE-2022-0778  │ CRITICAL │ 1.1.1k-r0         │ 1.1.1n-r0     │ Infinite loop in BN_mod_sqrt()     │
├─────────────────┼────────────────┼──────────┼───────────────────┼───────────────┼────────────────────────────────────┤
│ libcrypto1.1    │ CVE-2022-0778  │ CRITICAL │ 1.1.1k-r0         │ 1.1.1n-r0     │ OpenSSL infinite loop             │
├─────────────────┼────────────────┼──────────┼───────────────────┼───────────────┼────────────────────────────────────┤
│ musl            │ CVE-2020-28928 │ HIGH     │ 1.2.2-r3          │ 1.2.2-r7      │ Buffer overflow in musl           │
└─────────────────┴────────────────┴──────────┴───────────────────┴───────────────┴────────────────────────────────────┘

Build FAILED due to CRITICAL vulnerabilities in base image
```

**Current Dockerfile:**

```dockerfile
# Dockerfile with vulnerable base image
FROM alpine:3.14.2

WORKDIR /app

RUN apk add --no-cache python3 py3-pip
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app.py .
CMD ["python3", "app.py"]
```

**Step-by-Step Fix:**

1. **Check Base Image Vulnerabilities**:

```bash
# Scan current base image
trivy image alpine:3.14.2

# Check newer versions
trivy image alpine:3.17
trivy image alpine:3.18
trivy image alpine:latest
```

2. **Update Base Image**:

```dockerfile
# Dockerfile with updated base image
FROM alpine:3.18  # Latest stable with security patches

WORKDIR /app

# Update package index and install specific versions
RUN apk update && apk add --no-cache \
    python3=3.11.5-r0 \
    py3-pip=23.1.2-r0 \
    && rm -rf /var/cache/apk/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# Create non-root user for security
RUN adduser -D -s /bin/sh appuser
USER appuser

CMD ["python3", "app.py"]
```

3. **Use Distroless for Maximum Security**:

```dockerfile
# Multi-stage build with distroless final image
FROM python:3.11-alpine as builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Final stage with distroless
FROM gcr.io/distroless/python3-debian12
COPY --from=builder /root/.local /home/nonroot/.local
COPY app.py /app/

# Distroless images run as non-root by default
USER nonroot
WORKDIR /app
ENV PATH=/home/nonroot/.local/bin:$PATH

CMD ["python3", "app.py"]
```

4. **Verify Fix**:

```bash
# Build new image
docker build -t my-app:secure .

# Scan updated image
trivy image my-app:secure

# Expected output: Significantly reduced vulnerabilities
```

---

### Scenario 2: Python Package Vulnerabilities in Container

**Pipeline Failure Output:**

```
my-app:latest (python-pkg)
==========================
Total: 12 (UNKNOWN: 0, LOW: 2, MEDIUM: 3, HIGH: 5, CRITICAL: 2)

┌─────────────┬────────────────┬──────────┬───────────────────┬───────────────┬─────────────────────────────────────┐
│   Library   │ Vulnerability  │ Severity │ Installed Version │ Fixed Version │                Title                │
├─────────────┼────────────────┼──────────┼───────────────────┼───────────────┼─────────────────────────────────────┤
│ flask       │ CVE-2023-30861 │ CRITICAL │ 1.1.0             │ 2.3.2         │ Werkzeug vulnerable to XSS when    │
│             │                │          │                   │               │ path contains certain sequences     │
├─────────────┼────────────────┼──────────┼───────────────────┼───────────────┼─────────────────────────────────────┤
│ requests    │ CVE-2023-32681 │ HIGH     │ 2.25.0            │ 2.31.0        │ Requests vulnerable to unintended  │
│             │                │          │                   │               │ proxy usage                        │
└─────────────┴────────────────┴──────────┴───────────────────┴───────────────┴─────────────────────────────────────┘
```

**Step-by-Step Fix:**

1. **Update Requirements**:

```txt
# requirements.txt - Update to secure versions
Flask>=2.3.2        # Fixes CVE-2023-30861
requests>=2.31.0     # Fixes CVE-2023-32681
Werkzeug>=2.3.6      # Security dependency
```

2. **Update Dockerfile with Security Scanning**:

```dockerfile
FROM python:3.11-slim

# Install security updates
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Scan for vulnerabilities after installation
RUN pip list --format=json > /tmp/installed_packages.json

COPY app.py .

# Create non-root user
RUN adduser --disabled-password --gecos '' appuser
RUN chown -R appuser:appuser /app
USER appuser

HEALTHCHECK --interval=30s --timeout=3s \
    CMD curl -f http://localhost:5000/health || exit 1

CMD ["python", "app.py"]
```

3. **Add Vulnerability Scanning to Build Process**:

```bash
# build-and-scan.sh
#!/bin/bash

# Build image
docker build -t my-app:latest .

# Scan for vulnerabilities
echo "Scanning container for vulnerabilities..."
trivy image --severity HIGH,CRITICAL my-app:latest

# Check scan results
if [ $? -ne 0 ]; then
    echo "❌ Vulnerability scan failed"
    exit 1
fi

echo "✅ Container security scan passed"
```

---

## 📋 Hadolint Dockerfile Issues

### Scenario 1: Security and Best Practice Violations

**Pipeline Failure Output:**

```
Dockerfile:1 DL3006 warning: Always tag the version of an image explicitly
Dockerfile:8 DL3008 error: Pin versions in apt get install
Dockerfile:12 DL3002 error: Last USER should not be root
Dockerfile:15 DL3020 warning: Use COPY instead of ADD for files and folders
Dockerfile:18 DL3025 info: Use arguments JSON notation for CMD and ENTRYPOINT arguments

Build FAILED due to Dockerfile security violations
```

**Vulnerable Dockerfile:**

```dockerfile
# ❌ Issues: Untagged image, unpinned packages, root user, ADD usage
FROM python

WORKDIR /app

# ❌ No version pinning
RUN apt-get update && apt-get install -y curl vim

COPY requirements.txt .
RUN pip install -r requirements.txt

# ❌ Using ADD instead of COPY
ADD app.py .
ADD config/ ./config/

EXPOSE 5000

# ❌ Running as root, shell form CMD
CMD python app.py
```

**Step-by-Step Fix:**

1. **Fix Image Tagging**:

```dockerfile
# ✅ Use specific, secure tag
FROM python:3.11-slim
```

2. **Pin Package Versions**:

```dockerfile
# ✅ Pin specific versions and clean cache
RUN apt-get update && apt-get install -y \
    curl=7.88.1-10+deb12u4 \
    && rm -rf /var/lib/apt/lists/*
```

3. **Implement Proper User Management**:

```dockerfile
# ✅ Create and use non-root user
RUN adduser --disabled-password --gecos '' --uid 1000 appuser
```

4. **Use COPY Instead of ADD**:

```dockerfile
# ✅ Use COPY for local files
COPY app.py .
COPY config/ ./config/
```

5. **Use JSON CMD Format**:

```dockerfile
# ✅ Use exec form and non-root user
USER appuser
CMD ["python", "app.py"]
```

**Complete Fixed Dockerfile:**

```dockerfile
# ✅ Secure, best-practice Dockerfile
FROM python:3.11-slim

# Install system dependencies with pinned versions
RUN apt-get update && apt-get install -y \
    curl=7.88.1-10+deb12u4 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN adduser --disabled-password --gecos '' --uid 1000 appuser

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app.py .
COPY config/ ./config/

# Set proper ownership and switch to non-root user
RUN chown -R appuser:appuser /app
USER appuser

# Health check for container monitoring
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Use JSON notation for CMD
CMD ["python", "app.py"]
```

**Verification:**

```bash
# Run Hadolint scan
hadolint Dockerfile

# Expected output: No errors or warnings
# ✅ Dockerfile follows best practices
```

---

## 🔧 Pipeline Integration Problems

### Scenario 1: GitHub Actions Secrets Configuration

**Pipeline Failure Output:**

```
Error: Required secret SONAR_TOKEN not found
Error: Required secret SNYK_TOKEN not found
Error: Required secret SONAR_HOST_URL not found

The following secrets are required but not configured:
- SONAR_TOKEN: SonarQube authentication token
- SNYK_TOKEN: Snyk API token for vulnerability scanning
- SONAR_HOST_URL: SonarQube server URL

Pipeline execution failed due to missing configuration
```

**Step-by-Step Fix:**

1. **Generate SonarQube Token**:

```bash
# For SonarCloud
# 1. Go to https://sonarcloud.io/account/security
# 2. Generate new token with appropriate permissions
# 3. Copy token value

# For self-hosted SonarQube
# 1. Login to SonarQube instance
# 2. Go to My Account > Security > Generate Tokens
# 3. Create token with project analysis permissions
```

2. **Generate Snyk Token**:

```bash
# Method 1: Web interface
# 1. Login to https://snyk.io
# 2. Go to Account Settings > API Token
# 3. Copy your token

# Method 2: CLI
snyk auth
cat ~/.config/configstore/snyk.json | jq -r '.api'
```

3. **Configure GitHub Secrets**:

```bash
# Navigate to GitHub repository
# Settings > Secrets and variables > Actions > New repository secret

# Add the following secrets:
SONAR_TOKEN=<your-sonarqube-token>
SNYK_TOKEN=<your-snyk-token>
SONAR_HOST_URL=https://sonarcloud.io  # or your SonarQube URL
```

4. **Verify Secret Configuration**:

```yaml
# Add to workflow for testing (remove after verification)
- name: Verify secrets
  run: |
    if [ -z "${{ secrets.SONAR_TOKEN }}" ]; then
      echo "❌ SONAR_TOKEN not configured"
      exit 1
    fi
    if [ -z "${{ secrets.SNYK_TOKEN }}" ]; then
      echo "❌ SNYK_TOKEN not configured"  
      exit 1
    fi
    echo "✅ All secrets configured"
  env:
    SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
    SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
```

---

### Scenario 2: Tool Version Compatibility Issues

**Pipeline Failure Output:**

```
Error: SonarQube Quality Gate action failed
Caused by: java.lang.UnsupportedClassVersionError:
  Unsupported major.minor version 61.0

Error: Snyk action failed with exit code 2
Error: Unable to find supported Python version

Tools compatibility matrix mismatch detected
```

**Step-by-Step Fix:**

1. **Update Action Versions**:

```yaml
# .github/workflows/security-pipeline.yml
# ✅ Use compatible, latest versions

- name: SonarQube Scan
  uses: sonarqube-quality-gate-action@master # Latest

- name: Snyk Security Scan
  uses: snyk/actions/python@master # Latest

- name: Trivy Container Scan
  uses: aquasecurity/trivy-action@master # Latest
```

2. **Pin Runner Environment**:

```yaml
jobs:
  security-scan:
    runs-on: ubuntu-22.04 # Pin specific Ubuntu version

    steps:
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: "3.11" # Pin Python version
```

3. **Add Compatibility Checks**:

```yaml
- name: Environment compatibility check
  run: |
    echo "Runner OS: $(uname -a)"
    echo "Python version: $(python --version)"
    echo "Docker version: $(docker --version)"
    echo "Node version: $(node --version)"

    # Check minimum requirements
    python -c "import sys; assert sys.version_info >= (3, 8)"
    docker version --format '{{.Server.Version}}' | grep -E '^2[0-9]+'
```

---

## 🚨 Emergency Response Procedures

### Critical Vulnerability Response (CVSS 9.0+)

**Immediate Actions (0-2 hours):**

1. **Stop Deployment Pipeline**:

```bash
# Disable auto-deployment
gh workflow disable "Deploy to Production"

# Cancel running deployments
kubectl rollout pause deployment/my-app
```

2. **Assess Impact**:

```bash
# Check vulnerability details
snyk test --severity-threshold=critical --json > critical-vulns.json

# Analyze affected components
jq '.vulnerabilities[] | select(.severity == "critical") | {package, version, cve, title}' critical-vulns.json
```

3. **Emergency Communication**:

```bash
# Create incident ticket
curl -X POST https://api.github.com/repos/owner/repo/issues \
  -H "Authorization: token $GITHUB_TOKEN" \
  -d '{
    "title": "CRITICAL: Security vulnerability detected",
    "body": "Critical vulnerability found in production dependencies. Deployment halted.",
    "labels": ["security", "critical", "incident"]
  }'
```

**Short-term Fixes (2-8 hours):**

1. **Immediate Patching**:

```bash
# Create hotfix branch
git checkout -b hotfix/critical-security-fix

# Update vulnerable dependencies
sed -i 's/vulnerable-package==1.0.0/vulnerable-package>=1.0.5/' requirements.txt

# Test fix
python -m pytest tests/
docker build -t my-app:hotfix .
trivy image --severity CRITICAL my-app:hotfix
```

2. **Deploy Emergency Fix**:

```bash
# Fast-track deployment
git add requirements.txt
git commit -m "HOTFIX: Update vulnerable package to secure version"
git push origin hotfix/critical-security-fix

# Emergency merge and deploy
gh pr create --title "EMERGENCY: Critical security fix" --body "Fixes critical vulnerability"
gh pr merge --merge  # Skip normal review process for critical fixes
```

### Regular Vulnerability Management

**Weekly Security Review Process:**

1. **Generate Security Report**:

```bash
#!/bin/bash
# weekly-security-report.sh

echo "# Weekly Security Report - $(date)" > security-report.md
echo "" >> security-report.md

# SonarQube summary
echo "## SonarQube Analysis" >> security-report.md
curl -s -u "$SONAR_TOKEN:" \
  "$SONAR_HOST_URL/api/measures/component?component=$PROJECT_KEY&metricKeys=security_rating,vulnerabilities" \
  | jq -r '.component.measures[] | "- \(.metric): \(.value)"' >> security-report.md

# Snyk summary
echo "## Dependency Vulnerabilities" >> security-report.md
snyk test --json | jq -r '.vulnerabilities | group_by(.severity) | .[] | "\(.[0].severity): \(length) issues"' >> security-report.md

# Container scan summary
echo "## Container Security" >> security-report.md
trivy image --format json my-app:latest | jq -r '.Results[].Vulnerabilities | group_by(.Severity) | .[] | "\(.[0].Severity): \(length) vulnerabilities"' >> security-report.md
```

2. **Automated Remediation**:

```bash
#!/bin/bash
# auto-remediation.sh

# Check for available dependency updates
snyk test --print-deps | grep -i upgrade

# Create automated PRs for low-risk updates
snyk wizard --print-patches > patches.txt

if [ -s patches.txt ]; then
  git checkout -b automated/security-updates
  # Apply patches
  git add .
  git commit -m "chore: automated security updates"
  gh pr create --title "Automated Security Updates" --body "Low-risk security patches"
fi
```

---

## 📞 Support and Escalation

### Internal Escalation Path

1. **Level 1**: Development Team (0-2 hours response)
2. **Level 2**: Security Team (2-4 hours response)
3. **Level 3**: Security Architect (4-8 hours response)
4. **Level 4**: CISO/External Security Firm (8+ hours)

### External Resources

- **SonarQube Support**: [community.sonarsource.com](https://community.sonarsource.com)
- **Snyk Support**: [support.snyk.io](https://support.snyk.io)
- **Trivy Issues**: [github.com/aquasecurity/trivy/issues](https://github.com/aquasecurity/trivy/issues)
- **CVE Database**: [cve.mitre.org](https://cve.mitre.org)
- **NIST NVD**: [nvd.nist.gov](https://nvd.nist.gov)

### Emergency Contacts

```yaml
# emergency-contacts.yml
security_team:
  email: security@company.com
  slack: #security-alerts
  phone: "+1-555-SECURITY"

on_call:
  primary: security-oncall@company.com
  secondary: devops-oncall@company.com
```

Remember: **When in doubt, escalate quickly**. Security issues are better over-reported than under-reported.
