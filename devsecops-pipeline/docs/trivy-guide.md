# Trivy - Container and Infrastructure Security Scanner

## 🔍 What is Trivy?

Trivy is a comprehensive, easy-to-use open-source vulnerability scanner for containers, file systems, and Git repositories. It detects vulnerabilities in OS packages and language-specific packages, misconfigurations in Infrastructure as Code (IaC), and secrets in your code. Trivy is developed by Aqua Security and is widely adopted in DevSecOps pipelines.

## 🛠️ How Trivy Works

### 1. **Multi-Target Scanning**

```
Container Images → OS Packages → Language Dependencies → IaC Files → Secrets
```

1. **Image Analysis**: Extracts and analyzes container image layers
2. **Package Detection**: Identifies OS and language-specific packages
3. **Vulnerability Matching**: Compares against multiple vulnerability databases
4. **Configuration Analysis**: Scans IaC files for misconfigurations
5. **Secret Detection**: Finds hardcoded secrets and credentials

### 2. **Vulnerability Databases**

- **NVD**: National Vulnerability Database
- **GHSA**: GitHub Security Advisory Database
- **OS-specific**: Alpine, Debian, Ubuntu, RHEL, CentOS, Amazon Linux
- **Language-specific**: Node.js, Python, Ruby, Go, Java, .NET

### 3. **Scan Types**

- **Container Images**: Docker images, OCI images
- **Filesystem**: Local directories and files
- **Git Repositories**: Remote and local repositories
- **Kubernetes**: Manifests and running clusters
- **Infrastructure as Code**: Terraform, CloudFormation, Dockerfile

## 🚨 Common Vulnerabilities Detected

### 1. **High-Severity OS Package Vulnerabilities**

**Example - Ubuntu Base Image:**

```dockerfile
FROM ubuntu:18.04  # Contains known vulnerabilities
RUN apt-get update && apt-get install -y curl
```

**Trivy Detection:**

```
ubuntu:18.04 (ubuntu 18.04)
============================
Total: 115 (UNKNOWN: 0, LOW: 21, MEDIUM: 32, HIGH: 45, CRITICAL: 17)

┌─────────────────┬──────────────────┬──────────┬───────────────────┬───────────────┬─────────────────────────────────────┐
│     Library     │  Vulnerability   │ Severity │ Installed Version │ Fixed Version │                Title                │
├─────────────────┼──────────────────┼──────────┼───────────────────┼───────────────┼─────────────────────────────────────┤
│ apt             │ CVE-2020-3810    │ CRITICAL │ 1.6.12ubuntu0.1   │ 1.6.12ubuntu0.2│ Missing input validation when       │
│                 │                  │          │                   │               │ processing .deb packages            │
├─────────────────┼──────────────────┼──────────┼───────────────────┼───────────────┼─────────────────────────────────────┤
│ libc6           │ CVE-2021-3326    │ HIGH     │ 2.27-3ubuntu1     │ 2.27-3ubuntu1.6│ Buffer overflow in gconv modules    │
├─────────────────┼──────────────────┼──────────┼───────────────────┼───────────────┼─────────────────────────────────────┤
│ libssl1.1       │ CVE-2021-3449    │ HIGH     │ 1.1.1-1ubuntu2.1  │ 1.1.1-1ubuntu2.8│ NULL pointer dereference in         │
│                 │                  │          │                   │               │ signature_algorithms processing      │
└─────────────────┴──────────────────┴──────────┴───────────────────┴───────────────┴─────────────────────────────────────┘
```

**How to Fix:**

```dockerfile
# Use newer, patched base image
FROM ubuntu:22.04  # or ubuntu:20.04
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
```

### 2. **Python Package Vulnerabilities**

**Example - Vulnerable Dependencies:**

```txt
# requirements.txt
requests==2.18.4  # Contains CVE-2018-18074
urllib3==1.24.1   # Contains multiple CVEs
```

**Trivy Detection:**

```
Python (python-pkg)
==================
Total: 8 (UNKNOWN: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 2)

┌─────────────┬────────────────┬──────────┬───────────────────┬───────────────┬─────────────────────────────────────┐
│   Library   │ Vulnerability  │ Severity │ Installed Version │ Fixed Version │                Title                │
├─────────────┼────────────────┼──────────┼───────────────────┼───────────────┼─────────────────────────────────────┤
│ requests    │ CVE-2018-18074 │ HIGH     │ 2.18.4            │ 2.20.0        │ Redirect following without          │
│             │                │          │                   │               │ authentication header removal       │
├─────────────┼────────────────┼──────────┼───────────────────┼───────────────┼─────────────────────────────────────┤
│ urllib3     │ CVE-2019-11324 │ CRITICAL │ 1.24.1            │ 1.24.2        │ Improper neutralization of CRLF     │
│             │                │          │                   │               │ sequences in urllib3                │
├─────────────┼────────────────┼──────────┼───────────────────┼───────────────┼─────────────────────────────────────┤
│ urllib3     │ CVE-2020-26137 │ HIGH     │ 1.24.1            │ 1.25.9        │ CRLF injection via HTTP request     │
│             │                │          │                   │               │ method parameter                    │
└─────────────┴────────────────┴──────────┴───────────────────┴───────────────┴─────────────────────────────────────┘
```

**How to Fix:**

```txt
# requirements.txt - Updated versions
requests>=2.25.1
urllib3>=1.26.5
```

### 3. **Dockerfile Misconfigurations**

**Example - Insecure Dockerfile:**

```dockerfile
FROM python:3.11
WORKDIR /app

# ❌ Running as root
# ❌ No version pinning
# ❌ No cleanup after install

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 5000
CMD ["python", "app.py"]
```

**Trivy Detection:**

```
Dockerfile (dockerfile)
=======================
Total: 6 (UNKNOWN: 0, LOW: 2, MEDIUM: 1, HIGH: 2, CRITICAL: 1)

┌─────────────────────┬────────────────┬──────────┬──────────┬─────────────────────────────────────┐
│        Type         │   ID           │ Severity │  Title   │             Description             │
├─────────────────────┼────────────────┼──────────┼──────────┼─────────────────────────────────────┤
│ Dockerfile Security │ DS002          │ CRITICAL │ Root     │ Container is running as root user   │
│                     │                │          │ User     │ which poses security risks          │
├─────────────────────┼────────────────┼──────────┼──────────┼─────────────────────────────────────┤
│ Dockerfile Security │ DS013          │ HIGH     │ Port     │ Port 5000 should not be exposed     │
│                     │                │          │ Exposure │ unnecessarily                       │
├─────────────────────┼────────────────┼──────────┼──────────┼─────────────────────────────────────┤
│ Dockerfile Security │ DS015          │ MEDIUM   │ Package  │ apt/apk cache should be cleaned     │
│                     │                │          │ Cache    │ after package installation          │
└─────────────────────┴────────────────┴──────────┴──────────┴─────────────────────────────────────┘
```

**How to Fix:**

```dockerfile
FROM python:3.11-slim

# Create non-root user
RUN adduser --disabled-password --gecos '' appuser

WORKDIR /app

# Install dependencies as root, then switch user
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application and change ownership
COPY app.py .
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Don't expose port unnecessarily in Dockerfile
# EXPOSE 5000

CMD ["python", "app.py"]
```

### 4. **Secrets Detection**

**Example - Hardcoded Secrets:**

```python
# config.py
DATABASE_URL = "postgresql://admin:secretpassword123@localhost/mydb"
API_KEY = "sk-1234567890abcdef1234567890abcdef"
JWT_SECRET = "my-super-secret-jwt-key-12345"
```

**Trivy Detection:**

```
config.py (secrets)
==================
Total: 3 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 3, CRITICAL: 0)

┌─────────────────────┬────────────────┬──────────┬──────────┬─────────────────────────────────────┐
│        Type         │      ID        │ Severity │   Title  │             Match               │
├─────────────────────┼────────────────┼──────────┼──────────┼─────────────────────────────────────┤
│ Secret              │ database-url   │ HIGH     │ Database │ postgresql://admin:secretpass...    │
│                     │                │          │ URL      │                                     │
├─────────────────────┼────────────────┼──────────┼──────────┼─────────────────────────────────────┤
│ Secret              │ api-key        │ HIGH     │ API Key  │ sk-1234567890abcdef123456789...     │
├─────────────────────┼────────────────┼──────────┼──────────┼─────────────────────────────────────┤
│ Secret              │ jwt-secret     │ HIGH     │ JWT      │ my-super-secret-jwt-key-12345       │
│                     │                │          │ Secret   │                                     │
└─────────────────────┴────────────────┴──────────┴──────────┴─────────────────────────────────────┘
```

**How to Fix:**

```python
# config.py
import os

DATABASE_URL = os.getenv('DATABASE_URL')
API_KEY = os.getenv('API_KEY')
JWT_SECRET = os.getenv('JWT_SECRET')

# .env (not committed to git)
DATABASE_URL=postgresql://admin:secretpassword123@localhost/mydb
API_KEY=sk-1234567890abcdef1234567890abcdef
JWT_SECRET=my-super-secret-jwt-key-12345
```

## 🔧 Pipeline Integration Example

### GitHub Actions Integration

```yaml
- name: Run Trivy vulnerability scanner
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: "my-app:latest"
    format: "sarif"
    output: "trivy-results.sarif"
    severity: "CRITICAL,HIGH,MEDIUM"

- name: Upload Trivy scan results
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: "trivy-results.sarif"
```

### Expected Pipeline Failure

```
Trivy Security Scan Results:
============================

Container Image: my-app:latest
Scan completed in 45.2 seconds

CRITICAL: 3 vulnerabilities found
HIGH: 12 vulnerabilities found
MEDIUM: 8 vulnerabilities found

Critical Issues Requiring Immediate Attention:
1. CVE-2021-44228 (Log4Shell) - CRITICAL
   Library: log4j-core@2.14.1
   Fix: Upgrade to 2.17.0+

2. CVE-2020-3810 (apt) - CRITICAL
   Fix: Update base image to ubuntu:20.04+

3. CVE-2019-11324 (urllib3) - CRITICAL
   Fix: Upgrade to urllib3@1.24.2+

Build FAILED due to CRITICAL vulnerabilities
```

## 🛠️ Local Setup and Testing

### 1. **Install Trivy**

```bash
# macOS
brew install trivy

# Linux
wget https://github.com/aquasecurity/trivy/releases/download/v0.45.0/trivy_0.45.0_Linux-64bit.tar.gz
tar zxvf trivy_0.45.0_Linux-64bit.tar.gz
sudo mv trivy /usr/local/bin/

# Verify installation
trivy version
```

### 2. **Basic Container Scanning**

```bash
# Scan Docker image
trivy image python:3.11-slim

# Scan with specific severities
trivy image --severity HIGH,CRITICAL nginx:latest

# Output as JSON
trivy image --format json python:3.11-slim > scan-results.json

# Scan local image
docker build -t my-app .
trivy image my-app:latest
```

### 3. **Filesystem Scanning**

```bash
# Scan current directory
trivy fs .

# Scan specific directory
trivy fs /path/to/project

# Scan for secrets only
trivy fs --scanners secret .

# Scan for misconfigurations
trivy fs --scanners config .
```

### 4. **Repository Scanning**

```bash
# Scan remote repository
trivy repo https://github.com/user/repo

# Scan local repository
trivy repo .

# Include historical commits
trivy repo --include-non-failures .
```

## 📊 Understanding Trivy Reports

### Severity Classification

- **CRITICAL**: CVSS 9.0-10.0 (Immediate action required)
- **HIGH**: CVSS 7.0-8.9 (Important vulnerabilities)
- **MEDIUM**: CVSS 4.0-6.9 (Moderate risk)
- **LOW**: CVSS 0.1-3.9 (Minimal risk)
- **UNKNOWN**: No CVSS score available

### Report Formats

```bash
# Table format (default)
trivy image python:3.11-slim

# JSON format
trivy image --format json python:3.11-slim

# SARIF format (for GitHub)
trivy image --format sarif python:3.11-slim

# Template format
trivy image --format template --template "@contrib/html.tpl" python:3.11-slim
```

## 🛡️ Advanced Configuration

### 1. **Custom Policies**

Create `.trivyignore` file:

```
# Ignore specific CVEs
CVE-2019-1234
CVE-2020-5678

# Ignore by package
python-stdlib

# Ignore by path
/usr/local/lib/python3.11/site-packages/old-package/

# Ignore by severity (not recommended)
# LOW
```

### 2. **Configuration File**

Create `trivy.yaml`:

```yaml
# trivy.yaml
format: json
output: trivy-results.json
severity:
  - HIGH
  - CRITICAL
ignore-unfixed: true
security-checks:
  - vuln
  - config
  - secret
cache:
  clear: true
```

### 3. **Custom Scanners**

```bash
# Scan only for vulnerabilities
trivy image --scanners vuln python:3.11-slim

# Scan only for secrets
trivy fs --scanners secret .

# Scan only for misconfigurations
trivy fs --scanners config .

# Combine multiple scanners
trivy image --scanners vuln,secret,config my-app:latest
```

## 🚀 Integration Strategies

### 1. **CI/CD Integration**

```yaml
# Multi-stage scanning
steps:
  - name: Scan Dockerfile
    run: trivy config Dockerfile

  - name: Build image
    run: docker build -t app:${{ github.sha }} .

  - name: Scan built image
    run: trivy image app:${{ github.sha }}
```

### 2. **Quality Gates**

```bash
#!/bin/bash
# scan-and-gate.sh

# Run Trivy scan
trivy image --format json --output results.json my-app:latest

# Check for critical vulnerabilities
CRITICAL=$(jq '.Results[].Vulnerabilities[] | select(.Severity == "CRITICAL") | length' results.json)

if [ "$CRITICAL" -gt 0 ]; then
  echo "FAILED: Found $CRITICAL critical vulnerabilities"
  exit 1
fi

echo "PASSED: No critical vulnerabilities found"
```

### 3. **Monitoring and Alerting**

```bash
# Daily vulnerability scan
#!/bin/bash
trivy image --format json my-app:latest | \
  jq '.Results[].Vulnerabilities[] | select(.Severity == "HIGH" or .Severity == "CRITICAL")' | \
  mail -s "Daily Vulnerability Report" security@company.com
```

## 🎯 Best Practices

### 1. **Container Security**

- Use minimal base images (alpine, distroless)
- Regular base image updates
- Multi-stage builds to reduce attack surface
- Non-root user execution

### 2. **Vulnerability Management**

- Scan early and often
- Prioritize by severity and exploitability
- Set appropriate thresholds for CI/CD gates
- Regular dependency updates

### 3. **Secret Management**

- Use environment variables
- Implement proper secret rotation
- Scan before committing code
- Use secret management tools (Vault, AWS Secrets Manager)

### 4. **Performance Optimization**

- Use Trivy cache for faster scans
- Parallel scanning for multiple images
- Incremental scanning for large repositories
- Appropriate timeout settings

## 🔗 Useful Resources

- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [GitHub Actions Integration](https://github.com/aquasecurity/trivy-action)
- [Configuration Reference](https://aquasecurity.github.io/trivy/latest/docs/configuration/)
- [Vulnerability Database](https://github.com/aquasecurity/trivy-db)
