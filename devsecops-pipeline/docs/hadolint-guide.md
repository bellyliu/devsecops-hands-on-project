# Hadolint - Dockerfile Linter and Security Scanner

## 🔍 What is Hadolint?

Hadolint is a Dockerfile linter that helps you build best practice Docker images. It parses the Dockerfile into an AST and performs rules on top of the AST. It validates inline bash, written in Haskell, and follows the Dockerfile best practices defined by Docker. Hadolint is particularly strong at catching Dockerfile-specific security and efficiency issues.

## 🛠️ How Hadolint Works

### 1. **Dockerfile Analysis Process**

```
Dockerfile → Parser → AST → Rule Engine → Security Checks → Report
```

1. **Parsing**: Converts Dockerfile into Abstract Syntax Tree (AST)
2. **Rule Application**: Applies best practice and security rules
3. **Shell Analysis**: Validates inline bash commands using ShellCheck
4. **Security Analysis**: Identifies security vulnerabilities and misconfigurations
5. **Reporting**: Generates detailed reports with recommendations

### 2. **Rule Categories**

- **Security**: Identifies security vulnerabilities and misconfigurations
- **Best Practices**: Docker and container best practices
- **Performance**: Optimization recommendations
- **Maintainability**: Code quality and readability
- **Style**: Formatting and consistency

### 3. **Integration with ShellCheck**

Hadolint integrates with ShellCheck to analyze shell commands in RUN instructions, providing comprehensive bash security analysis.

## 🚨 Common Issues Detected

### 1. **Running as Root User (DL3002)**

**Example - Vulnerable Dockerfile:**

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 5000

# ❌ Running as root user
CMD ["python", "app.py"]
```

**Hadolint Detection:**

```
Dockerfile:11 DL3002 warning: Last USER should not be root
  └── User is currently 'root'. Consider switching to a non-root user.
```

**Security Impact:**

- Container runs with root privileges
- Potential for privilege escalation
- Increased attack surface
- Violates principle of least privilege

**How to Fix:**

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

# ✅ Create and use non-root user
RUN adduser --disabled-password --gecos '' appuser
COPY . .
RUN chown -R appuser:appuser /app
USER appuser

EXPOSE 5000
CMD ["python", "app.py"]
```

### 2. **Package Manager Cache Not Cleaned (DL3009)**

**Example - Inefficient Dockerfile:**

```dockerfile
FROM ubuntu:20.04

# ❌ Package cache not cleaned
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    curl
```

**Hadolint Detection:**

```
Dockerfile:4 DL3009 warning: Delete the apt-get lists after installing something
  └── Cleaning package manager cache reduces image size and attack surface
```

**Security & Performance Impact:**

- Larger image size
- Potential information disclosure
- Increased attack surface
- Wasted storage and bandwidth

**How to Fix:**

```dockerfile
FROM ubuntu:20.04

# ✅ Clean package cache in same layer
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    curl \
    && rm -rf /var/lib/apt/lists/*
```

### 3. **Unpinned Package Versions (DL3008)**

**Example - Vulnerable to Supply Chain Attacks:**

```dockerfile
FROM ubuntu:20.04

# ❌ Unpinned package versions
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    curl
```

**Hadolint Detection:**

```
Dockerfile:4 DL3008 warning: Pin versions in apt get install
  └── Specify package versions for reproducible builds
```

**Security Impact:**

- Non-reproducible builds
- Potential supply chain attacks
- Unexpected behavior changes
- Difficult to track vulnerabilities

**How to Fix:**

```dockerfile
FROM ubuntu:20.04

# ✅ Pin specific package versions
RUN apt-get update && apt-get install -y \
    python3=3.8.2-0ubuntu2 \
    python3-pip=20.0.2-5ubuntu1.1 \
    curl=7.68.0-1ubuntu2.7 \
    && rm -rf /var/lib/apt/lists/*
```

### 4. **Using ADD Instead of COPY (DL3020)**

**Example - Potentially Dangerous:**

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# ❌ Using ADD for local files
ADD requirements.txt .
ADD app.py .
ADD config.json .
```

**Hadolint Detection:**

```
Dockerfile:5-7 DL3020 warning: Use COPY instead of ADD for files and folders
  └── ADD has additional functionality that can be security risk
```

**Security Impact:**

- ADD can decompress archives automatically
- ADD can fetch remote URLs
- Potential for malicious content execution
- Less predictable behavior

**How to Fix:**

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# ✅ Use COPY for local files
COPY requirements.txt .
COPY app.py .
COPY config.json .

# Use ADD only when needed for URLs or archives
# ADD https://example.com/file.tar.gz /tmp/
```

### 5. **Exposing Sensitive Ports (DL3011)**

**Example - Exposing Risky Ports:**

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY . .

# ❌ Exposing potentially sensitive ports
EXPOSE 22  # SSH
EXPOSE 3306  # MySQL
EXPOSE 5432  # PostgreSQL
```

**Hadolint Detection:**

```
Dockerfile:6 DL3011 warning: Valid UNIX ports range from 0 to 65535. Port 22 is commonly used by SSH.
Dockerfile:7 DL3011 warning: Port 3306 is commonly used by MySQL and might be sensitive.
Dockerfile:8 DL3011 warning: Port 5432 is commonly used by PostgreSQL and might be sensitive.
```

**Security Impact:**

- Unnecessary port exposure
- Potential attack vectors
- Information disclosure
- Service enumeration

**How to Fix:**

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY . .

# ✅ Only expose necessary application ports
EXPOSE 5000  # Application port

# Don't expose infrastructure service ports
# Configure port mapping at runtime if needed
```

### 6. **Shell Command Security Issues**

**Example - Vulnerable Shell Commands:**

```dockerfile
FROM python:3.11-slim

# ❌ Various shell security issues
RUN curl -sSL https://example.com/script.sh | bash
RUN wget $URL -O /tmp/file
RUN echo $PASSWORD > /tmp/pwd
```

**Hadolint Detection:**

```
Dockerfile:4 SC2094 error: Make sure not to read and write the same file in the same pipeline
Dockerfile:5 SC2154 warning: $URL is referenced but not assigned
Dockerfile:6 SC2086 info: Double quote to prevent globbing and word splitting
```

**Security Impact:**

- Code injection vulnerabilities
- Command injection attacks
- Credential exposure
- Arbitrary command execution

**How to Fix:**

```dockerfile
FROM python:3.11-slim

# ✅ Secure shell commands
RUN curl -sSL https://example.com/script.sh -o /tmp/script.sh \
    && chmod +x /tmp/script.sh \
    && /tmp/script.sh \
    && rm /tmp/script.sh

# Use proper variable handling
ARG DOWNLOAD_URL
RUN wget "${DOWNLOAD_URL}" -O /tmp/file

# Don't expose secrets in commands
# Use Docker secrets or environment variables
```

## 🔧 Pipeline Integration Example

### GitHub Actions Integration

```yaml
- name: Run Hadolint Dockerfile Linter
  uses: hadolint/hadolint-action@v3.1.0
  with:
    dockerfile: Dockerfile
    format: sarif
    output-file: hadolint-results.sarif
    no-fail: true

- name: Upload Hadolint results
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: hadolint-results.sarif
```

### Expected Pipeline Failure

```
Hadolint Dockerfile Analysis Results:
====================================

Dockerfile: ./Dockerfile
Analyzed in 0.234 seconds

ERRORS: 2 issues found
WARNINGS: 5 issues found
INFO: 3 issues found

Critical Issues:
1. DL3002 [ERROR] Line 15: Last USER should not be root
   Impact: Container runs with elevated privileges

2. DL3008 [ERROR] Line 8: Pin versions in apt get install
   Impact: Non-reproducible builds, supply chain risk

3. DL3009 [WARNING] Line 8: Delete apt-get lists after installing
   Impact: Increased image size and attack surface

4. DL3020 [WARNING] Line 12: Use COPY instead of ADD
   Impact: Potential security risk with ADD instruction

5. SC2086 [INFO] Line 10: Double quote to prevent globbing
   Impact: Shell injection vulnerability

Build FAILED due to Dockerfile security and best practice violations
```

## 🛠️ Local Setup and Testing

### 1. **Install Hadolint**

```bash
# macOS
brew install hadolint

# Linux - Download binary
wget https://github.com/hadolint/hadolint/releases/download/v2.12.0/hadolint-Linux-x86_64
chmod +x hadolint-Linux-x86_64
sudo mv hadolint-Linux-x86_64 /usr/local/bin/hadolint

# Docker
docker run --rm -i hadolint/hadolint < Dockerfile

# Verify installation
hadolint --version
```

### 2. **Basic Scanning**

```bash
# Scan Dockerfile
hadolint Dockerfile

# Scan with specific format
hadolint --format json Dockerfile

# Ignore specific rules
hadolint --ignore DL3008 --ignore DL3009 Dockerfile

# Output to file
hadolint --format sarif Dockerfile > hadolint-results.sarif
```

### 3. **Configuration File**

Create `.hadolint.yaml`:

```yaml
# .hadolint.yaml
format: json
failure-threshold: warning

ignored:
  - DL3008 # Pin versions in apt get install
  - DL3009 # Delete apt-get lists

trusted-registries:
  - docker.io
  - quay.io
  - gcr.io

label-schema:
  author: text
  version: semver
```

## 📊 Understanding Hadolint Reports

### Rule Categories and Severity

```
DL3xxx: Dockerfile best practices (WARNING/ERROR)
DL4xxx: Dockerfile maintainability (INFO/WARNING)
SC2xxx: ShellCheck rules (INFO/WARNING/ERROR)
```

### Common Rule Patterns

- **DL3002**: Last USER should not be root
- **DL3008**: Pin versions in package managers
- **DL3009**: Delete package manager cache
- **DL3020**: Use COPY instead of ADD
- **DL3025**: Use arguments JSON notation for CMD and ENTRYPOINT
- **DL4006**: Set SHELL option -o pipefail

### Report Formats

```bash
# Standard output
hadolint Dockerfile

# JSON format
hadolint --format json Dockerfile

# SARIF format (for GitHub Security tab)
hadolint --format sarif Dockerfile

# Checkstyle format
hadolint --format checkstyle Dockerfile

# CodeClimate format
hadolint --format codeclimate Dockerfile
```

## 🛡️ Advanced Configuration

### 1. **Inline Ignore Rules**

```dockerfile
FROM python:3.11-slim

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y curl

# hadolint ignore=DL3002
USER root

# Multiple ignores
# hadolint ignore=DL3008,DL3009
RUN apt-get install -y python3 python3-pip
```

### 2. **Custom Rules Configuration**

```yaml
# .hadolint.yaml
failure-threshold: error
format: json

ignored:
  - DL3008 # Allow unpinned versions in development

trusted-registries:
  - docker.io
  - company-registry.com

label-schema:
  maintainer: email
  version: semver
  description: text

strict-labels: true
disable-ignore-pragma: false
```

### 3. **Integration with Pre-commit**

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/hadolint/hadolint
    rev: v2.12.0
    hooks:
      - id: hadolint-docker
        args: ["--ignore", "DL3008"]
```

## 🚀 Best Practices

### 1. **Security-Focused Rules**

Always enforce these critical security rules:

```yaml
# Never ignore these security rules
critical-rules:
  - DL3002 # Don't run as root
  - DL3020 # Use COPY, not ADD
  - DL3001 # Switch to non-root user
```

### 2. **Performance Optimization**

```dockerfile
# ✅ Multi-stage build with security best practices
FROM python:3.11-slim as builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --user -r requirements.txt

FROM python:3.11-slim as runtime
RUN adduser --disabled-password --gecos '' appuser
WORKDIR /app

# Copy only necessary files
COPY --from=builder /root/.local /home/appuser/.local
COPY app.py .
RUN chown -R appuser:appuser /app

USER appuser
ENV PATH=/home/appuser/.local/bin:$PATH
CMD ["python", "app.py"]
```

### 3. **Dockerfile Template**

```dockerfile
# Secure Dockerfile template
ARG PYTHON_VERSION=3.11
FROM python:${PYTHON_VERSION}-slim

# Create non-root user
RUN adduser --disabled-password --gecos '' --uid 1000 appuser

# Install system dependencies with pinned versions
RUN apt-get update && apt-get install -y \
    curl=7.88.1-10+deb12u4 \
    && rm -rf /var/lib/apt/lists/*

# Set working directory and copy files
WORKDIR /app
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code and set permissions
COPY --chown=appuser:appuser . .

# Switch to non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Use JSON notation for CMD
CMD ["python", "app.py"]
```

## 🎯 Integration Strategies

### 1. **CI/CD Pipeline Integration**

```yaml
# Complete Dockerfile scanning workflow
jobs:
  dockerfile-security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Lint Dockerfile with Hadolint
        uses: hadolint/hadolint-action@v3.1.0
        with:
          dockerfile: Dockerfile
          failure-threshold: error

      - name: Build test image
        run: docker build -t test-image .

      - name: Test image security
        run: |
          # Verify non-root user
          USER=$(docker run --rm test-image whoami)
          if [ "$USER" = "root" ]; then
            echo "ERROR: Container running as root"
            exit 1
          fi
```

### 2. **Quality Gates**

```bash
#!/bin/bash
# dockerfile-quality-gate.sh

# Run Hadolint with JSON output
hadolint --format json Dockerfile > hadolint-results.json

# Count errors and warnings
ERRORS=$(jq '[.[] | select(.level == "error")] | length' hadolint-results.json)
WARNINGS=$(jq '[.[] | select(.level == "warning")] | length' hadolint-results.json)

echo "Hadolint Results: $ERRORS errors, $WARNINGS warnings"

# Fail on any errors
if [ "$ERRORS" -gt 0 ]; then
    echo "FAILED: Dockerfile contains $ERRORS error(s)"
    jq '[.[] | select(.level == "error")]' hadolint-results.json
    exit 1
fi

# Warn on too many warnings
if [ "$WARNINGS" -gt 5 ]; then
    echo "WARNING: Dockerfile contains $WARNINGS warning(s)"
    jq '[.[] | select(.level == "warning")]' hadolint-results.json
fi

echo "PASSED: Dockerfile quality check successful"
```

## 🔗 Useful Resources

- [Hadolint Documentation](https://github.com/hadolint/hadolint)
- [Dockerfile Best Practices](https://docs.docker.com/develop/dev-best-practices/)
- [ShellCheck Integration](https://www.shellcheck.net/)
- [Docker Security Scanning](https://docs.docker.com/engine/scan/)
