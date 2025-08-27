# Example Files for Security Tool Demonstrations

This directory contains intentionally vulnerable code and configuration files that demonstrate the types of security issues detected by our DevSecOps pipeline tools.

## ⚠️ WARNING

**DO NOT USE THESE FILES IN PRODUCTION!**

These files are for educational purposes only and contain known security vulnerabilities.

## 📁 Files Description

### `vulnerable_code.py`

Demonstrates Python security vulnerabilities that SonarQube SAST will detect:

- SQL injection vulnerabilities
- Cross-site scripting (XSS)
- Hard-coded credentials
- Weak cryptographic functions
- Path traversal vulnerabilities
- Debug mode in production

### `Dockerfile.vulnerable`

Shows Dockerfile security issues that Hadolint will detect:

- Untagged base images
- Running as root user
- Unpinned package versions
- Not cleaning package cache
- Using ADD instead of COPY
- Hard-coded secrets
- Exposing sensitive ports
- Shell form CMD

### `requirements-vulnerable.txt`

Contains outdated Python packages with known vulnerabilities that Snyk will detect:

- Flask with CVE vulnerabilities
- urllib3 with CRLF injection issues
- Jinja2 with XSS vulnerabilities
- cryptography with weak crypto
- PyYAML with code execution issues

## 🧪 Testing with Security Tools

### Local Testing Commands

```bash
# Test with SonarQube (requires local SonarQube server)
sonar-scanner -Dsonar.sources=examples/vulnerable_code.py

# Test with Snyk
snyk test --file=examples/requirements-vulnerable.txt

# Test with Trivy
trivy config examples/Dockerfile.vulnerable

# Test with Hadolint
hadolint examples/Dockerfile.vulnerable
```

### Expected Detections

#### SonarQube

- **Critical**: SQL injection in `get_vulnerable_user()`
- **Critical**: Hard-coded credentials
- **High**: XSS in `vulnerable_greeting()`
- **High**: Weak MD5 hashing
- **Medium**: Path traversal vulnerability
- **Info**: Debug mode enabled

#### Snyk

- **Critical**: Multiple CVEs in Flask, urllib3, cryptography
- **High**: Security vulnerabilities in Jinja2, SQLAlchemy
- **Medium**: Various dependency vulnerabilities
- **License Issues**: Potential GPL license conflicts

#### Trivy

- **Critical**: Base image vulnerabilities
- **High**: Configuration misconfigurations
- **Medium**: Secrets in environment variables

#### Hadolint

- **Error**: DL3002 - Running as root
- **Error**: DL3008 - Unpinned versions
- **Warning**: DL3006 - Untagged image
- **Warning**: DL3009 - Package cache not cleaned
- **Warning**: DL3020 - Using ADD instead of COPY

## 🔧 How to Fix

Refer to the main documentation for detailed fix instructions:

- [SonarQube Guide](../docs/sonarqube-guide.md)
- [Snyk Guide](../docs/snyk-guide.md)
- [Trivy Guide](../docs/trivy-guide.md)
- [Hadolint Guide](../docs/hadolint-guide.md)
- [Troubleshooting Guide](../docs/troubleshooting-guide.md)

## 📚 Educational Use

These examples are perfect for:

1. Understanding what each security tool detects
2. Learning how to interpret security scan results
3. Practicing vulnerability remediation
4. Training team members on security best practices
5. Testing security tool configurations

Remember: The goal is to learn from these mistakes and avoid them in real applications!
