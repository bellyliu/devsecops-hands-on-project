# Snyk - Software Composition Analysis (SCA)

## 🔍 What is Snyk?

Snyk is a leading developer security platform that specializes in Software Composition Analysis (SCA). It identifies and helps fix vulnerabilities in open-source dependencies, container images, Infrastructure as Code (IaC), and code repositories. Snyk continuously monitors your dependencies for newly discovered vulnerabilities.

## 🛠️ How Snyk Works

### 1. **Vulnerability Detection Process**

```
Dependencies → Snyk Database → Vulnerability Matching → Risk Assessment → Remediation
```

1. **Dependency Discovery**: Scans package files (requirements.txt, package.json, etc.)
2. **Database Lookup**: Compares against Snyk's vulnerability database
3. **Impact Analysis**: Assesses exploitability and business impact
4. **Fix Recommendations**: Provides upgrade paths and patches
5. **Continuous Monitoring**: Alerts on new vulnerabilities

### 2. **Vulnerability Database**

- **Sources**: CVE, NVD, security advisories, proprietary research
- **Coverage**: 1M+ vulnerabilities across all ecosystems
- **Speed**: Often faster than CVE publication
- **Accuracy**: Manual verification reduces false positives

### 3. **Risk Prioritization**

- **CVSS Score**: Common Vulnerability Scoring System
- **Exploit Maturity**: Known exploits in the wild
- **Reachability**: Whether vulnerable code is actually used
- **Business Context**: Impact on your specific application

## 🚨 Common Vulnerabilities Detected

### 1. **Remote Code Execution (RCE)**

**Example - Vulnerable Dependency:**

```txt
# requirements.txt
Flask==1.0.2  # Contains CVE-2018-1000656
```

**Snyk Detection:**

```
✗ High severity vulnerability found in Flask
  Path: Flask@1.0.2
  Info: Improper Input Validation leads to Denial of Service (DoS)
  CVE: CVE-2018-1000656
  CVSS Score: 7.5
  Introduced through: Flask@1.0.2

  Detailed paths:
    Flask@1.0.2
```

**Vulnerability Details:**

- **Issue**: Improper input validation in JSON parsing
- **Impact**: Denial of Service through malformed JSON
- **Exploit**: Publicly available
- **Fix**: Upgrade to Flask@1.0.3 or higher

**How to Fix:**

```txt
# requirements.txt
Flask>=1.0.3  # Fixed version
```

### 2. **Cross-Site Scripting (XSS) in Dependencies**

**Example - Vulnerable Package:**

```txt
# requirements.txt
Jinja2==2.10  # Contains CVE-2019-10906
```

**Snyk Detection:**

```
✗ High severity vulnerability found in Jinja2
  Path: Jinja2@2.10
  Info: Cross-site Scripting (XSS) in Jinja2
  CVE: CVE-2019-10906
  CVSS Score: 8.2
  CWE: CWE-79

  Vulnerability Details:
  - Sandbox escape vulnerability
  - Allows template injection attacks
  - Can lead to XSS in web applications
```

**How to Fix:**

```txt
# requirements.txt
Jinja2>=2.10.1  # Patched version
```

### 3. **SQL Injection in Third-party Libraries**

**Example - Vulnerable Database Driver:**

```txt
# requirements.txt
SQLAlchemy==1.2.0  # Contains known SQL injection issue
```

**Snyk Detection:**

```
✗ Critical severity vulnerability found in SQLAlchemy
  Path: SQLAlchemy@1.2.0
  Info: SQL Injection vulnerability
  CVE: CVE-2019-7164
  CVSS Score: 9.8

  Issue Summary:
  - Improper neutralization of SQL commands
  - Affects Oracle dialect with cx_Oracle
  - Allows arbitrary SQL execution
```

**How to Fix:**

```txt
# requirements.txt
SQLAlchemy>=1.2.18  # Security patch included
```

### 4. **Cryptographic Vulnerabilities**

**Example - Weak Crypto Library:**

```txt
# requirements.txt
cryptography==2.1.4  # Contains multiple CVEs
```

**Snyk Detection:**

```
✗ High severity vulnerability found in cryptography
  Path: cryptography@2.1.4
  Info: Use of Insufficiently Random Values
  CVE: CVE-2018-10903
  CVSS Score: 7.5

  Additional Issues Found:
  - CVE-2020-25659: Bleichenbacher timing oracle
  - CVE-2020-36242: Buffer overflow in ECDH

  Recommendation: Upgrade to cryptography@3.3.2 or higher
```

**How to Fix:**

```txt
# requirements.txt
cryptography>=3.3.2  # Multiple security fixes
```

## 🔧 Pipeline Integration Example

### GitHub Actions Integration

```yaml
- name: Run Snyk to check for vulnerabilities
  uses: snyk/actions/python@master
  env:
    SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
  with:
    args: --severity-threshold=high --file=requirements.txt
```

### Expected Pipeline Failure

```
Testing /path/to/requirements.txt...

✗ High severity vulnerability found in Flask
  introduced by Flask@1.0.2

✗ Critical severity vulnerability found in urllib3
  introduced by urllib3@1.24.1

✗ Medium severity vulnerability found in requests
  introduced by requests@2.20.0

Organization: your-org
Package manager: pip
Target file: requirements.txt
Project name: flask-app
Open source: no
Project path: /path/to/project

Tested 45 dependencies for known issues, found 3 issues, 3 vulnerable paths.

Build failed due to vulnerabilities above severity threshold (high)
```

## 🛠️ Local Setup and Testing

### 1. **Install Snyk CLI**

```bash
# Install via npm
npm install -g snyk

# Or download binary
curl -Lo snyk https://github.com/snyk/snyk/releases/latest/download/snyk-linux
chmod +x snyk
sudo mv snyk /usr/local/bin/

# Authenticate
snyk auth
```

### 2. **Basic Scanning**

```bash
# Test current directory
snyk test

# Test specific file
snyk test --file=requirements.txt

# Include dev dependencies
snyk test --dev

# Set severity threshold
snyk test --severity-threshold=high

# Output as JSON
snyk test --json > snyk-results.json
```

### 3. **Monitor for New Vulnerabilities**

```bash
# Add project to monitoring
snyk monitor

# Monitor specific file
snyk monitor --file=requirements.txt

# Set project name
snyk monitor --project-name="My Flask App"
```

## 📊 Understanding Snyk Reports

### Vulnerability Report Structure

```json
{
  "vulnerabilities": [
    {
      "id": "SNYK-PYTHON-FLASK-40388",
      "title": "Denial of Service (DoS)",
      "severity": "high",
      "cvssScore": 7.5,
      "cve": "CVE-2018-1000656",
      "package": "Flask",
      "version": "1.0.2",
      "upgradePath": ["Flask@1.0.3"],
      "patches": [],
      "isUpgradable": true,
      "isPatchable": false,
      "exploitMaturity": "proof-of-concept"
    }
  ]
}
```

### Severity Levels

- **Critical**: CVSS 9.0-10.0 (Immediate action required)
- **High**: CVSS 7.0-8.9 (High priority fixes)
- **Medium**: CVSS 4.0-6.9 (Important but not urgent)
- **Low**: CVSS 0.1-3.9 (Informational)

### Exploit Maturity

- **Mature**: Reliable exploit exists
- **Proof of Concept**: PoC code available
- **No Known Exploit**: Theoretical vulnerability
- **No Data**: Insufficient information

## 🛡️ Advanced Features

### 1. **Policy Management**

Create `.snyk` file for custom policies:

```yaml
# .snyk
version: v1.0.0
ignore:
  SNYK-PYTHON-REQUESTS-174003:
    - "*":
        reason: False positive in our use case
        expires: "2024-12-31T23:59:59.999Z"

patch:
  SNYK-PYTHON-FLASK-40388:
    - Flask:
        patched: "2023-08-27T10:05:30.000Z"
```

### 2. **License Compliance**

```bash
# Check for license issues
snyk test --license

# Set license policy
snyk test --license --severity-threshold=medium
```

### 3. **Container Scanning**

```bash
# Scan Docker image
snyk container test python:3.11-slim

# Test Dockerfile
snyk container test --file=Dockerfile python:3.11-slim
```

## 🚀 Remediation Strategies

### 1. **Automatic Upgrades**

```bash
# Show available upgrades
snyk test --print-deps

# Apply automatic upgrades
snyk wizard

# Generate fix PR (GitHub integration)
snyk fix
```

### 2. **Manual Remediation**

```python
# Create requirements-secure.txt with fixed versions
Flask>=1.1.4
requests>=2.25.1
urllib3>=1.26.5
cryptography>=3.3.2
```

### 3. **Alternative Packages**

```txt
# Replace vulnerable packages
# Instead of: pycrypto (unmaintained)
pycryptodome>=3.9.0

# Instead of: yaml (unsafe)
PyYAML>=5.1
```

## 🔄 Continuous Monitoring

### 1. **Webhook Integration**

```json
{
  "url": "https://api.github.com/repos/owner/repo/issues",
  "format": "github",
  "filters": {
    "severity": ["high", "critical"],
    "exploit": ["mature", "proof-of-concept"]
  }
}
```

### 2. **Scheduled Scans**

```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on:
  schedule:
    - cron: "0 2 * * 1" # Weekly Monday 2 AM

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Snyk
        uses: snyk/actions/python@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
```

## 🎯 Best Practices

### 1. **Dependency Management**

- Pin versions in production
- Regular dependency updates
- Use virtual environments
- Document security decisions

### 2. **Vulnerability Response**

- Prioritize by CVSS score and exploit maturity
- Test patches in staging first
- Maintain security backlog
- Document exceptions

### 3. **Integration Tips**

- Set appropriate severity thresholds
- Use ignore policies judiciously
- Monitor trends over time
- Automate where possible

## 🔗 Useful Resources

- [Snyk Documentation](https://docs.snyk.io/)
- [Vulnerability Database](https://snyk.io/vuln/)
- [CLI Reference](https://docs.snyk.io/snyk-cli)
- [GitHub Integration](https://docs.snyk.io/integrations/git-repository-scm-integrations/github-integration)
