# SonarQube - Static Application Security Testing (SAST)

## 🔍 What is SonarQube?

SonarQube is a leading open-source platform for static code analysis that helps developers write cleaner, safer code. It performs Static Application Security Testing (SAST) by analyzing source code without executing it, identifying security vulnerabilities, code smells, bugs, and technical debt.

## 🛠️ How SonarQube Works

### 1. **Code Analysis Process**

```
Source Code → SonarQube Scanner → Analysis Engine → Quality Gate → Report
```

1. **Scanner Collection**: The SonarQube scanner collects source code files
2. **Static Analysis**: Code is analyzed using predefined rules and patterns
3. **Rule Engine**: Applies security, reliability, and maintainability rules
4. **Quality Gate**: Evaluates if code meets defined quality standards
5. **Reporting**: Generates detailed reports with issues and metrics

### 2. **Analysis Types**

- **Security Hotspots**: Potential security vulnerabilities requiring review
- **Security Vulnerabilities**: Confirmed security issues (OWASP Top 10)
- **Code Smells**: Maintainability issues that increase technical debt
- **Bugs**: Reliability issues that could cause unexpected behavior
- **Coverage**: Test coverage analysis and gaps

### 3. **Quality Gates**

Quality Gates are checkpoints that prevent poor-quality code from being deployed:

- **Pass**: Code meets all defined criteria
- **Fail**: Code has critical issues that must be fixed
- **Customizable**: Set thresholds for different metrics

## 🚨 Common Vulnerabilities Detected

### 1. **SQL Injection (CWE-89)**

**Example - Vulnerable Code:**

```python
# ❌ BAD: SQL Injection vulnerability
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()
```

**SonarQube Detection:**

```
Security Hotspot: SQL queries should not be vulnerable to injection attacks
- Severity: CRITICAL
- Rule: python:S2077
- Location: Line 3
- Description: User input is directly concatenated into SQL query
```

**How to Fix:**

```python
# ✅ GOOD: Using parameterized queries
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = %s"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()
```

### 2. **Cross-Site Scripting (XSS) - CWE-79**

**Example - Vulnerable Code:**

```python
# ❌ BAD: XSS vulnerability
from flask import Flask, request, render_template_string

@app.route('/hello')
def hello():
    name = request.args.get('name', '')
    return f"<h1>Hello {name}!</h1>"  # Direct HTML output
```

**SonarQube Detection:**

```
Security Vulnerability: XSS vulnerability due to unescaped user input
- Severity: HIGH
- Rule: python:S5131
- Location: Line 6
- Description: User input directly rendered in HTML without escaping
```

**How to Fix:**

```python
# ✅ GOOD: Using proper escaping
from flask import Flask, request, escape

@app.route('/hello')
def hello():
    name = request.args.get('name', '')
    return f"<h1>Hello {escape(name)}!</h1>"
```

### 3. **Hard-coded Credentials (CWE-798)**

**Example - Vulnerable Code:**

```python
# ❌ BAD: Hard-coded credentials
DATABASE_PASSWORD = "admin123"
API_KEY = "sk-1234567890abcdef"

def connect_db():
    return connect(
        host="localhost",
        user="admin",
        password="admin123"  # Hard-coded password
    )
```

**SonarQube Detection:**

```
Security Vulnerability: Hard-coded credentials should not be used
- Severity: CRITICAL
- Rule: python:S2068
- Location: Line 2-3, 8
- Description: Passwords and API keys should not be hard-coded
```

**How to Fix:**

```python
# ✅ GOOD: Using environment variables
import os

DATABASE_PASSWORD = os.getenv('DATABASE_PASSWORD')
API_KEY = os.getenv('API_KEY')

def connect_db():
    return connect(
        host=os.getenv('DB_HOST', 'localhost'),
        user=os.getenv('DB_USER'),
        password=os.getenv('DATABASE_PASSWORD')
    )
```

### 4. **Weak Cryptography (CWE-327)**

**Example - Vulnerable Code:**

```python
# ❌ BAD: Using weak hashing algorithm
import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # MD5 is weak
```

**SonarQube Detection:**

```
Security Vulnerability: Weak cryptographic hash functions should not be used
- Severity: HIGH
- Rule: python:S4790
- Location: Line 5
- Description: MD5 is cryptographically broken and unsuitable for further use
```

**How to Fix:**

```python
# ✅ GOOD: Using strong hashing with salt
import bcrypt

def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt)

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed)
```

## 🔧 Pipeline Integration Example

### GitHub Actions Integration

```yaml
- name: SonarQube Scan
  uses: sonarqube-quality-gate-action@master
  env:
    SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
    SONAR_HOST_URL: ${{ secrets.SONAR_HOST_URL }}
  with:
    projectBaseDir: .
    args: >
      -Dsonar.projectKey=my-project
      -Dsonar.sources=.
      -Dsonar.exclusions=**/*test*/**
      -Dsonar.python.coverage.reportPaths=coverage.xml
```

### Expected Pipeline Failure

```
Quality Gate Status: FAILED
Issues Found:
- 3 Security Vulnerabilities (HIGH)
- 1 Security Hotspot (CRITICAL)
- 12 Code Smells (MEDIUM)
- Coverage: 65% (Below threshold of 80%)

Blocking Issues:
1. SQL Injection vulnerability in user_service.py:42
2. Hard-coded password in config.py:15
3. XSS vulnerability in templates/user.html:23
```

## 🛠️ Local Setup and Testing

### 1. **Docker Setup**

```bash
# Start SonarQube server
docker run -d --name sonarqube \
  -p 9000:9000 \
  -e SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true \
  sonarqube:latest

# Access at http://localhost:9000
# Default credentials: admin/admin
```

### 2. **Project Configuration**

```properties
# sonar-project.properties
sonar.projectKey=my-python-project
sonar.projectName=My Python Project
sonar.projectVersion=1.0.0
sonar.sources=.
sonar.exclusions=**/*test*/**,**/venv/**
sonar.python.coverage.reportPaths=coverage.xml
sonar.qualitygate.wait=true
```

### 3. **Local Scanning**

```bash
# Install scanner
brew install sonar-scanner  # macOS
# or download from https://docs.sonarqube.org/latest/analysis/scan/sonarscanner/

# Run analysis
sonar-scanner \
  -Dsonar.projectKey=my-project \
  -Dsonar.sources=. \
  -Dsonar.host.url=http://localhost:9000 \
  -Dsonar.login=your-token
```

## 📊 Understanding Reports

### Quality Gate Conditions

```
Security Rating: A (0 vulnerabilities)
Reliability Rating: B (1-5 bugs)
Maintainability Rating: C (6-10 code smells)
Coverage: 85% (meets 80% threshold)
Duplicated Lines: 2% (below 3% threshold)
```

### Security Rating Scale

- **A**: 0 security vulnerabilities
- **B**: 1+ minor vulnerabilities
- **C**: 1+ major vulnerabilities
- **D**: 1+ critical vulnerabilities
- **E**: 1+ blocker vulnerabilities

## 🚀 Best Practices

### 1. **Quality Gate Configuration**

```
New Code:
- Security Rating: A
- Reliability Rating: A
- Maintainability Rating: A
- Coverage on New Code: >= 80%
- Duplicated Lines on New Code: < 3%
```

### 2. **Rule Customization**

- Enable security-focused rule sets
- Configure custom rules for your tech stack
- Set appropriate severity levels
- Regular rule updates

### 3. **Integration Tips**

- Run analysis on every commit
- Block merges that fail quality gates
- Monitor security hotspots regularly
- Track technical debt trends

## 🔗 Useful Resources

- [SonarQube Documentation](https://docs.sonarqube.org/)
- [Python Security Rules](https://rules.sonarsource.com/python/type/Security%20Hotspot)
- [Quality Gate Setup](https://docs.sonarqube.org/latest/user-guide/quality-gates/)
- [SonarCloud](https://sonarcloud.io) - Cloud version for public repositories
