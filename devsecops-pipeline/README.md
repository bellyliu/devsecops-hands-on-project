# DevSecOps CI/CD Pipeline

A comprehensive DevSecOps CI/CD pipeline implementation using GitHub Actions for a Python Flask application. This project demonstrates the integration of security scanning tools including Static Application Security Testing (SAST), Software Composition Analysis (SCA), and container vulnerability scanning.

## 🏗️ Project Overview

This project showcases a complete DevSecOps pipeline that includes:

- **Application**: A simple Python Flask "Hello World" web application
- **CI/CD Pipeline**: GitHub Actions workflow with multiple security checkpoints
- **Security Integration**:
  - **SAST**: SonarQube for static code analysis
  - **SCA**: Snyk for dependency vulnerability scanning
  - **Container Scanning**: Trivy and Docker Scout for container security
- **Quality Gates**: Automated code quality checks and security validations

## 📁 Project Structure

```
devsecops-pipeline/
├── .github/
│   └── workflows/
│       └── security-pipeline.yml    # Main CI/CD pipeline
├── app.py                           # Flask application
├── requirements.txt                 # Python dependencies
├── Dockerfile                       # Container configuration
├── test_app.py                     # Unit tests
├── sonar-project.properties        # SonarQube configuration
├── pyproject.toml                  # Python project configuration
├── .gitignore                      # Git ignore rules
└── README.md                       # This file
```

## 🚀 Pipeline Stages

The CI/CD pipeline consists of five main stages:

### 1. **Lint & Test**

- Code formatting validation (Black, isort)
- Static code analysis (flake8)
- Unit test execution with pytest
- Test result artifact upload

### 2. **SAST - SonarQube Analysis**

- Static Application Security Testing
- Code quality and security vulnerability detection
- Coverage report generation
- Quality gate validation

### 3. **SCA - Snyk Vulnerability Scan**

- Software Composition Analysis
- Dependency vulnerability scanning
- SARIF report generation for GitHub Security tab
- High severity threshold enforcement

### 4. **Build & Scan Container**

- Multi-platform Docker image build (AMD64/ARM64)
- Container vulnerability scanning with Trivy
- Docker Scout security analysis
- Image registry push (GitHub Container Registry)

### 5. **Security Summary**

- Consolidated security report generation
- Pipeline status summary
- Artifact collection and organization

## 🛠️ Local Setup Guide

### Prerequisites

- Python 3.11+
- Docker
- Git

### Running the Application Locally

1. **Clone the repository:**

   ```bash
   git clone <your-repo-url>
   cd devsecops-pipeline
   ```

2. **Set up Python environment:**

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Run the application:**

   ```bash
   python app.py
   ```

   The application will be available at `http://localhost:5000`

4. **Run tests:**
   ```bash
   python -m pytest test_app.py -v
   ```

### Running with Docker

1. **Build the Docker image:**

   ```bash
   docker build -t flask-app .
   ```

2. **Run the container:**
   ```bash
   docker run -p 5000:5000 flask-app
   ```

### Local SonarQube Setup

To run SonarQube locally for development and testing:

1. **Start SonarQube using Docker:**

   ```bash
   docker run -d --name sonarqube \
     -p 9000:9000 \
     -e SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true \
     sonarqube:latest
   ```

2. **Access SonarQube:**

   - Open `http://localhost:9000` in your browser
   - Default credentials: `admin/admin`
   - You'll be prompted to change the password on first login

3. **Create a new project:**

   - Click "Create Project" → "Manually"
   - Project key: `devsecops-pipeline`
   - Display name: `DevSecOps Pipeline Flask App`
   - Generate a token for the project

4. **Run local analysis:**

   ```bash
   # Install SonarQube Scanner
   # On macOS:
   brew install sonar-scanner

   # On Linux:
   # Download from https://docs.sonarqube.org/latest/analysis/scan/sonarscanner/

   # Run analysis
   sonar-scanner \
     -Dsonar.projectKey=devsecops-pipeline \
     -Dsonar.sources=. \
     -Dsonar.host.url=http://localhost:9000 \
     -Dsonar.login=<your-generated-token>
   ```

## ⚙️ CI/CD Setup

### Required GitHub Repository Secrets

To run the complete pipeline, configure the following secrets in your GitHub repository (`Settings` → `Secrets and variables` → `Actions`):

#### 1. SonarQube Configuration

**`SONAR_HOST_URL`**

- **Value**: Your SonarQube server URL
- **Examples**:
  - SonarCloud: `https://sonarcloud.io`
  - Self-hosted: `https://your-sonarqube-instance.com`
  - Local development: `http://localhost:9000`

**`SONAR_TOKEN`**

- **How to get**:
  1. Log in to your SonarQube instance
  2. Go to `My Account` → `Security` → `Generate Tokens`
  3. Create a token with appropriate permissions
  4. Copy the generated token

#### 2. Snyk Configuration

**`SNYK_TOKEN`**

- **How to get**:
  1. Sign up for a free account at [snyk.io](https://snyk.io)
  2. Go to `Account Settings` → `API Token`
  3. Copy your API token
  4. Or run `snyk auth` in CLI and copy from `~/.config/configstore/snyk.json`

### Setting up SonarQube

#### Option 1: SonarCloud (Recommended for GitHub projects)

1. **Sign up for SonarCloud:**

   - Go to [sonarcloud.io](https://sonarcloud.io)
   - Sign in with your GitHub account
   - Import your repository

2. **Configure the project:**
   - Set `SONAR_HOST_URL` to `https://sonarcloud.io`
   - Generate and set the `SONAR_TOKEN`

#### Option 2: Self-hosted SonarQube

1. **Deploy SonarQube:**

   ```bash
   # Using Docker Compose (production setup)
   version: '3'
   services:
     sonarqube:
       image: sonarqube:latest
       ports:
         - "9000:9000"
       environment:
         - SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true
       volumes:
         - sonarqube_data:/opt/sonarqube/data
         - sonarqube_logs:/opt/sonarqube/logs
         - sonarqube_extensions:/opt/sonarqube/extensions

   volumes:
     sonarqube_data:
     sonarqube_logs:
     sonarqube_extensions:
   ```

2. **Configure secrets:**
   - Set `SONAR_HOST_URL` to your instance URL
   - Generate and set the `SONAR_TOKEN`

### Setting up Snyk

1. **Create Snyk account:**

   - Sign up at [snyk.io](https://snyk.io)
   - Connect your GitHub account

2. **Get API token:**
   - Navigate to Account Settings
   - Copy your API token
   - Set as `SNYK_TOKEN` secret

### Container Registry Setup

The pipeline uses GitHub Container Registry (ghcr.io) by default, which requires no additional setup for public repositories. For private repositories, ensure the `GITHUB_TOKEN` has appropriate permissions.

## 🔒 Security Features

### Static Application Security Testing (SAST)

- **Tool**: SonarQube
- **Scans**: Code quality, security hotspots, vulnerabilities
- **Integration**: Quality gates prevent merge on security issues

### Software Composition Analysis (SCA)

- **Tool**: Snyk
- **Scans**: Known vulnerabilities in dependencies
- **Integration**: SARIF upload to GitHub Security tab

### Container Security Scanning

- **Tools**: Trivy, Docker Scout
- **Scans**: Base image vulnerabilities, misconfigurations
- **Integration**: Multi-platform scanning, SARIF reports

### Additional Security Features

- **Non-root container user**: Dockerfile uses dedicated app user
- **Minimal base image**: Python slim image reduces attack surface
- **Health checks**: Container health monitoring
- **Security headers**: Can be extended with Flask-Security

## 📊 Monitoring and Reporting

The pipeline provides comprehensive reporting:

- **GitHub Security Tab**: Centralized vulnerability dashboard
- **Artifacts**: Downloadable security reports
- **Step Summary**: Pipeline status overview
- **Quality Gates**: Automated pass/fail decisions

## 🚀 Deployment

The pipeline builds and pushes multi-platform container images to GitHub Container Registry. To deploy:

```bash
# Pull the latest image
docker pull ghcr.io/your-username/your-repo/flask-app:latest

# Run in production
docker run -d \
  --name flask-app-prod \
  -p 80:5000 \
  --restart unless-stopped \
  ghcr.io/your-username/your-repo/flask-app:latest
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Ensure all security scans pass
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🛡️ Security

For security concerns, please email security@yourcompany.com instead of opening a public issue.

## 📚 Additional Resources

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [SonarQube Documentation](https://docs.sonarqube.org/)
- [Snyk Documentation](https://docs.snyk.io/)
- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [OWASP DevSecOps Guidelines](https://owasp.org/www-project-devsecops-guideline/)
