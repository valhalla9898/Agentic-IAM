# Agentic-IAM

[![GitHub License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Status](https://img.shields.io/badge/status-production--ready-brightgreen.svg)](#status)
[![CI](https://github.com/valhalla9898/Agentic-IAM/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/valhalla9898/Agentic-IAM/actions/workflows/ci.yml)
[![E2E](https://github.com/valhalla9898/Agentic-IAM/actions/workflows/playwright-e2e.yml/badge.svg?branch=main)](https://github.com/valhalla9898/Agentic-IAM/actions/workflows/playwright-e2e.yml)
[![Security Scan](https://github.com/valhalla9898/Agentic-IAM/actions/workflows/security.yml/badge.svg?branch=main)](https://github.com/valhalla9898/Agentic-IAM/actions/workflows/security.yml)
[![AI CLI Smoke](https://github.com/valhalla9898/Agentic-IAM/actions/workflows/ai-cli-smoke.yml/badge.svg?branch=main)](https://github.com/valhalla9898/Agentic-IAM/actions/workflows/ai-cli-smoke.yml)
[![Pre-commit](https://github.com/valhalla9898/Agentic-IAM/actions/workflows/pre-commit.yml/badge.svg?branch=main)](https://github.com/valhalla9898/Agentic-IAM/actions/workflows/pre-commit.yml)

## 📋 Overview

**Agentic-IAM** is an enterprise-grade Identity and Access Management (IAM) platform purpose-built for AI agent ecosystems. It provides comprehensive authentication, authorization, federation, and credential management capabilities with built-in security controls, audit logging, and compliance features.

### Key Capabilities
- **Agent Identity Management**: Secure identity provisioning and lifecycle management for AI agents
- **Multi-Protocol Authentication**: Support for mTLS, OAuth 2.0, federated identity
- **Fine-Grained Authorization**: Role-based and attribute-based access control (RBAC/ABAC)
- **Transport Security**: Mutual TLS, encrypted credential storage, quantum-ready cryptography
- **Audit & Compliance**: Comprehensive audit logging, compliance reporting, incident detection
- **AI-Powered Assistance**: AI CLI with knowledge base and cloud model support
- **Dashboard Interface**: Intuitive Streamlit-based administration UI
- **GraphQL API**: Modern API for programmatic access and integrations

---

## ✅ Production Status

- **Status**: Production-ready baseline (verified April 2026)
- **Test Coverage**: 88 tests passing (unit + integration + E2E)
- **Critical Issues**: 0 remaining
- **CI/CD**: Full automation with linting, testing, security scanning, and E2E validation
- **Code Quality**: Pydantic V2 compliant, async/await lifecycle management

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- PowerShell 5.1 or Command Prompt (Windows)
- Git (for version control)

### Installation & Running (Windows)

#### Option 1: Using Virtual Environment (Recommended)
```bash
# 1. Clone the repository
git clone https://github.com/valhalla9898/Agentic-IAM.git
cd Agentic-IAM

# 2. Create virtual environment
python -m venv .venv

# 3. Activate virtual environment
.venv\Scripts\activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Run the dashboard
python run_gui.py

# 6. Open your browser
# Navigate to http://localhost:8501
```

#### Option 2: Using Quick Start Scripts
```bash
# PowerShell
.\setup_venv.ps1
.\LAUNCHER.ps1

# Command Prompt
setup_venv.bat
LAUNCHER.bat
```

### Demo Credentials
Test the dashboard with these built-in accounts:
- **Admin Account**: Username: `admin` | Password: `admin123`
- **Operator Account**: Username: `operator` | Password: `operator123`
- **User Account**: Username: `user` | Password: `user123`

---

## 🤖 AI Assistant CLI

Agentic-IAM includes an intelligent AI assistant for answering questions about the platform.

### Usage

#### Using Package CLI (if installed)
```bash
agentic-iam-ai "How to enable mTLS?"
```

#### Using PowerShell
```powershell
.\ask_ai.ps1 "How to enable mTLS?"
```

#### Using Command Prompt
```batch
ask_ai.bat "How to enable mTLS?"
```

#### Using Python Directly
```bash
python scripts/ask_ai.py "Your question here"
```

### Configuration Modes

```bash
# Local knowledge base (default)
agentic-iam-ai "Question" --model knowledge

# ChatGPT integration (requires OPENAI_API_KEY environment variable)
agentic-iam-ai "Question" --model openai:gpt-3.5-turbo

# Using environment variable
set OPENAI_API_KEY=your_api_key_here
agentic-iam-ai "Question" --model openai:gpt-3.5-turbo
```

---

## 📊 Web Dashboard

### Accessing the Dashboard
Once `python run_gui.py` is running, open your browser to `http://localhost:8501`

### Features
- **User Management**: Create, update, and manage user accounts
- **Agent Management**: Register, configure, and monitor AI agents
- **Access Control**: Define roles and permissions
- **Audit Logs**: View comprehensive audit trail of all system activities
- **Security Events**: Monitor risk levels and security incidents
- **Real-time Status**: View live system status and performance metrics

### API Documentation
Swagger/OpenAPI documentation available at `http://localhost:8000/docs` (when API server is running)

---

## ✨ Quality Assurance

### Running Tests Locally

#### Full Quality Gate (Recommended)
Runs unit tests, integration tests, and end-to-end tests:
```bash
python scripts/check_all.py
```

#### Quick Quality Gate (Skip E2E)
Runs only unit and integration tests:
```bash
python scripts/check_all.py --quick
```

#### Using PowerShell
```powershell
.\check_all.ps1
```

### Running Specific Test Categories
```bash
# Unit tests only
pytest tests/test_unit -q

# Integration tests only
pytest tests/test_integration -q

# End-to-end tests only
pytest tests/test_e2e -q

# All tests with verbose output
pytest tests -v
```

---

## 📦 Dependency Management

### Standard Installation
Install dependencies from `requirements.txt`:
```bash
pip install -r requirements.txt
```

### Reproducible Installations (Pinned Versions)
For consistent environments across machines and CI/CD:
```bash
pip install -r requirements-lock.txt
```

### Updating Lockfile
After modifying dependencies, refresh the lockfile:
```bash
python scripts/update_lockfile.py
```

---

## 🔍 Code Quality & Pre-commit Hooks

### Setting Up Pre-commit
Pre-commit hooks automatically validate code before commits:
```bash
# Install hooks
pre-commit install

# Run on all files (before first commit)
pre-commit run --all-files
```

### What Pre-commit Checks
- Code formatting and style (flake8)
- Python syntax validation
- YAML/JSON formatting
- Secret detection
- Trailing whitespace

---

## 📚 Documentation

### Quick References
- **[RUNBOOK.md](RUNBOOK.md)** - Step-by-step deployment guide
- **[QUICK_START.md](QUICK_START.md)** - Quick setup instructions
- **[CHANGELOG_LATEST.md](CHANGELOG_LATEST.md)** - Latest changes and fixes

### Comprehensive Guides
- **[docs/README_DETAILED.md](docs/README_DETAILED.md)** - Complete project documentation
- **[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)** - Development and contribution guidelines
- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** - System architecture overview

### Project Documentation
- **[START_HERE.md](START_HERE.md)** - Project overview and quick links
- **[ARCHITECTURE_DIAGRAM.md](ARCHITECTURE_DIAGRAM.md)** - Visual system architecture

---

## 🔧 API Reference

### REST API
When the application is running, access the interactive API documentation:
- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`

### Health Check Endpoints
```bash
# Service health
curl http://localhost:8000/health/

# Readiness probe
curl http://localhost:8000/health/ready

# Liveness probe
curl http://localhost:8000/health/live
```

### GraphQL API
GraphQL endpoint available at `/graphql` when server is running.

---

## 🐳 Docker Support

### Building Docker Image
```bash
# Development image
docker build -f Dockerfile -t agentic-iam:latest .

# Production image
docker build -f Dockerfile.prod -t agentic-iam:prod .
```

### Running with Docker
```bash
# Development
docker run -p 8501:8501 -p 8000:8000 agentic-iam:latest

# Production
docker run -p 8501:8501 -p 8000:8000 agentic-iam:prod
```

### Docker Compose
```bash
# Start all services
docker-compose up

# Stop all services
docker-compose down

# View logs
docker-compose logs -f
```

---

## 🔒 Security Features

### Built-in Security Controls
- **Mutual TLS (mTLS)**: Secure agent-to-platform communication
- **Encrypted Storage**: Credentials and sensitive data encrypted at rest
- **Quantum-Ready Cryptography**: Post-quantum algorithm support
- **Role-Based Access Control (RBAC)**: Fine-grained permission management
- **Audit Logging**: Comprehensive security event tracking
- **Federated Identity**: Support for multi-cloud identity federation
- **Session Management**: Secure session lifecycle and timeout handling

### Security Best Practices
1. Change default credentials before production deployment
2. Enable mTLS for all agent communications
3. Regularly review audit logs for security events
4. Keep dependencies updated using `pip install -r requirements-lock.txt`
5. Use environment variables for sensitive configuration

---

## 🤝 Contributing

### Development Workflow
1. Create a feature branch: `git checkout -b feature/your-feature`
2. Make your changes and ensure tests pass: `python scripts/check_all.py`
3. Commit with clear messages: `git commit -m "Add feature description"`
4. Push to your fork: `git push origin feature/your-feature`
5. Submit a pull request with description

### Code Standards
- Follow PEP 8 style guidelines
- Write unit tests for new functionality
- Update documentation for changes
- Ensure all tests pass before submitting PR
- Use type hints for better code clarity

---

## 🐛 Troubleshooting

### Common Issues

#### Virtual Environment Not Activating
```bash
# Verify Python is installed
python --version

# Try explicit activation
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
.venv\Scripts\Activate.ps1
```

#### Dependencies Installation Fails
```bash
# Upgrade pip first
python -m pip install --upgrade pip

# Clear pip cache
pip cache purge

# Retry installation
pip install -r requirements.txt
```

#### Dashboard Not Accessible
```bash
# Verify the service is running
# Check http://localhost:8501

# View application logs for errors
python run_gui.py  # Run with verbose output
```

#### AI CLI Fails with Model Mode
```bash
# Ensure OPENAI_API_KEY is set
set OPENAI_API_KEY=your_key_here

# Retry the command
agentic-iam-ai "Your question"

# If still failing, use local knowledge mode
agentic-iam-ai "Your question" --model knowledge
```

#### Tests Fail Locally
```bash
# Run with verbose output
pytest tests -v

# Run single test for debugging
pytest tests/test_unit/test_authentication.py -v

# Check for environment issues
python -m pytest --co  # Collect tests without running
```

---

## 📋 System Requirements

### Minimum Specifications
- **OS**: Windows 10/11, macOS 10.14+, or Linux (Ubuntu 18.04+)
- **Python**: 3.8 or higher
- **RAM**: 2 GB minimum (4 GB recommended)
- **Storage**: 500 MB for installation and dependencies
- **Network**: Internet connection for AI cloud features

### Recommended Specifications
- **Python**: 3.10 or 3.11
- **RAM**: 8 GB
- **Storage**: 2 GB (with full test suite and documentation)
- **CPU**: Multi-core processor for optimal performance

---

## 📄 License

Agentic-IAM is licensed under the **MIT License**. See [LICENSE](LICENSE) file for details.

For commercial use, licensing inquiries, or questions, please contact the project maintainers.

---

## 📞 Support & Community

### Getting Help
- **Documentation**: See [docs/README_DETAILED.md](docs/README_DETAILED.md) for comprehensive guides
- **Issues**: Report bugs and feature requests on GitHub Issues
- **Discussions**: Use GitHub Discussions for questions and community support

### Feedback & Contributions
We welcome feedback, bug reports, and contributions from the community. Please see [CONTRIBUTING.md](CONTRIBUTING.md) (or contributing guidelines in [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)).

---

## 🎯 Project History

**Agentic-IAM** was developed as an enterprise-grade solution for securing AI agent ecosystems with production-ready IAM capabilities. The project has undergone extensive testing, security audits, and optimization to ensure reliability in critical deployments.

### Key Milestones
- ✅ Initial IAM core implementation
- ✅ GUI dashboard with Streamlit
- ✅ Comprehensive test suite (88 tests)
- ✅ Production deployment readiness (April 2026)
- ✅ All critical vulnerabilities resolved
- ✅ Full Pydantic V2 migration
- ✅ Enhanced agent lifecycle management

---

**Last Updated**: April 7, 2026 | **Version**: 1.0.0-production
