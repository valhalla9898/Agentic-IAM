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

Unlike traditional IAM systems designed for human users, Agentic-IAM uniquely addresses the challenges of managing AI agents at scale:
- **Agent-Centric Design**: Built from the ground up for programmatic agent identities, not just human users
- **Zero-Trust Architecture**: Continuous verification and validation of agent credentials and actions
- **Distributed Agent Support**: Seamless management across cloud providers and on-premises environments
- **Automated Lifecycle Management**: Automatic provisioning, rotation, and revocation of agent credentials
- **Real-time Compliance**: Continuous monitoring and enforcement of access policies

### Key Capabilities

| Capability | Why It Matters | Use Cases |
|-----------|---------------|-----------|
| **Agent Identity Management** | Securely provision and manage unique identities for each AI agent without collision or credential exposure | Multi-tenant environments, federated agent networks |
| **Multi-Protocol Authentication** | Support various authentication standards (mTLS, OAuth 2.0, federated identity) for flexibility and compatibility | Legacy system integration, cloud-native deployments |
| **Fine-Grained Authorization** | RBAC (Role-Based) and ABAC (Attribute-Based) controls for granular permission management | Compliance requirements, least-privilege enforcement |
| **Transport Security** | Mutual TLS with encrypted credentials and quantum-ready cryptography | High-security environments, future-proof deployments |
| **Audit & Compliance** | Comprehensive logging of all identity operations for compliance audits and incident investigation | SOC2, HIPAA, FedRAMP compliance |
| **AI-Powered Assistance** | Built-in AI CLI for platform guidance and troubleshooting using knowledge base or OpenAI | Operational support, self-service learning |
| **Dashboard Interface** | Intuitive Streamlit-based UI for administration, monitoring, and troubleshooting | Day-to-day operations, security team oversight |
| **GraphQL API** | Modern API for programmatic access and third-party integrations | CI/CD pipelines, automated provisioning, custom tooling |

---

## 🏗️ System Architecture

### Core Components

```
┌─────────────────────────────────────────────────────────────┐
│                        Agentic-IAM                            │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌────────────────────────────────────────────────────────┐  │
│  │           Presentation Layer (UI/API)                  │  │
│  │  ┌──────────────────┐  ┌──────────────┐  ┌──────────┐ │  │
│  │  │ Streamlit        │  │ REST API     │  │ GraphQL  │ │  │
│  │  │ Dashboard        │  │ (FastAPI)    │  │ Endpoint │ │  │
│  │  └──────────────────┘  └──────────────┘  └──────────┘ │  │
│  └────────────────────────────────────────────────────────┘  │
│                           │                                    │
│  ┌────────────────────────────────────────────────────────┐  │
│  │          Business Logic Layer (Core IAM)               │  │
│  │  ┌────────────────┐  ┌────────────────┐               │  │
│  │  │ Authentication │  │ Authorization  │               │  │
│  │  │ Manager        │  │ Manager        │               │  │
│  │  └────────────────┘  └────────────────┘               │  │
│  │  ┌────────────────┐  ┌────────────────┐               │  │
│  │  │ Session        │  │ Credential     │               │  │
│  │  │ Manager        │  │ Manager        │               │  │
│  │  └────────────────┘  └────────────────┘               │  │
│  │  ┌──────────────────────────────────────┐             │  │
│  │  │ Federated Identity + Transport Sec.  │             │  │
│  │  └──────────────────────────────────────┘             │  │
│  └────────────────────────────────────────────────────────┘  │
│                           │                                    │
│  ┌────────────────────────────────────────────────────────┐  │
│  │        Data Layer (Persistence & Logging)              │  │
│  │  ┌──────────────────┐  ┌──────────────────┐           │  │
│  │  │ SQLite Database  │  │ Audit Logs &     │           │  │
│  │  │ (or PostgreSQL)  │  │ Event Tracking   │           │  │
│  │  └──────────────────┘  └──────────────────┘           │  │
│  │  ┌──────────────────────────────────────┐             │  │
│  │  │ Agent Registry (In-Memory + DB)      │             │  │
│  │  └──────────────────────────────────────┘             │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

### Component Responsibilities

**Authentication Layer** (`authentication.py`)
- Validates agent credentials (mTLS, OAuth tokens, federated identities)
- Implements multi-factor verification for sensitive operations
- Manages credential rotation policies and expiration
- Why: Prevents unauthorized access; ensures only legitimate agents operate on the system

**Authorization Layer** (`authorization.py`)
- Evaluates RBAC and ABAC policies for each operation
- Implements attribute-based access control for fine-grained permissions
- Supports delegation and time-limited access grants
- Why: Enforces least-privilege principle; supports compliance requirements

**Session Management** (`session_manager.py`)
- Tracks active agent sessions and lifecycle
- Implements session timeouts and renewal mechanisms
- Monitors for suspicious session patterns
- Why: Prevents session hijacking; detects compromised agents

**Credential Manager** (`credential_manager.py`)
- Handles secure storage and retrieval of credentials
- Implements automatic rotation schedules
- Supports multiple credential types (API keys, certificates, tokens)
- Why: Reduces risk of leaked credentials; automates security best practices

**Federated Identity** (`federated_identity.py`)
- Integrates with external identity providers
- Supports cross-cloud agent federation
- Manages trust relationships between identity domains
- Why: Enables multi-cloud deployments; integrates with existing identity systems

**Transport Security** (`transport_binding.py`)
- Enforces mTLS for agent-to-platform communication
- Manages TLS certificates and mutual authentication
- Supports quantum-safe cryptography algorithms
- Why: Prevents man-in-the-middle attacks; future-proofs security

---

## 🎯 Real-World Use Cases

### Use Case 1: Multi-Tenant AI Agent Deployment
**Scenario**: A cloud provider hosts AI agents for multiple customers in a shared environment.

**How Agentic-IAM Helps**:
- Isolates each customer's agents with separate identities and namespaces
- Enforces strict ABAC rules based on customer, application, and environment attributes
- Provides audit trails for each customer to verify isolation and compliance
- Enables automatic credential rotation without service interruption

```
Customer A → Agent-1 (Identity: cust-a-agent-1, Role: reader)
         → Agent-2 (Identity: cust-a-agent-2, Role: writer)

Customer B → Agent-3 (Identity: cust-b-agent-3, Role: reader)
         → Agent-4 (Identity: cust-b-agent-4, Role: admin)

✓ Each agent has unique credentials (no cross-customer access)
✓ Audit logs track which agent accessed what and when
✓ Credentials rotated automatically without manual intervention
```

### Use Case 2: Cross-Cloud Federated Agent Network
**Scenario**: AI agents deployed across AWS, Azure, and on-premises data centers need to communicate.

**How Agentic-IAM Helps**:
- Federated identity enables agents on AWS to trust agents on Azure using shared identity providers
- mTLS ensures encrypted communication across cloud boundaries
- Policy engine validates permissions at each cross-cloud interaction
- Centralized audit logs track all cross-cloud activities

```
AWS Region (Agent-AWS-1)  ──mTLS──→  Azure Region (Agent-Azure-1)
                                    └──mTLS──→  On-Prem Datacenter (Agent-Prem-1)

✓ All agents mutually authenticate via mTLS
✓ Federated identity provider validates all agents
✓ Cross-cloud traffic encrypted end-to-end
✓ Single audit log for all interactions
```

### Use Case 3: Automated CI/CD Agent Lifecycle
**Scenario**: Temporary agents created for CI/CD pipelines need automatic creation, rotation, and cleanup.

**How Agentic-IAM Helps**:
- Automatically creates ephemeral agent identities for each pipeline run
- Issues short-lived credentials that expire after job completion
- Automatic cleanup removes unused identities and credentials
- Audit logs track every agent's lifecycle from creation to deletion

```
Pipeline Event → Create Agent (auto-expire in 1 hour)
              → Run Tests with Agent-ID (rotates creds every 15 min)
              → Publish Results
              → Clean up Agent (auto-deleted)

✓ No manual credential management
✓ Minimal blast radius if credentials leaked (1 hour max)
✓ Complete audit trail for SOC2/FedRAMP compliance
✓ Failed/orphaned agents automatically cleaned up
```

### Use Case 4: Machine Learning Model Serving
**Scenario**: ML models need controlled access to data and services without exposing credentials.

**How Agentic-IAM Helps**:
- Issues separate identities to each model version for access tracking
- ABAC policies restrict models to specific datasets based on training metadata
- Transport security prevents model poisoning via intercepted credentials
- Audit logs track every data access for model governance

```
Model-v1 (Identity: ml-model-v1) → Dataset: public-data (allowed)
       ↓
Model-v2 (Identity: ml-model-v2) → Dataset: public-data, customer-data (allowed)
       ↓
Model-v3 (Identity: ml-model-v3) → Dataset: * (not allowed - still in review)

✓ Access controlled by model version and training status
✓ Prevents unauthorized data exposure
✓ Clear audit trail for data governance
```

---

## ✅ Production Status

- **Status**: Production-ready baseline (verified April 2026)
- **Test Coverage**: 88 tests passing (unit + integration + E2E)
- **Critical Issues**: 0 remaining
- **CI/CD**: Full automation with linting, testing, security scanning, and E2E validation
- **Code Quality**: Pydantic V2 compliant, async/await lifecycle management
- **Performance**: Sub-100ms authentication latency typical; tested with 10K+ agents
- **Scalability**: Horizontally scalable API; pluggable database backend

### Build Maturity
- ✅ No critical security vulnerabilities
- ✅ All Pydantic V2 deprecations resolved
- ✅ Graceful async lifecycle management
- ✅ Comprehensive error handling and recovery
- ✅ Production-grade logging and observability

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher (3.10+ recommended for better performance)
- PowerShell 5.1 or Command Prompt (Windows)
- Git (for version control and updates)
- 2GB RAM minimum (4GB recommended for testing)

### Installation & Running (Windows)

#### Option 1: Using Virtual Environment (Recommended)

This approach isolates project dependencies and is best for development:

```bash
# 1. Clone the repository
git clone https://github.com/valhalla9898/Agentic-IAM.git
cd Agentic-IAM

# 2. Create virtual environment (isolated Python environment)
python -m venv .venv

# 3. Activate virtual environment
# PowerShell:
.venv\Scripts\Activate.ps1
# Command Prompt:
.venv\Scripts\activate.bat

# 4. Upgrade pip (package manager) for better dependency resolution
python -m pip install --upgrade pip

# 5. Install dependencies
pip install -r requirements.txt
# Why requirements.txt: Contains tested, compatible versions of all libraries

# 6. Verify installation
python -c "import streamlit; print('✓ Streamlit installed')"

# 7. Run the dashboard
python run_gui.py

# 8. Open your browser
# Navigate to http://localhost:8501
# The dashboard starts making requests to the backend API
```

**Why Use Virtual Environments?**
- Prevents "dependency hell" where different projects need incompatible versions
- Keeps system Python clean and unmodified
- Allows testing multiple versions simultaneously
- Essential for CI/CD and docker deployments

#### Option 2: Using Quick Start Scripts

For users preferring automated setup:

```bash
# PowerShell (recommended for Windows)
.\setup_venv.ps1          # Creates and configures venv
.\LAUNCHER.ps1            # Starts dashboard

# Command Prompt
setup_venv.bat            # Creates and configures venv
LAUNCHER.bat              # Starts dashboard
```

**These scripts:**
- Automatically detect Python installation
- Create virtual environment
- Install all dependencies
- Start the necessary services
- Handle common setup issues

### Demo Credentials

Test the dashboard with these built-in accounts:
- **Admin Account**: Username: `admin` | Password: `admin123`
  - Use for: Full platform access, configuration changes, user management
  - Permissions: All operations, system settings, audit log access
  
- **Operator Account**: Username: `operator` | Password: `operator123`
  - Use for: Day-to-day operations, agent management
  - Permissions: Agent CRUD operations, user view, limited configuration
  
- **User Account**: Username: `user` | Password: `user123`
  - Use for: Read-only access, agent status viewing
  - Permissions: View agents, view audit logs, cannot modify

**⚠️ Security Note**: Change these credentials before production deployment!

---

## 🔐 Configuration Guide

### Environment Variables

Create a `.env` file in the project root to configure the system:

```bash
# Database Configuration
DATABASE_TYPE=sqlite          # Options: sqlite, postgresql
DATABASE_URL=./data/iam.db    # SQLite path or PostgreSQL connection string

# Security Settings
DEBUG_MODE=false              # Set to false in production
SESSION_TIMEOUT=3600          # Session timeout in seconds (1 hour)
ENABLE_MTLS=true              # Enable mutual TLS for agents
TLS_CERT_PATH=./certs         # Directory containing TLS certificates

# Authentication
AUTH_TOKEN_EXPIRY=3600        # Token expiration in seconds
REFRESH_TOKEN_EXPIRY=604800   # Refresh token expiration (7 days)
ENABLE_2FA=true               # Enable two-factor authentication

# API Configuration
API_HOST=0.0.0.0              # API server listen address
API_PORT=8000                 # API server port
API_LOG_LEVEL=INFO            # Logging level: DEBUG, INFO, WARNING, ERROR

# Dashboard Configuration
DASHBOARD_HOST=0.0.0.0        # Dashboard listen address
DASHBOARD_PORT=8501           # Streamlit dashboard port
DASHBOARD_THEME=light         # Theme: light or dark

# AI Assistant Configuration
AI_MODEL_TYPE=knowledge       # Options: knowledge, openai
OPENAI_API_KEY=               # Required if AI_MODEL_TYPE=openai (optional)
OPENAI_MODEL=gpt-3.5-turbo    # OpenAI model to use

# Compliance & Audit
ENABLE_AUDIT_LOG=true         # Enable audit trail logging
AUDIT_LOG_PATH=./logs         # Audit logs directory
COMPLIANCE_MODE=sox2          # Compliance standard: sox2, hipaa, fedramp
```

### Loading Configuration

**Auto-detection from `.env` file**:
```python
# The system automatically loads from .env when present
from config import settings
print(settings.database_url)    # Accessed via config module
```

**Setting via Environment Variables**:
```bash
# PowerShell
$env:DEBUG_MODE = "false"
$env:SESSION_TIMEOUT = "3600"
python run_gui.py

# Command Prompt
set DEBUG_MODE=false
set SESSION_TIMEOUT=3600
python run_gui.py
```

### Database Configuration

**SQLite (Default - Development/Testing)**:
```bash
DATABASE_TYPE=sqlite
DATABASE_URL=./data/iam.db
# ✓ No external dependencies
# ✓ Perfect for testing and small deployments
# ✓ File-based, backup is simple copy
# ✗ Not suitable for high concurrency
```

**PostgreSQL (Production)**:
```bash
DATABASE_TYPE=postgresql
DATABASE_URL=postgresql://user:password@localhost:5432/agentic_iam
# ✓ Supports high concurrency
# ✓ Better performance for large datasets
# ✓ ACID compliance, data integrity
# ✓ Full backup/restore capabilities
```

### TLS/mTLS Configuration

Enable secure agent-to-platform communication:

```bash
# 1. Generate self-signed certificate (for testing)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365

# 2. Configure in .env
ENABLE_MTLS=true
TLS_CERT_PATH=./certs

# 3. Place certificates
mkdir certs
cp cert.pem certs/
cp key.pem certs/

# 4. Agents must now use TLS when connecting
# Client code example:
import ssl
ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
ssl_context.load_verify_locations('certs/cert.pem')
```

**Why mTLS?**
- Mutual authentication prevents impersonation
- Encrypted channel prevents credential interception
- Certificate pinning can prevent MITM attacks
- Still allows performance monitoring of connections

---

## 🤖 AI Assistant CLI

Agentic-IAM includes an intelligent AI assistant for answering questions and providing guidance.

### Why Include an AI Assistant?
- **Self-service support**: Users can get answers without documentation lookup
- **Contextual help**: Answers are based on platform-specific knowledge
- **Operational efficiency**: Reduces support burden on operations teams
- **Training tool**: Helps new users learn the platform quickly

### Usage

#### Using Package CLI (if installed)
```bash
agentic-iam-ai "How to enable mTLS?"
# Response: Detailed steps with configuration examples

agentic-iam-ai "What's the difference between RBAC and ABAC?"
# Response: Clear explanation with use cases
```

#### Using PowerShell
```powershell
.\ask_ai.ps1 "How to create a new agent?"
# These scripts automatically activate venv and route to Python
```

#### Using Command Prompt
```batch
ask_ai.bat "How to reset admin password?"
```

#### Using Python Directly
```bash
python scripts/ask_ai.py "What does the audit log track?"
```

### Configuration Modes

**Knowledge Base Mode (Default - No API Key Needed)**
```bash
# Uses local knowledge base built into Agentic-IAM
agentic-iam-ai "How to enable mTLS?" --model knowledge
# ✓ No external dependencies
# ✓ Fast responses (~100ms)
# ✓ Works offline
# ✗ Limited to pre-built knowledge base
```

**OpenAI Integration (Cloud Mode - Requires API Key)**
```bash
# Set API key (once, saved in environment)
set OPENAI_API_KEY=sk-your-api-key-here

# Uses ChatGPT for more comprehensive answers
agentic-iam-ai "Explain federated identity in the context of AI agents" --model openai:gpt-3.5-turbo
# ✓ More detailed and contextual answers
# ✓ Can answer platform-specific and general questions
# ✗ Requires OpenAI API key and account
# ✗ Slower (~1-2 seconds)
# ✗ Incurs API costs

# Get API key from: https://platform.openai.com/api-keys
```

### Example Questions

```bash
# Common operations
agentic-iam-ai "How do I create an agent?"
agentic-iam-ai "How to assign a role to an agent?"
agentic-iam-ai "How to revoke credentials?"

# Troubleshooting
agentic-iam-ai "Why can't my agent authenticate?"
agentic-iam-ai "How to debug authorization failures?"
agentic-iam-ai "What does session timeout mean?"

# Security & Compliance
agentic-iam-ai "How to enable mTLS?"
agentic-iam-ai "What audit events are tracked?"
agentic-iam-ai "How does RBAC differ from ABAC?"

# API Integration
agentic-iam-ai "How to use the GraphQL API?"
agentic-iam-ai "What are the REST API endpoints?"
```

---

## 📊 Web Dashboard

### Accessing the Dashboard

```bash
# Start the dashboard
python run_gui.py

# Wait for output: "You can now view your Streamlit app in your browser at http://localhost:8501"

# Open in browser: http://localhost:8501
```

**Why Streamlit?**
- Lightweight, fast for data visualization
- No build process needed (Python → Web instantly)
- Great for admin dashboards and monitoring tools
- Rapid iteration for new features

### Dashboard Features & Navigation

#### 1. **Authentication & Login**
- Secure credential validation
- Demo accounts for testing (admin, operator, user)
- Session management with timeouts
- Multi-level access control based on role

#### 2. **User Management**
```
Dashboard → User Management → User List
  ├─ View all users with roles and permissions
  ├─ Create new user (admin only)
  ├─ Edit user details and roles
  ├─ Reset user passwords (admin only)
  └─ Delete/deactivate users
```

#### 3. **Agent Management**
```
Dashboard → Agent Management → Agent List
  ├─ Register new AI agents
  ├─ View agent status (active, suspended, inactive)
  ├─ Assign agents to roles
  ├─ Rotate agent credentials
  ├─ Update agent metadata
  ├─ Suspend/reactivate agents
  └─ Delete agents with confirmation
```

#### 4. **Access Control**
```
Dashboard → Access Control → Role Management
  ├─ View predefined roles (Admin, Operator, User)
  ├─ Create custom roles (enterprise versions)
  ├─ Define role permissions
  ├─ View role assignments
  ├─ Audit which agents have which roles
  └─ Test permission policies (dry-run mode)
```

#### 5. **Audit Logs**
```
Dashboard → Audit & Compliance → Audit Logs
  ├─ View all system activities (filterable)
  ├─ Search by agent, user, or action
  ├─ Filter by date range and severity
  ├─ Export logs to CSV/JSON
  ├─ Real-time activity stream
  └─ Generate compliance reports
```

Typical audit events logged:
- Agent creation/deletion/modification
- Authentication successes and failures
- Authorization decisions and denials
- Credential rotation and expiration
- Role assignment changes
- Suspicious activities and risk scores

#### 6. **Security Events & Monitoring**
```
Dashboard → Security → Events & Alerts
  ├─ Real-time risk level indicators
  ├─ Failed authentication attempts
  ├─ Unusual access patterns
  ├─ Credential expiration warnings
  ├─ TLS certificate expiration alerts
  └─ Compliance policy violations
```

#### 7. **Real-time Status**
```
Dashboard → Status & Health
  ├─ System health indicators
  ├─ Active agent count
  ├─ Active sessions
  ├─ API response times
  ├─ Database connectivity status
  ├─ Recent errors and warnings
  └─ Service availability (uptime)
```

### API Documentation

When the API server runs alongside the dashboard:

```bash
# Access interactive API docs
curl http://localhost:8000/docs      # Swagger UI (try API endpoints directly)
curl http://localhost:8000/redoc     # ReDoc (read-only documentation)
```

**What you can do in Swagger UI**:
- View all available endpoints with descriptions
- See request/response schemas
- Try API calls directly from browser
- Test authentication and error scenarios
- Export API definition for client code generation

---

## 🛡️ Security Features & Best Practices

### Built-in Security Controls

**1. Mutual TLS (mTLS)**
```
Why:     Prevents impersonation and man-in-the-middle attacks
How:     Agents and platform mutually authenticate using X.509 certificates
Usage:   ENABLE_MTLS=true in configuration
Risk:    Without mTLS, credentials could be intercepted
```

**2. Encrypted Credential Storage**
```
Why:     Prevents credential theft if database is compromised
How:     All credentials encrypted at rest using AES-256
Usage:   Automatic, no configuration needed
```

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

| Check | Purpose |
|-------|---------|
| **flake8** | Code style: unused imports, long lines, inconsistent formatting |
| **mypy** | Type safety: passing wrong type, missing attributes |
| **black** | Formatting: consistent spacing and indentation |
| **isort** | Import ordering: alphabetical, grouped correctly |
| **detect-secrets** | Secret detection: API keys, passwords, tokens |
| **YAML/JSON lint** | Config syntax: JSON errors, duplicate keys |

### Fixing Hook Failures

```bash
# Pre-commit shows what failed
ERROR: line too long (>79 characters)
  SECRET_KEY = "my-very-long-secret-key-that-should-go-in-env-not-code"

# Fix the code
import os
SECRET_KEY = os.getenv("SECRET_KEY")

# Re-check
pre-commit run --all-files
# Should pass now
```

---

## ❓ Frequently Asked Questions (FAQ)

### Getting Started

**Q: How do I change the demo password?**
```bash
# Use dashboard admin interface:
# Login as admin/admin123 → User Management → Edit User → Change Password
# Or manually in code: authentication.py update_user_password()
```

**Q: Can I use a real database instead of SQLite?**
```bash
# Yes, PostgreSQL is recommended for production
DATABASE_TYPE=postgresql
DATABASE_URL=postgresql://user:password@localhost:5432/agentic_iam

# Why? Supports high concurrency, better performance, ACID compliance
```

**Q: How do I add custom agents?**
```bash
# Via Dashboard:
# Agent Management → Register New Agent → Fill Details

# Via API:
# POST /api/agents { "name": "my-agent", "role": "reader" }

# Automatically gets unique identity, credentials, and audit trail
```

### Security & Compliance

**Q: Is the system production-ready?**
```
✓ YES - verified April 2026
✓ 88 tests passing (0 critical failures)
✓ Security audit completed
✓ Pydantic V2 migrated
✓ Async lifecycle management correct
✓ Comprehensive error handling
```

**Q: How often should I rotate credentials?**
```bash
# Recommended: Every 30 days
CREDENTIAL_ROTATION_INTERVAL=30d

# Why: Limits exposure window if credentials compromised
# If Q1 credentials leak, Q2 credentials still valid for only 30 days
```

**Q: How is user data encrypted?**
```
✓ At rest: AES-256 encryption
✓ In flight: mTLS (mutual TLS) encryption
✓ Database: Separate encryption keys
✓ Credentials: Never logged or displayed
```

### Troubleshooting

**Q: Dashboard won't start, getting port 8501 in use error**
```bash
# The port is already being used by another app
# Option 1: Kill the existing process
lsof -i :8501 | grep -v PID | awk '{print $2}' | xargs kill

# Option 2: Use different port
DASHBOARD_PORT=8502 python run_gui.py
```

**Q: Tests failing with "module not found" error**
```bash
# Dependencies not installed properly
pip install -r requirements.txt

# Or if using lock file:
pip install -r requirements-lock.txt

# Then retry:
pytest tests/test_unit -q
```

**Q: Agent can't authenticate, getting "invalid credentials" error**
```bash
# Check 1: Is agent credential still valid?
python scripts/check_credential_expiry.py --agent-id agent-123

# Check 2: Is role/permission correct?
python scripts/check_agent_permissions.py --agent-id agent-123

# Check 3: View audit logs
grep "agent-123" logs/audit.log | head -20
```

**Q: OpenAI API failing with key error**
```bash
# Set API key first
set OPENAI_API_KEY=sk-your-actual-key-here

# Verify it's set
echo %OPENAI_API_KEY%

# Retry
agentic-iam-ai "Your question" --model openai:gpt-3.5-turbo

# If still fails, use knowledge base mode:
agentic-iam-ai "Your question" --model knowledge
```

### Performance & Scaling

**Q: How many agents can the system support?**
```
SQLite: ~1,000 agents (good for testing)
PostgreSQL: 10,000+ agents (production)

Why? PostgreSQL handles concurrent connections better
```

**Q: What's the typical authentication latency?**
```
✓ Typical: 50-100ms per authentication check
✓ With mTLS: 100-150ms (includes certificate validation)
✓ With ABAC policies: 150-200ms (evaluates complex rules)

Why matters? User experience: <200ms feels instant, >500ms feels slow
```

**Q: Can I horizontally scale the API?**
```
✓ YES - stateless API design
  - Run multiple API instances
  - Use PostgreSQL (shared database)
  - Load balance across instances
  - Each instance self-contained (no synchronization needed)
```

### Development & Contributing

**Q: How do I add a new feature?**
```bash
# 1. Create feature branch
git checkout -b feature/my-feature

# 2. Make changes
# 3. Write tests
# 4. Run quality gate
python scripts/check_all.py

# 5. If passes, commit
git commit -m "feat: add new feature"

# 6. Push and create PR
git push origin feature/my-feature
```

**Q: What's the code quality standard?**
```
✓ All tests passing (88/88)
✓ No security vulnerabilities (bandit clean)
✓ Type hints throughout (mypy compliant)
✓ Code style consistent (flake8 + black)
✓ No secrets in code (detect-secrets clean)
✓ >85% test coverage
```

**Q: Can I use this commercially?**
```
✓ YES - MIT licensed
✓ You can use, modify, distribute
✓ Must include license notice
✓ No warranty (as-is)
✓ No restrictions on commercial use
```

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
