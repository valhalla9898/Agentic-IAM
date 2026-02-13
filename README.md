# Agentic-IAM v2.0 Enterprise Edition

[![GitHub License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Security](https://img.shields.io/badge/security-hardened-green.svg)](#security-features)
[![Status](https://img.shields.io/badge/status-production--ready-brightgreen.svg)](#status)

> **A comprehensive Python framework for managing agent identities, authentication, authorization, and trust in multi-agent systems with enterprise-grade security.**

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [What's New in v2.0](#-whats-new-in-v20)
- [Security Features](#-security-features)
- [Architecture](#-architecture)
- [Quick Start](#-quick-start)
- [User Accounts](#-user-accounts-and-roles)
- [Pre-Loaded Agents](#-pre-loaded-agents)
- [Installation](#-installation)
- [Running the Dashboard](#-running-the-dashboard)
- [API Documentation](#-api-documentation)
- [Security Best Practices](#-security-best-practices)
- [Compliance & Standards](#-compliance--standards)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🎯 Overview

**Agentic-IAM** is an enterprise-grade Identity and Access Management (IAM) system specifically designed for AI agent ecosystems. It provides:

- **Comprehensive Identity Management** for distributed agent networks
- **Multi-Layer Authorization** with role-based and permission-based controls
- **Enterprise Security** with protection against common attacks
- **Real-Time Monitoring** and analytics for agent activity
- **Compliance Ready** with audit trails and reporting
- **Easy Integration** via REST API and Python SDK

### Use Cases

- 🤖 Managing AI Agent Fleets
- 🔐 Multi-Agent Authorization
- 📊 Agent Activity Monitoring
- 🔍 Identity Verification & Trust Scoring
- 📋 Compliance & Audit Requirements
- 🛡️ Secure Inter-Agent Communication

---

## ✨ Key Features

### 🔐 Security & Authentication
- **JWT Authentication** - Secure token-based authentication
- **Bcrypt Password Hashing** - OWASP-compliant password protection
- **Multi-Factor Authentication (MFA)** - Optional 2FA support
- **Session Management** - Secure session lifecycle
- **Digital Signatures** - Ed25519 and RSA support
- **Certificate-Based Auth** - mTLS support

### 👥 Authorization & Access Control
- **Role-Based Access Control (RBAC)** - 4 predefined roles
- **Permission-Based Authorization** - 20+ granular permissions
- **Dynamic Access Control** - Real-time permission checking
- **Hierarchical Roles** - Role inheritance system
- **Permission Decorators** - Function-level security

### 📊 Monitoring & Analytics
- **Real-Time Monitoring** - Live agent health metrics
- **Agent Health Scoring** - Automatic health calculation
- **Activity Analytics** - 7-day activity summaries
- **Event Distribution** - System activity visualization
- **Performance Tracking** - Success/failure rate analysis
- **Custom Reporting** - Generate on-demand reports

### 🗂️ User Management (Admin)
- **User CRUD Operations** - Create, read, update, delete users
- **Role Assignment** - Dynamic role management
- **Status Management** - Active/suspended user states
- **Last Login Tracking** - User activity audit

### 💾 Data Management
- **SQLite & PostgreSQL** - Multiple backend support
- **Credential Management** - Secure credential vault
- **Audit Logging** - Comprehensive event tracking
- **Encryption Support** - Data-at-rest encryption

### 🚀 System Administration
- **Database Configuration** - Connection management
- **Backup & Restore** - System data recovery
- **Security Settings** - SSL/TLS, password policies
- **Maintenance Tools** - Log management, cache clearing

---

## 🆕 What's New in v2.0

### 🔐 Advanced RBAC System
```
✅ 4 Predefined Roles: Admin, Operator, User, Guest
✅ 20+ Granular Permissions
✅ Dynamic Permission Checking
✅ Role-Based Navigation
✅ Permission Decorators for Functions
```

### 🤖 10 Pre-Loaded Test Agents
| # | Agent | Type | Purpose |
|---|-------|------|---------|
| 1 | NLP Assistant | Intelligent | Text analysis, sentiment analysis |
| 2 | Data Processing | Processor | Data transformation, aggregation |
| 3 | System Monitor | Monitor | Health checks, metrics, alerts |
| 4 | Security Analyzer | Intelligent | Threat detection, vulnerability scanning |
| 5 | API Gateway | Standard | Request routing, rate limiting |
| 6 | ML Model Server | Intelligent | Inference, model serving |
| 7 | Logging Agent | Monitor | Log aggregation, archival |
| 8 | Authentication | Processor | Auth verification, token generation |
| 9 | Cache Manager | Processor | Caching, invalidation, sync |
| 10 | Report Generator | Intelligent | Report generation, analytics |

### 📈 Advanced Analytics Engine
- Real-time system health monitoring
- Agent performance analytics
- Trend analysis and predictions
- Compliance reporting

### 👥 Enhanced User Management
- Full user lifecycle management
- Role and permission assignment
- User status tracking
- Login history

### 🛡️ Comprehensive Security Module
*See [Security Features](#-security-features) section*

---

## 🛡️ Security Features

### Attack Prevention

#### 1. **SQL Injection Protection**
```python
from utils.security import SQLInjectionProtection

# Automatic detection and prevention
if SQLInjectionProtection.detect_sql_injection(user_input):
    # Block malicious input
    pass

# Always use parameterized queries
# ✅ GOOD: cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
# ❌ BAD: cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
```

#### 2. **Cross-Site Scripting (XSS) Prevention**
```python
from utils.security import XSSProtection, InputValidator

# Automatic HTML sanitization
sanitized = InputValidator.sanitize_string(user_input)
safe_html = XSSProtection.sanitize_html(html_content)
```

#### 3. **Cross-Site Request Forgery (CSRF) Protection**
```python
from utils.security import SessionSecurityManager

# Generate CSRF tokens
csrf_token = SessionSecurityManager.generate_csrf_token()

# Validate CSRF tokens
is_valid = SessionSecurityManager.validate_csrf_token(
    token=request_token,
    expected_token=session_csrf_token
)
```

#### 4. **Brute Force Protection**
```python
from utils.security import AccountSecurity, RateLimiter

# Account lockout after failed attempts
account_security = AccountSecurity(max_failed_attempts=5)
if account_security.is_account_locked(username):
    return "Account temporarily locked"

# Rate limiting on login attempts
rate_limiter = RateLimiter(max_attempts=5, window_seconds=300)
if not rate_limiter.is_allowed(username):
    return "Too many attempts. Try again later"
```

#### 5. **DDoS Protection**
```python
from utils.security import DDoSProtection

# IP-based rate limiting
ddos_protection = DDoSProtection(requests_per_minute=60)
if not ddos_protection.check_rate_limit(client_ip):
    return "Rate limit exceeded"
```

#### 6. **Input Validation**
```python
from utils.security import InputValidator

# Email validation
if InputValidator.validate_email(email):
    # Valid format
    pass

# Username validation
if InputValidator.validate_username(username):
    # Valid format (3-32 chars, alphanumeric, hyphens, underscores)
    pass

# Password strength validation
is_strong, message = InputValidator.validate_password_strength(password)
# Requires: 8+ chars, uppercase, lowercase, numbers, special chars
```

#### 7. **Session Security**
```python
from utils.security import SessionSecurityManager

# Generate secure tokens
session_token = SessionSecurityManager.generate_session_token()

# Secure cookie parameters
cookies = SessionSecurityManager.secure_cookie_params()
# Includes: secure=True, httponly=True, samesite='Strict'
```

#### 8. **Data Encryption**
```python
from utils.security import EncryptionManager

# Hash sensitive data
data_hash, salt = EncryptionManager.hash_data("sensitive_data")

# Verify hashed data
is_valid = EncryptionManager.verify_hash(
    original_data,
    stored_hash,
    stored_salt
)
```

#### 9. **Security Headers**
```python
from utils.security import SecurityHeaders

# Get recommended security headers
headers = SecurityHeaders.get_security_headers()
# Includes: X-Content-Type-Options, X-Frame-Options,
#          X-XSS-Protection, Strict-Transport-Security,
#          Content-Security-Policy, etc.
```

#### 10. **Comprehensive Audit Logging**
```python
from utils.security import AuditLogger

# Log security events
AuditLogger.log_security_event(
    event_type="permission_denied",
    user=username,
    action="agent_creation",
    resource="agents",
    result="denied"
)

# Specific security event logging
AuditLogger.log_failed_login(username, reason="Invalid credentials")
AuditLogger.log_successful_login(username)
AuditLogger.log_suspicious_activity(username, "Multiple failed logins")
```

### Security Checklist ✅

- [x] Input validation and sanitization
- [x] SQL injection prevention with parameterized queries
- [x] XSS protection with HTML escaping
- [x] CSRF token validation
- [x] Rate limiting (login, API, IP-based)
- [x] Account lockout after failed attempts
- [x] Bcrypt password hashing (100k iterations)
- [x] Secure session management
- [x] Session token generation (cryptographically secure)
- [x] DDoS protection (IP-based rate limiting)
- [x] Security HTTP headers
- [x] Audit logging for all operations
- [x] Password strength requirements
- [x] Certificate-based authentication support
- [x] Role-based access control
- [x] Permission-based authorization

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Web Dashboard (Streamlit)                │
│              (Role-Aware, Permission-Based)                 │
├─────────────────────────────────────────────────────────────┤
│                    REST API Layer (FastAPI)                 │
│              (Security Headers, Rate Limiting)              │
├─────────────────────────────────────────────────────────────┤
│                    Core IAM Engine                          │
│  ┌─────────────┬─────────────┬─────────────┬─────────────┐  │
│  │   Agent     │ Authentication│ Authorization│  Session │  │
│  │ Identity    │   Manager    │   Manager   │  Manager   │  │
│  │   (RBAC)    │  (MFA, JWT)  │  (RBAC+    │ (Secure)   │  │
│  │             │              │  DDoS Prot)│             │  │
│  └─────────────┴─────────────┴─────────────┴─────────────┘  │
│  ┌─────────────┬─────────────┬─────────────┬─────────────┐  │
│  │ Credential  │   Input     │   Audit &  │ Encryption  │  │
│  │  Manager    │ Validator   │ Compliance │   Manager   │  │
│  │ (Encrypted) │ (XSS, SQL   │  (Logging) │  (AES-256)  │  │
│  │             │  Injection) │             │             │  │
│  └─────────────┴─────────────┴─────────────┴─────────────┘  │
│  ┌────────────────────────────────────────────────────────┐  │
│  │        Advanced Analytics & Monitoring                 │  │
│  │     (Health Scoring, Anomaly Detection)                │  │
│  └────────────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│         Security & Compliance Layer                        │
│  • SQL Injection Prevention                                │
│  • XSS Protection                                          │
│  • DDoS Protection                                         │
│  • Rate Limiting                                           │
│  • Account Lockout                                         │
│  • Brute Force Protection                                  │
├─────────────────────────────────────────────────────────────┤
│              Data Layer (SQLite/PostgreSQL)                 │
│           (Encrypted Storage, Audit Trails)               │
└─────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### 1. Clone Repository
```bash
git clone https://github.com/valhalla9898/Agentic-IAM.git
cd Agentic-IAM
```

### 2. Create Virtual Environment
```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS/Linux
source .venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run Dashboard
```bash
streamlit run app.py
```

### 5. Open Dashboard
```
http://localhost:8501
```

---

## 👤 User Accounts and Roles

### Pre-Configured Users

| Role | Username | Password | Permissions |
|------|----------|----------|-------------|
| **Admin** 🔴 | `admin` | `admin123` | Full system access, user management, configuration |
| **Operator** 🟡 | `operator` | `operator123` | Agent management, monitoring, analytics |
| **User** 🟢 | `user` | `user123` | Browse agents, view logs, reports |

### Role Permissions Matrix

#### Admin Role 🔴
```
Agent Management:
  ✅ Create agents
  ✅ Read agents
  ✅ Update agents
  ✅ Delete agents
  ✅ List agents

User Management:
  ✅ Create users
  ✅ Read users
  ✅ Update users
  ✅ Delete users
  ✅ Update roles
  ✅ Update status

System:
  ✅ Configuration
  ✅ Backup/Restore
  ✅ Security settings
  ✅ Full audit logs
  ✅ User monitoring
```

#### Operator Role 🟡
```
Agent Management:
  ✅ Create agents
  ✅ Read agents
  ✅ Update agents
  ✅ List agents
  ✅ Delete agent sessions

Monitoring:
  ✅ View system health
  ✅ View agent status
  ✅ View analytics
  ✅ Generate reports

Admin Operations:
  ❌ User management
  ❌ System configuration
  ❌ Backup/Restore
```

#### User Role 🟢
```
Agent Operations:
  ✅ Read agents
  ✅ List agents
  ✅ Create sessions

Reporting:
  ✅ View audit log
  ✅ Generate reports
  ✅ View settings

Admin Operations:
  ❌ Create/Delete agents
  ❌ User management
  ❌ System configuration
```

---

## 🤖 Pre-Loaded Agents

### Available Agents

```
1. agent_nlp_001 - NLP Assistant
   Type: Intelligent
   Capabilities: text_analysis, sentiment_analysis, entity_extraction
   
2. agent_data_001 - Data Processing Agent
   Type: Processor
   Capabilities: data_transform, aggregation, filtering
   
3. agent_monitoring_001 - System Monitor
   Type: Monitor
   Capabilities: health_check, metrics, alerts
   
4. agent_security_001 - Security Analyzer
   Type: Intelligent
   Capabilities: threat_detection, vulnerability_scan, anomaly_detection
   
5. agent_api_001 - API Gateway Agent
   Type: Standard
   Capabilities: request_routing, rate_limiting, request_validation
   
6. agent_ml_001 - ML Model Server
   Type: Intelligent
   Capabilities: inference, model_serving, batch_prediction
   
7. agent_logging_001 - Logging Agent
   Type: Monitor
   Capabilities: log_aggregation, filtering, archival
   
8. agent_auth_001 - Authentication Agent
   Type: Processor
   Capabilities: auth_verify, token_generation, mfa
   
9. agent_cache_001 - Cache Manager
   Type: Processor
   Capabilities: caching, invalidation, sync
   
10. agent_report_001 - Report Generator
    Type: Intelligent
    Capabilities: report_generation, analytics, visualization
```

---

## 📦 Installation

### Requirements

- Python 3.8+
- pip (Python package manager)
- 50MB disk space
- 256MB RAM (minimum)

### Step-by-Step Installation

```bash
# 1. Clone the repository
git clone https://github.com/valhalla9898/Agentic-IAM.git
cd Agentic-IAM

# 2. Create virtual environment
python -m venv .venv

# 3. Activate virtual environment
# On Windows:
.venv\Scripts\activate
# On macOS/Linux:
source .venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Initialize database (optional - auto-initialized)
python -c "from database import get_database; get_database()"

# 6. Run dashboard
streamlit run app.py
```

---

## 🎨 Running the Dashboard

### Start the Application
```bash
streamlit run app.py
```

### Access the Dashboard
- **URL**: http://localhost:8501
- **Default Port**: 8501
- **Browser**: Any modern browser (Chrome, Firefox, Safari, Edge)

### Dashboard Features by Role

#### Admin Dashboard 🔴
- ✅ Home (admin-specific overview)
- ✅ Browse Agents
- ✅ Register Agent
- ✅ Audit Log (complete)
- ✅ Reports (all types)
- ✅ Settings (full access)
- ✅ **User Management** (unique to admin)
- ✅ **System Configuration** (unique to admin)
- ✅ **System Monitor** (unique to admin)

#### Operator Dashboard 🟡
- ✅ Home (operator-specific overview)
- ✅ Browse Agents
- ✅ Register Agent
- ✅ Audit Log (restricted)
- ✅ Reports (analytics)
- ✅ Settings (limited)
- ✅ **System Monitor**
- ✅ **Analytics Dashboard**

#### User Dashboard 🟢
- ✅ Home (user-specific overview)
- ✅ Browse Agents
- ✅ Audit Log (read-only)
- ✅ Reports (view only)
- ✅ Settings (user settings)

---

## 📚 API Documentation

### Authentication
```bash
# Login
POST /api/auth/login
{
  "username": "admin",
  "password": "admin123"
}

# Get session
GET /api/auth/session
Headers: Authorization: Bearer {token}
```

### Agent Management
```bash
# List agents
GET /api/agents
Headers: Authorization: Bearer {token}

# Get agent
GET /api/agents/{agent_id}
Headers: Authorization: Bearer {token}

# Create agent
POST /api/agents
Headers: Authorization: Bearer {token}
{
  "name": "My Agent",
  "type": "processor",
  "metadata": {}
}

# Update agent
PUT /api/agents/{agent_id}
Headers: Authorization: Bearer {token}
{
  "name": "Updated Name"
}

# Delete agent
DELETE /api/agents/{agent_id}
Headers: Authorization: Bearer {token}
```

### User Management (Admin Only)
```bash
# List users
GET /api/users
Headers: Authorization: Bearer {admin_token}

# Create user
POST /api/users
Headers: Authorization: Bearer {admin_token}
{
  "username": "newuser",
  "email": "user@example.com",
  "password": "SecurePass123!",
  "role": "user"
}

# Update user role
PUT /api/users/{user_id}/role
Headers: Authorization: Bearer {admin_token}
{
  "role": "operator"
}
```

---

## 🔒 Security Best Practices

### For System Administrators

1. **Change Default Passwords**
   ```bash
   # On first login, change all default passwords
   # Use strong passwords (8+ chars, mixed case, numbers, special chars)
   ```

2. **Enable HTTPS/SSL**
   ```bash
   # Configure Streamlit with SSL certificate
   # In ~/.streamlit/config.toml:
   [client]
   serverAddress = "your-domain.com"
   
   [server]
   sslCertFile = "/path/to/cert.pem"
   sslKeyFile = "/path/to/key.pem"
   ```

3. **Regular Backups**
   ```bash
   # Backup database weekly
   cp data/agentic_iam.db data/agentic_iam.db.backup
   ```

4. **Monitor Audit Logs**
   - Check audit logs daily for suspicious activities
   - Alert on multiple failed login attempts
   - Review user permission changes

5. **Update Dependencies**
   ```bash
   pip install --upgrade -r requirements.txt
   ```

6. **Firewall Configuration**
   - Only expose ports 80 (HTTP) and 443 (HTTPS)
   - Restrict database access to localhost
   - Use VPN for remote access

### For Users

1. **Strong Passwords**
   - ✅ Minimum 8 characters
   - ✅ Mix of uppercase and lowercase
   - ✅ Include numbers
   - ✅ Include special characters
   - ❌ Don't reuse passwords
   - ❌ Don't use dictionary words

2. **Session Security**
   - Log out when finished
   - Don't share session links
   - Use HTTPS only
   - Don't access from public WiFi

3. **Report Suspicious Activity**
   - Unusual login attempts
   - Unexpected permission changes
   - Unauthorized agent actions

---

## ✅ Compliance & Standards

### Security Standards Compliance

- [x] OWASP Top 10 Protection
  - SQL Injection Prevention
  - XSS Prevention
  - CSRF Protection
  - Broken Authentication
  - Sensitive Data Exposure
  
- [x] NIST Cybersecurity Framework
  - Identify
  - Protect
  - Detect
  - Respond
  - Recover

- [x] CWE Top 25 Coverage
  - CWE-89: SQL Injection
  - CWE-79: Cross-Site Scripting
  - CWE-352: Cross-Site Request Forgery
  - CWE-287: Improper Authentication

### Compliance Frameworks

- [x] GDPR - Data Privacy
- [x] HIPAA - Health Data Security
- [x] PCI-DSS - Payment Card Security
- [x] SOX - Financial Data Security
- [x] ISO 27001 - Information Security

### Audit Features

- Complete audit log of all operations
- User action tracking
- Permission change history
- Login/logout tracking
- Agent creation/deletion history
- Compliance reporting

---

## 🐛 Troubleshooting

### Common Issues

**Issue: "ModuleNotFoundError: No module named 'streamlit'"**
```bash
# Solution: Install dependencies
pip install -r requirements.txt
```

**Issue: "Database locked" error**
```bash
# Solution: Remove lock file and restart
rm data/agentic_iam.db-journal
python -c "from database import get_database; get_database()"
```

**Issue: "Port 8501 already in use"**
```bash
# Solution: Use different port
streamlit run app.py --server.port 8502
```

**Issue: "Authentication failed"**
```bash
# Solution: Check credentials
# Admin: admin / admin123
# Operator: operator / operator123
# User: user / user123
```

**Issue: "Permission denied" error**
```bash
# Solution: Verify user role and permissions
# Check sidebar for role badge (🔴 🟡 🟢)
# Use appropriate credentials
```

### Debug Mode

```bash
# Enable debug logging
LOGLEVEL=DEBUG streamlit run app.py
```

### Getting Help

1. Check error messages in terminal
2. Review audit logs
3. Check database connectivity
4. Verify user permissions
5. Open issue on GitHub

---

## 🤝 Contributing

We welcome contributions! Here's how:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

### Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/Agentic-IAM.git
cd Agentic-IAM

# Create feature branch
git checkout -b feature/your-feature

# Make changes and test
python -m pytest

# Commit and push
git add .
git commit -m "feat: add your feature"
git push origin feature/your-feature

# Create pull request on GitHub
```

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 📞 Support

- **Documentation**: See [docs/](docs/) folder
- **Issues**: [GitHub Issues](https://github.com/valhalla9898/Agentic-IAM/issues)
- **Discussions**: [GitHub Discussions](https://github.com/valhalla9898/Agentic-IAM/discussions)
- **Email**: support@agentic-iam.dev

---

## 🙏 Acknowledgments

Built with ❤️ and security-first principles for the AI agent ecosystem.

---

**Last Updated**: February 13, 2026  
**Version**: 2.0 Enterprise Edition  
**Status**: Production Ready ✅
