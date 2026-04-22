# 📚 Files & Components Guide - Agentic-IAM

## Overview

This guide explains every important file in the project and its purpose.

---

## Root Level Files

### `authentication.py`
**Purpose**: Verify agent identity

**Responsibilities**:
- Validate credentials (API key, Certificate, Token)
- Calculate trust scores
- Log authentication attempts
- Enforce rate limiting

**Key Methods**:
- `authenticate()` - Main verification
- `verify_credential()` - Check validity
- `calculate_trust_level()` - Compute score

---

### `authorization.py`
**Purpose**: Determine what agents can do

**Responsibilities**:
- Check RBAC policies
- Evaluate ABAC rules
- Check context conditions
- Log authorization decisions

**Key Methods**:
- `authorize()` - Check permission
- `check_permission()` - Verify single permission
- `get_agent_permissions()` - List permissions

---

### `agent_identity.py`
**Purpose**: Create and manage agent identities

**Classes**:
- `AgentIdentity` - Individual agent identity
- `AgentIdentityManager` - Manage multiple identities
- `AuthenticationResult` - Authentication result
- `AuthenticationManager` - Handle authentication
- `AuthorizationManager` - Handle authorization

---

### `session_manager.py`
**Purpose**: Manage agent sessions

**Responsibilities**:
- Create sessions
- Validate sessions
- Handle expiration
- Detect suspicious activity

**Key Methods**:
- `create_session()` - Start new session
- `validate_session()` - Check validity
- `end_session()` - Close session
- `renew_session()` - Extend expiration

---

### `credential_manager.py`
**Purpose**: Secure credential storage

**Responsibilities**:
- Generate credentials
- Encrypt before storing
- Auto-rotate credentials
- Revoke expired credentials

**Key Methods**:
- `create_credential()` - Create new
- `get_credential()` - Retrieve
- `rotate_credential()` - Create new + revoke old
- `revoke_credential()` - Invalidate

---

### `federated_identity.py`
**Purpose**: Link with external identity systems

**Responsibilities**:
- Link with Azure AD, AWS IAM, Okta
- Sync permissions from external systems
- Verify federated tokens
- Manage trust relationships

---

### `transport_binding.py`
**Purpose**: secure agent-to-platform communication

**Responsibilities**:
- Enforce mTLS
- Verify certificates
- Manage encryption keys
- Support quantum-safe algorithms

---

### `audit_compliance.py`
**Purpose**: Comprehensive operation logging

**Classes**:
- `AuditManager` - Log operations
- `ComplianceManager` - Check compliance

**Support Frameworks**:
- GDPR (European privacy)
- HIPAA (Health data)
- SOX (Public companies)
- PCI-DSS (Credit cards)
- ISO-27001 (Information security)

---

### `database.py`
**Purpose**: Data persistence

**Main Tables**:
- `users` - Dashboard users
- `agents` - Registered agents
- `events` - Audit log
- `sessions` - Active sessions
- `permissions` - Agent permissions

**Key Methods**:
- `add_agent()` - Register agent
- `log_event()` - Log operation
- `get_events()` - Search events
- `add_permission()` - Grant permission

---

### `agent_registry.py`
**Purpose**: Fast in-memory agent storage

**Properties**:
- Fast lookups
- Synced with database
- In-memory caching

---

### `app.py`
**Purpose**: Main Streamlit dashboard

**Pages**:
- Home - Statistics and overview
- Agent Management - CRUD operations
- User Management - Admin panel
- Audit Log - View events
- Settings - Configure system

---

## API Directory

### `api/main.py`
**Purpose**: FastAPI application

**Endpoints**:
- GET /health - Health check
- POST /api/agents - Create agent
- GET /api/agents - List agents
- POST /api/authenticate - Verify agent
- POST /api/authorize - Check permission
- GET /api/events - Audit log

---

### `api/graphql.py`
**Purpose**: GraphQL API

**Queries**:
- agents - List agents
- agent(id) - Single agent
- events - Audit events
- permissions - Agent permissions

**Mutations**:
- registerAgent - Create agent
- updateAgent - Modify agent
- deleteAgent - Remove agent

---

### `api/models.py`
**Purpose**: Data structure definitions

**Models**:
- Agent - Agent data
- User - User data
- Event - Audit event
- Session - Session data
- Credential - Credential data
- Permission - Permission data

---

## Core Directory

### `core/agentic_iam.py`
**Purpose**: Main system orchestrator

**Manages**:
- Authentication Manager
- Authorization Manager
- Session Manager
- Credential Manager
- Federated Identity Manager
- Transport Security Manager
- Audit Manager
- Compliance Manager
- Agent Registry
- Database

**Key Methods**:
- `initialize()` - Setup system
- `shutdown()` - Clean up

---

## Dashboard Directory

### `dashboard/components/`
**Purpose**: Reusable UI components

**Files**:
- `login.py` - Login page
- `agent_selection.py` - Agent chooser
- `agent_management.py` - Agent admin
- `user_management.py` - User admin
- `audit_log.py` - Event viewer
- `settings.py` - Configuration

---

## Config Directory

### `config/settings.py`
**Purpose**: System configuration

**Settings**:
- DEBUG - Development mode
- DATABASE_PATH - Database location
- LOG_LEVEL - Logging level
- SESSION_TIMEOUT - Session expiration
- CREDENTIAL_TTL - Credential validity
- SSL/TLS - Encryption settings

---

## Tests Directory

### `tests/unit/`
**Purpose**: Unit tests

**Test Files**:
- `test_authentication.py`
- `test_authorization.py`
- `test_session_manager.py`
- `test_credential_manager.py`
- `test_audit.py`

---

### `tests/integration/`
**Purpose**: Integration tests

**Test Files**:
- `test_full_flow.py` - Complete workflow
- `test_api.py` - API endpoints
- `test_dashboard.py` - Dashboard UI

---

### `tests/e2e/`
**Purpose**: End-to-end tests

**Test Files**:
- `test_user_workflow.py` - User scenario
- `test_admin_workflow.py` - Admin scenario

---

## Configuration Files

### `requirements.txt`
**Purpose**: Python dependencies

**Key Packages**:
- fastapi - Web API
- pydantic - Data validation
- sqlalchemy - Database ORM
- streamlit - Dashboard
- ariadne - GraphQL

---

### `pytest.ini`
**Purpose**: Test configuration

**Settings**:
- Test paths
- Coverage targets
- Async configuration

---

### `.env.example`
**Purpose**: Environment variables template

**Copy to `.env` and edit**:
```bash
cp .env.example .env
```

---

### `Dockerfile`
**Purpose**: Docker container image

**Usage**:
```bash
docker build -t agentic-iam:latest .
docker run -p 8501:8501 agentic-iam:latest
```

---

### `docker-compose.yml`
**Purpose**: Run all services together

**Services**:
- Dashboard (Streamlit)
- API (FastAPI)
- Database (SQLite/PostgreSQL)

**Usage**:
```bash
docker-compose up
```

---

## Architecture Map

```
Presentation Layer
└─ Streamlit (app.py)
└─ REST API (api/main.py)
└─ GraphQL (api/graphql.py)
        │
Business Logic Layer
└─ core/agentic_iam.py
   ├─ authentication.py
   ├─ authorization.py
   ├─ session_manager.py
   ├─ credential_manager.py
   ├─ federated_identity.py
   ├─ transport_binding.py
   ├─ audit_compliance.py
   └─ agent_registry.py
        │
Data Layer
└─ database.py
```

---

## How to Use This Guide

**For New Users**:
1. Read `README.md` - Overview
2. Read `QUICK_START_EN.md` - Quick start
3. Read `EXAMPLES_EN.md` - Code examples

**For Developers**:
1. Read `ARCHITECTURE_EN.md` - Deep dive
2. Read this file - Components guide
3. Check actual code in repository

**For Administrators**:
1. Read `README.md` - Summary
2. Read `QUICK_START_EN.md` - FAQ
3. Use dashboard for operations

---

This guide explains every file and component in the project!
