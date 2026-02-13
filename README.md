# Agentic-IAM

A comprehensive Python framework for managing agent identities, authentication, authorization, and trust in multi-agent systems.

**v2.0 - Enhanced with Advanced RBAC, Analytics & Monitoring** 🚀

## ✨ What's New in v2.0

### 🔐 Advanced Role-Based Access Control (RBAC)
- **4 Predefined Roles**: Admin, Operator, User, Guest
- **Fine-Grained Permissions**: 20+ granular permission controls
- **Dynamic Access Control**: Permission checks on all operations
- **Role Inheritance**: Hierarchical permission structure
- **Permission Decorators**: Built-in authorization for functions

### 📊 Analytics & Monitoring
- **Real-Time Monitoring**: Live system and agent health metrics
- **Agent Health Scoring**: Automatic health calculation based on activity
- **Performance Analytics**: Track success rates and failure analysis
- **Event Distribution**: Visualize system activity patterns
- **Trend Analysis**: 7-day activity summaries per agent

### 📈 Advanced Reporting
- **System Health Reports**: Comprehensive system-wide metrics
- **Agent Performance Reports**: Detailed per-agent analytics
- **Compliance Reports**: Audit trails and security metrics
- **Custom Reports**: Generate on-demand reports
- **Export Capabilities**: Download reports in CSV format

### 👥 Enhanced User Management (Admin Only)
- **User CRUD Operations**: Create, read, update, delete users
- **Role Assignment**: Assign roles to users dynamically
- **Status Management**: Active/suspended user states
- **User Listings**: View all users with detailed information

### 🔧 System Administration
- **Database Configuration**: Manage DB connections and settings
- **Security Configuration**: SSL/TLS, 2FA, password policies
- **Backup & Restore**: System backup and recovery
- **Maintenance Tools**: Log cleaning, cache clearing
- **Service Management**: Restart and manage services

### 📡 System Monitoring Dashboard (Operator/Admin)
- **Live Health Metrics**: CPU, Memory, Network, Connections
- **Agent Status Table**: Real-time agent health overview
- **Performance Trends**: Historical performance analysis
- **Alert Management**: Active alerts and notifications

## Overview

This framework provides a complete solution for agent identity management with enterprise-grade security features, compliance support, and intelligent trust scoring.

![Platform Overview](https://github.com/user-attachments/assets/9638885c-d336-43cd-a287-c086c06dd582)
![New Note](https://github.com/user-attachments/assets/ea52841b-80a9-4beb-a3c4-c1487827df19)

 System Architecture
###  Agentic-IAM Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Web Dashboard (Streamlit)                │
├─────────────────────────────────────────────────────────────┤
│                    REST API Layer (FastAPI)                 │
├─────────────────────────────────────────────────────────────┤
│                    Core IAM Engine                          │
│  ┌─────────────┬─────────────┬─────────────┬─────────────┐  │
│  │   Agent     │ Authentication│ Authorization│  Session │  │
│  │ Identity    │   Manager    │   Manager   │  Manager   │  │
│  └─────────────┴─────────────┴─────────────┴─────────────┘  │
│  ┌─────────────┬─────────────┬─────────────┬─────────────┐  │
│  │ Federated   │ Credential  │   Agent     │ Transport   │  │
│  │ Identity    │  Manager    │  Registry   │ Security    │  │
│  └─────────────┴─────────────┴─────────────┴─────────────┘  │
│  ┌─────────────┬─────────────┬─────────────────────────────┐│
│  │   Audit &   │ Intelligence│    Trust Scoring &          ││
│  │ Compliance  │   Engine    │  Behavioral Analytics       ││
│  └─────────────┴─────────────┴─────────────────────────────┘│
├─────────────────────────────────────────────────────────────┤
│              Data Layer (SQLite/PostgreSQL)                 │
└─────────────────────────────────────────────────────────────┘
```

![Key Point](https://github.com/user-attachments/assets/697eb68a-ee80-4af6-9c72-65de212664c4)


**Key Components:**
- **Frontend:** Streamlit web dashboard for management
- **API Layer:** FastAPI REST endpoints for integration
- **Core Engine:** 10 integrated security modules
- **Data Layer:** Persistent storage with encryption


## Features

### 🔐 Core Identity Management
- **Agent Identity**: UUID-based identities with metadata and cryptographic keys
- **Digital Signatures**: Ed25519 and RSA support for identity verification
- **DID Support**: Decentralized Identifier document generation

### 🔑 Authentication Subsystem
- **JWT Authentication**: Secure token-based authentication
- **Cryptographic Auth**: Challenge-response with digital signatures
- **mTLS Support**: Mutual TLS certificate-based authentication
- **Multi-Factor Auth**: Configurable multi-factor authentication flows

### 🛡️ Authorization Engine
- **RBAC**: Role-Based Access Control with inheritance
- **ABAC**: Attribute-Based Access Control with policy engine
- **PBAC**: Policy-Based Access Control with custom rules
- **Hybrid Engine**: Combine multiple authorization approaches

### 📋 Session Management
- **Secure Sessions**: Token lifecycle with TTL and refresh
- **Audit Trails**: Comprehensive session activity logging
- **Rate Limiting**: Configurable limits and security policies
- **Multi-Session Support**: Agent session limits and management

### 🌐 Federated Identity
- **OIDC Support**: OpenID Connect integration
- **SAML Integration**: SAML 2.0 identity provider support
- **DIDComm**: Decentralized identity communication
- **Trust Brokers**: Cross-domain trust relationships

### 🔒 Credential Management
- **Secure Storage**: Encrypted credential vault with rotation
- **Key Rotation**: Automated and policy-based rotation
- **Multiple Backends**: In-memory and file-based storage
- **Credential Types**: API keys, passwords, certificates, tokens

### 📖 Agent Registry
- **Discovery Service**: Agent registration and lookup
- **Persistent Storage**: SQLite and in-memory backends
- **Search & Filter**: Advanced query capabilities
- **Audit Logging**: Complete registry operation tracking

### 🚀 Transport Binding
- **Multi-Protocol**: HTTP/HTTPS, gRPC, WebSocket, STDIO support
- **Security Enforcement**: Transport-layer security policies
- **Identity Extraction**: Automatic identity binding from requests
- **Rate Limiting**: Per-agent and per-transport limits

### 📊 Audit & Compliance
- **Comprehensive Logging**: All identity operations tracked
- **Compliance Frameworks**: GDPR, HIPAA, SOX, PCI-DSS, PCI-DSS v4.0, NIST CSF, ISO-27001 support
- **Integrity Verification**: Cryptographic audit trail protection
- **Automated Reports**: Compliance violation detection

### 🧠 Agent Intelligence
- **Trust Scoring**: ML-based trust and reputation scoring
- **Anomaly Detection**: Behavioral pattern analysis
- **Risk Assessment**: Dynamic risk level calculation
- **Behavioral Profiling**: Agent activity pattern learning

## 🤖 Pre-Loaded Test Agents (v2.0)

The system comes with 10 pre-built agents for demonstration:

| Agent ID | Name | Type | Purpose |
|----------|------|------|---------|
| `agent_nlp_001` | NLP Assistant | Intelligent | Text analysis, sentiment analysis, entity extraction |
| `agent_data_001` | Data Processing | Processor | Data transformation, aggregation, filtering |
| `agent_monitoring_001` | System Monitor | Monitor | Health checks, metrics, alerts |
| `agent_security_001` | Security Analyzer | Intelligent | Threat detection, vulnerability scanning |
| `agent_api_001` | API Gateway | Standard | Request routing, rate limiting, validation |
| `agent_ml_001` | ML Model Server | Intelligent | Inference, model serving, batch prediction |
| `agent_logging_001` | Logging Agent | Monitor | Log aggregation, filtering, archival |
| `agent_auth_001` | Authentication | Processor | Auth verification, token generation, MFA |
| `agent_cache_001` | Cache Manager | Processor | Caching, invalidation, sync |
| `agent_report_001` | Report Generator | Intelligent | Report generation, analytics, visualization |

## 👤 User Accounts & Login Credentials (v2.0)

Three user accounts are pre-created with different roles:

| Username | Password | Role | Permissions |
|----------|----------|------|-------------|
| `admin` | `admin123` | Admin | Full system access, user management, configuration |
| `operator` | `operator123` | Operator | Agent management, monitoring, analytics |
| `user` | `user123` | User | Browse agents, view audit logs, reports |

### Role Permissions Summary

**Admin Role 🔴**
- ✅ All user management operations
- ✅ System configuration and backup
- ✅ Security settings and policies
- ✅ Full audit log access
- ✅ All agent operations

**Operator Role 🟡**
- ✅ Agent management (CRUD)
- ✅ Session monitoring
- ✅ Performance analytics
- ✅ Report generation
- ✅ System monitoring
- ❌ User management
- ❌ System configuration

**User Role 🟢**
- ✅ Browse and view agents
- ✅ View audit logs
- ✅ Generate reports
- ✅ View settings
- ❌ Create/delete agents
- ❌ User management
- ❌ System configuration

## 🚀 Running the Dashboard (v2.0)

### Launch the Dashboard

```bash
# Install dependencies (if not already done)
pip install -r requirements.txt

# Run the Streamlit dashboard
streamlit run app.py

# The dashboard will be available at: http://localhost:8501
```

### Dashboard Navigation by Role

**For Admin Users** 🔴
- Full system access
- User management interface 
- System configuration tools
- Complete audit logs

**For Operator Users** 🟡
- Agent management and monitoring
- Performance analytics
- Report generation
- System health monitoring

**For Regular Users** 🟢
- Browse and view agents
- View audit logs
- Generate reports
- Check settings

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/valhalla9898/Agentic-IAM.git
cd Agentic-IAM

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# On Windows:
.venv\Scripts\activate
# On macOS/Linux:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage

```python
from agent_identity import AgentIdentity, AgentMetadata, IdentityClaims
from authentication import JWTAuthentication, AuthenticationManager
from authorization import RBACEngine, Role
from session_manager import SessionManager, InMemorySessionStore, AuditLogger

# Create an agent identity
metadata = AgentMetadata(
    name="My Agent",
    agent_type="service_bot",
    version="1.0.0",
    organization="MyOrg"
)

claims = IdentityClaims(
    role="agent",
    permissions=["read", "write"],
    scopes=["user_data"]
)

agent = AgentIdentity(metadata=metadata, claims=claims)

# Set up authentication
auth_manager = AuthenticationManager()
jwt_auth = JWTAuthentication(secret_key="your-secret-key")
auth_manager.register_method("jwt", jwt_auth, is_default=True)

# Generate and verify token
token = jwt_auth.generate_token(agent)
result = auth_manager.authenticate({'token': token}, 'jwt')

print(f"Authentication successful: {result.success}")
print(f"Agent ID: {result.agent_id}")
```

### Advanced Usage

```python
from authorization import HybridAuthorizationEngine, Policy, PolicyRule, Effect
from session_manager import SessionManager
from agent_registry import AgentRegistry, InMemoryAgentStorage, RegistryAuditor
from credential_manager import CredentialManager, InMemoryCredentialStore, FernetEncryption
from audit_compliance import AuditManager, SQLiteAuditStorage, ComplianceFramework
from agent_intelligence import AgentIntelligenceEngine

# Set up comprehensive system
session_store = InMemorySessionStore()
session_manager = SessionManager(session_store)

registry_storage = InMemoryAgentStorage()
registry = AgentRegistry(registry_storage)

credential_store = InMemoryCredentialStore()
credential_encryption = FernetEncryption()
credential_manager = CredentialManager(credential_store, credential_encryption)

audit_storage = SQLiteAuditStorage("audit.db")
audit_manager = AuditManager(audit_storage)

intelligence_engine = AgentIntelligenceEngine()

# Register agent
registry.register_agent(
    agent,
    endpoints=["https://my-agent.example.com"],
    capabilities=["text_processing", "data_analysis"]
)

# Create session
from authentication import AuthenticationResult
auth_result = AuthenticationResult(success=True, agent_id=agent.agent_id, auth_method="jwt")
session_id = session_manager.create_session(agent, auth_result)

# Store credentials
api_key_id = credential_manager.store_credential(
    name="External API Key",
    credential_data="secret_api_key_123",
    credential_type=CredentialType.API_KEY,
    owner_agent_id=agent.agent_id
)

# Log audit event
audit_manager.log_event(
    AuditEventType.AUTH_SUCCESS,
    agent_id=agent.agent_id,
    session_id=session_id,
    details={"method": "jwt"}
)

# Calculate trust score
events = audit_manager.query_events(AuditQuery(agent_id=agent.agent_id))
trust_score = intelligence_engine.calculate_trust_score(agent.agent_id, events)

print(f"Trust Score: {trust_score.overall_score:.3f}")
print(f"Risk Level: {trust_score.risk_level.value}")
```

## Architecture

### Core Components

1. **AgentIdentity**: Core identity representation with cryptographic keys
2. **Authentication**: Multi-method authentication with JWT, signatures, mTLS
3. **Authorization**: Flexible policy-based access control
4. **SessionManager**: Secure session lifecycle management
5. **FederatedIdentity**: Cross-domain identity federation
6. **CredentialManager**: Secure credential storage and rotation
7. **AgentRegistry**: Agent discovery and registration service
8. **TransportBinding**: Protocol-agnostic identity binding
9. **AuditCompliance**: Comprehensive audit logging and compliance
10. **AgentIntelligence**: ML-based trust scoring and anomaly detection

### Security Features

- **End-to-End Encryption**: All sensitive data encrypted at rest and in transit
- **Digital Signatures**: Cryptographic verification of agent actions
- **Zero Trust Architecture**: Never trust, always verify approach
- **Audit Trails**: Immutable audit logs with integrity verification
- **Anomaly Detection**: ML-based behavioral analysis
- **Compliance**: Built-in support for regulatory frameworks

### Scalability

- **Modular Design**: Use only the components you need
- **Pluggable Backends**: Support for various storage systems
- **Async Support**: Non-blocking operations where applicable
- **Caching**: Intelligent caching for performance
- **Federation**: Scale across trust domains

## Configuration

### Environment Variables

```bash
# Database configuration
AGENT_IDENTITY_DB_PATH=/path/to/database
AGENT_IDENTITY_ENCRYPTION_KEY=your-encryption-key

# Authentication configuration
JWT_SECRET_KEY=your-jwt-secret
JWT_TOKEN_TTL=3600

# Session configuration
SESSION_TTL=3600
MAX_SESSIONS_PER_AGENT=5

# Audit configuration
AUDIT_LOG_PATH=/path/to/audit.log
ENABLE_AUDIT_ENCRYPTION=true

# Compliance configuration
COMPLIANCE_FRAMEWORKS=gdpr,hipaa
DATA_RETENTION_DAYS=2555  # 7 years
```

### Production Deployment

For production deployments, consider:

1. **Database Backend**: Use PostgreSQL or MySQL instead of SQLite
2. **Redis Sessions**: Use Redis for distributed session storage
3. **HSM Integration**: Hardware Security Module for key management
4. **Load Balancing**: Distribute across multiple instances
5. **Monitoring**: Integrate with Prometheus/Grafana
6. **Backup Strategy**: Regular encrypted backups
7. **Disaster Recovery**: Multi-region deployment

## Security Considerations

### Best Practices

1. **Key Management**: Use HSM or cloud KMS for production keys
2. **Secret Rotation**: Implement automated credential rotation
3. **Network Security**: Use TLS 1.3 for all communications
4. **Access Control**: Follow principle of least privilege
5. **Monitoring**: Implement real-time security monitoring
6. **Incident Response**: Have procedures for security incidents
7. **Regular Audits**: Conduct security assessments

### Threat Model

The framework protects against:

- **Identity Spoofing**: Cryptographic verification prevents impersonation
- **Credential Theft**: Encrypted storage and rotation limit exposure
- **Session Hijacking**: Secure session management with integrity checks
- **Privilege Escalation**: Fine-grained authorization controls
- **Insider Threats**: Comprehensive audit trails and anomaly detection
- **Compliance Violations**: Automated compliance monitoring

## Development

### Running Tests

```bash
# Install development dependencies
pip install pytest pytest-asyncio coverage

# Run tests
pytest tests/

# Run with coverage
coverage run -m pytest tests/
coverage report
```

### Code Quality

```bash
# Format code
black agent_identity/

# Check linting
flake8 agent_identity/

# Type checking
mypy agent_identity/
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Implement your changes with tests
4. Ensure code quality checks pass
5. Submit a pull request

## Foundational Research & Academic AI Research References

This framework is inspired by and implements concepts from the following research:

### Zero-Trust Identity for Agentic AI
**A Novel Zero-Trust Identity Framework for Agentic AI: Decentralized Authentication and Fine-Grained Access Control**  
*Ken Huang, Vineeth Sai Narajala, John Yeoh, Ramesh Raskar, Youssef Harkati, Jerry Huang, Idan Habler, Chris Hughes*  
arXiv:2505.19301 [cs.CR] - [https://arxiv.org/abs/2505.19301](https://arxiv.org/abs/2505.19301)


**Agent Name Service (ANS): A Universal Directory for Secure AI Agent Discovery and Interoperability**  
*Ken Huang, Vineeth Sai Narajala, Idan Habler, Akram Sheriff*  
arXiv:2505.10609 [cs.CR] - [https://arxiv.org/abs/2505.10609](https://arxiv.org/abs/2505.10609)

These papers provide the theoretical foundation for the zero-trust identity architecture, decentralized authentication mechanisms, and fine-grained access control systems implemented in Agentic-IAM.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions:

- Documentation: [Framework Docs](docs/)
- Issues: [GitHub Issues](https://github.com/valhalla9898/Agentic-IAM/issues)
- Security: security@agentic-iam.com 

## Changelog

### v1.2.0 (Latest)
- Added enhanced ML models for trust scoring with IsolationForest
- Implemented additional compliance frameworks (PCI-DSS v4.0, NIST CSF)
- Added performance optimizations for high-throughput scenarios
- Introduced GraphQL subscription support for real-time events
- Integrated advanced anomaly detection algorithms

### v1.1.0
- Added GraphQL API interface
- Implemented Kubernetes operator scaffold
- Introduced ML trust scoring engine with scikit-learn
- Extended compliance standards (GDPR, HIPAA, SOX, PCI-DSS, ISO-27001)
- Added mobile API endpoints for agent registration
- Performance improvements with LRU caching and async operations
- UI cleanup and English-only interfaces

### v1.0.1
- Fixed missing imports in session management router
- Corrected parameter naming to avoid module shadowing
- Enhanced API router import structure
- Improved dependency injection

### v1.0.0
- Initial release with all core components
- Full authentication and authorization support
- Comprehensive audit and compliance framework
- Agent intelligence and trust scoring
- Multi-protocol transport binding
- Federated identity support
- RESTful API with FastAPI
- Web dashboard with Streamlit
- Kubernetes operator support
- Mobile agent endpoints
- Kubernetes CustomResourceDefinition (CRD) support

## Roadmap

### Recently Implemented Features (v1.2.0)
- ✅ Enhanced ML models for trust scoring (added IsolationForest for anomaly detection)
- ✅ Additional compliance frameworks (PCI-DSS v4.0, NIST CSF)
- ✅ Performance optimizations for high-throughput scenarios (async processing, LRU caching)
- ✅ GraphQL subscription support (agent registration events)
- ✅ Advanced anomaly detection algorithms (IsolationForest integration)
- ✅ Kubernetes native operators with CRD support
- ✅ Multi-cloud identity federation (AWS IAM, Azure AD, GCP)
- ✅ Quantum-resistant encryption algorithms
- ✅ Real-time dashboards with WebSocket integration
- ✅ API rate limiting with Redis backend

### Upcoming Features
- Blockchain-based audit trails
- Zero-knowledge proofs for privacy-preserving verification
- AI-powered threat intelligence integration
- Federated learning for distributed trust scoring
- Advanced RBAC with temporal constraints
- Decentralized identity (DID) with verifiable credentials
- Homomorphic encryption for secure data processing
- Edge computing support for IoT agent management
- Automated compliance reporting with AI insights
- Integration with SIEM systems (Splunk, ELK Stack)
- Mobile SDK for agent registration and management
- Voice-based authentication using biometrics
- Predictive analytics for security threat forecasting
- Serverless deployment options (AWS Lambda, Azure Functions)
- Container security scanning integration (Trivy, Clair)
- GDPR data portability and right to erasure automation
- Neural network-based behavioral profiling
- Quantum-safe key exchange protocols
- Decentralized autonomous organizations (DAO) for governance
- Augmented reality (AR) interface for agent visualization
- Machine learning operations (MLOps) for model deployment
- Carbon footprint tracking for green computing
- Ethical AI compliance and bias detection
- Swarm intelligence for collective decision making
- Holographic authentication methods
- Brain-computer interface (BCI) integration
- Nanobots security for microscopic threats
- Time-travel debugging for audit logs
- Interdimensional identity verification

## Report After Merge
Post-merge report — Summary of fixes applied

- Fixed a circular import between `api.main` and router modules by adding `api/dependencies.py` and using dependency injection to decouple imports.
- Rewrote `config/settings.py` to provide sensible defaults and include required fields such as encryption keys, mTLS, and MFA configuration.
- Added the missing router `api/routers/authentication.py` to provide authentication endpoints used by unit tests.
- Updated `agent_identity.py` and `agent_intelligence.py` to accept configuration via `initialize(**kwargs)` and added `shutdown` methods for graceful shutdown.
- Hardened `api/main.py` to safely import and register routers without causing import-time failures.
- Updated `conftest.py` for better compatibility with `pytest` and `pytest-asyncio` (converted the `mock_iam` fixture to a synchronous provider while preserving async mock methods).
- Unit test progress: the authentication login test now passes; remaining tests are being iteratively addressed.
This section documents the issues discovered after the recent merge, the root causes we found, and the exact remediation steps performed. All notes are in English.

1) Authentication / Login failures
- Problem: Dashboard login sometimes rejected valid credentials (default admin/user couldn't authenticate).
- Root cause: `users` table omitted `full_name` and `status` fields and password hashes were stored/handled inconsistently across code paths (bytes vs text). Some code paths inserted raw bytes without ensuring the lookup code normalized the returned type for `bcrypt.checkpw`.
- Fix applied:
    - Updated `database.py` to store `password_hash` as a BLOB and to explicitly insert `sqlite3.Binary(...)` when creating users.
    - Added `full_name` and `status` columns to the `users` schema and ensured `list_users`, `get_user_by_id`, `authenticate_user`, and `create_user` return and accept those fields.
    - Normalized fetched password hash types (handled `memoryview`, `bytes`, and `str`) before calling `bcrypt.checkpw` to avoid type issues.

2) User lifecycle helpers
- Problem: Tests and UI expected status management (suspend/reactivate) but the API lacked a helper.
- Fix applied: Added `update_user_status(user_id, new_status)` to `database.py` and made `change_password` consistently use `sqlite3.Binary` for updates.

3) Documentation and onboarding
- Added `HOW_TO_USE.md` with clear English instructions for installation, running the Streamlit dashboard, testing, and troubleshooting.
- Added a Windows desktop launcher `Open-Agentic-IAM.bat` that activates the repository `.venv` and runs the Streamlit dashboard on port 8501.

4) Streamlit "Report After Merge" viewer
- The file `dashboard/report_after_merge.py` reads this section from `README.md`. Use the Streamlit viewer to read a human-friendly rendering of these notes.

5) Other engineering notes
- Dependency injection and routers: Some routers caused circular imports at import-time. The fix used lazy dependency providers and defensive router imports (see `api/dependencies.py` and `api/main.py` changes).
- Manager lifecycle: Several managers were updated to expose `initialize(**kwargs)` and `shutdown()` to support TestClient lifespan and clean shutdown.
- Tests: We iteratively updated fixtures and dependency overrides; a number of tests still require focused fixes (session signatures, MFA route behavior). We'll continue iterating.

If you'd like, I can now:
- Run the local authentication tests (`python test_login.py`) and share the output.
- Capture a screenshot of the Streamlit dashboard at http://localhost:8501.
- Push these doc and launcher files to the remote branch and open a PR description draft.

### Notes: issues traced to recent contributor changes
The following items were traced to recent changes merged from the branch authored by Riyad (investigation based on commit timestamps and failing traces):
- Missing `authentication` router and some endpoints required by the dashboard — caused runtime import errors in the API startup.
- Circular import patterns between routers and core settings — caused app initialization failures unless dependency injection was deferred.
- Partial schema drift: user-related fields (`full_name`, `status`) were referenced by UI/tests but not present in the original DB schema.
- Mixed handling of password hashes (bytes vs text) across code paths.

For each item above we implemented the fixes described in the previous section.

6) Post-merge follow-up fixes (current)
- Problem: Several unit tests and runtime paths expected session objects and session-manager methods (`refresh_session`, `terminate_session`, `terminate_agent_sessions`) to exist and be called with keyword args.
- Root cause: `SessionManager` previously used simple dicts and positional-only methods which caused mismatches with tests that assert `refresh_session(session_id=..., refresh_token=...)` and other keyword calls.
- Fix applied:
    - Replaced lightweight session dicts with a `Session` class and updated `SessionManager` to store `Session` objects internally.
    - `create_session` now returns a `session_id` string (keeps compatibility) and `get_session` returns the `Session` object.
    - Added `refresh_session(session_id=..., refresh_token=...)`, `terminate_session(session_id, reason=...)`, and `terminate_agent_sessions(agent_id, reason=...)` to match test expectations.

7) MFA and router compatibility
- Problem: Tests attempted to call MFA endpoints (`/api/v1/auth/mfa/start`, `/api/v1/auth/mfa/verify`) but the router lacked these routes.
- Fix applied:
    - Added `/mfa/start` and `/mfa/verify` endpoints to `api/routers/authentication.py` delegating to `authentication_manager.start_mfa` and `authentication_manager.verify_mfa` when available (501 Not Implemented otherwise).
    - Updated code that calls `refresh_session` to use keyword args so unit tests that assert keyword-based calls now pass.

8) Exported types and graceful shutdown
- Problem: Several tests imported `AuthorizationDecision`, `Session`, and `RiskLevel` from top-level modules and failed because these names weren't exported.
- Fix applied:
    - Exported `AuthorizationDecision`, `Session`, and `RiskLevel` from the appropriate modules (`agent_identity.py`, `authorization.py`, and `agent_intelligence.py`).
    - Added missing `shutdown()` implementation to `AuditManager` so the core shutdown sequence can await it without errors.

Next steps: run the full test-suite and iterate on any remaining failures (I will run pytest and report back with failing tests and fixes). 
