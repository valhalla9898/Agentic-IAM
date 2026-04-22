# 🏗️ System Architecture - Agentic-IAM

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [System Layers](#system-layers)
3. [Core Components](#core-components)
4. [Data Flow](#data-flow)
5. [Component Interactions](#component-interactions)
6. [Performance Characteristics](#performance-characteristics)

---

## Architecture Overview

Agentic-IAM implements a **layered, modular architecture** optimized for security, scalability, and high performance:

```
┌────────────────────────────────────────────────────────────┐
│ Application Layer (UI, REST API, GraphQL)                  │
├────────────────────────────────────────────────────────────┤
│ Business Logic Layer (Auth, Authz, Sessions, Audit)        │
├────────────────────────────────────────────────────────────┤
│ Data Persistence Layer (PostgreSQL, Redis Cache)           │
├────────────────────────────────────────────────────────────┤
│ Security Layer (mTLS, Encryption, Zero-Trust)              │
└────────────────────────────────────────────────────────────┘
```

---

## System Layers

### Layer 1: Presentation (User Interfaces & APIs)

Three presentation options serve different use cases:

```
┌─────────────────────────────────────────────┐
│         Presentation Layer                   │
├─────────────────────────────────────────────┤
│  [Web Dashboard]  → http://localhost:8501   │
│  [REST API]       → http://localhost:8000   │
│  [GraphQL]        → /graphql                │
└─────────────────────────────────────────────┘
```

#### Streamlit Dashboard (`app.py`)

**Purpose**: Intuitive web interface for non-technical administrators

**Capabilities**:
- 🔐 Secure authentication with multi-factor support
- 📊 Real-time monitoring dashboard
- 👥 agent and user management interface
- 📋 Searchable audit log viewer
- ⚙️ System configuration management

**Supporting Components**:
- `app.py` - Entry point
- `dashboard/components/` - Reusable UI elements
- `dashboard/realtime.py` - WebSocket-based updates

#### REST API (`api/main.py`)

**Purpose**: Standard HTTP API for system integrations

**Key Endpoints**:
```
GET    /health                  - Health status
POST   /api/v1/agents           - Create agent
GET    /api/v1/agents           - List agents
GET    /api/v1/agents/{id}      - Get agent details
POST   /api/v1/authenticate     - Validate credentials
POST   /api/v1/authorize        - Check permissions
GET    /api/v1/events/audit     - Audit trail
```

#### GraphQL API (`api/graphql.py`)

**Purpose**: Query language for complex data requirements

**Example Operations**:
```graphql
query {
  agents(status: ACTIVE) { 
    id name permissions roles
  }
  auditEvents(limit: 100) { 
    timestamp agentId action result
  }
}

mutation {
  registerAgent(name: "DataWorker") { 
    id certPath status
  }
}
```

---

### Layer 2: Business Logic (Core IAM Engine)

```
┌──────────────────────────────────────────────────────────────┐
│           Business Logic & IAM Services                      │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────────┐    ┌──────────────────┐               │
│  │ Authentication   │◄──►│ Authorization    │               │
│  │ Manager          │    │ Manager          │               │
│  └──────────────────┘    └──────────────────┘               │
│         ▲                        ▲                          │
│         │ credential data       │ permission rules         │
│  ┌──────┴────────────────────────┴──────────┐              │
│  │                                          │              │
│  ▼               ▼                          ▼              │
│  ┌──────────┐ ┌────────────┐ ┌────────────────┐           │
│  │ Session  │ │Credential  │ │ Transport      │           │
│  │ Manager  │ │ Manager    │ │ Security       │           │
│  └──────────┘ └────────────┘ └────────────────┘           │
│                                                             │
│  ┌──────────────────┐    ┌──────────────────┐             │
│  │ Federated        │    │ Risk & Anomaly   │             │
│  │ Identity         │    │ Detection        │             │
│  └──────────────────┘    └──────────────────┘             │
│                                                             │
│  ┌──────────────────────────────────────────┐             │
│  │ Audit & Compliance Logger                │             │
│  └──────────────────────────────────────────┘             │
│                                                             │
└──────────────────────────────────────────────────────────────┘
```

---

## Core Components

### 1. Authentication Manager

**Responsibility**: Validates agent identity through credentials

**Core Functions**:
```python
authenticate(agent_id, credentials, method) → AuthResult
verify_credential(credential) → bool
calculate_trust_score(credential) → float(0-100)
is_credential_valid(credential) → bool
```

**Implementation Details**:

- **Credential Validation**: Cryptographic verification of digital signatures
- **Trust Scoring**: Evaluates credential quality, age, and context
- **Rate Limiting**: Enforces maximum failed attempts per time window
- **Audit Trail**: Logs every authentication attempt with outcome
- **Account Protection**: Automatic lockout after N failed attempts

**Supported Methods**:
- Client TLS certificates (mTLS)
- OAuth 2.0 tokens
- SAML assertions
- API keys with rotation
- Hardware token (TOTP/HOTP)

---

### 2. Authorization Manager

**Responsibility**: Enforces access control policies

**Core Functions**:
```python
authorize(agent_id, resource, action, context) → Decision
check_permission(agent_id, permission) → bool
get_agent_roles(agent_id) → List[Role]
get_agent_permissions(agent_id) → List[Permission]
evaluate_policy(agent_id, policy) → bool
```

**Access Control Models**:

**RBAC (Role-Based Access Control)**:
```
Agent → Role(s) → Permission(s) → Decision
Example: Agent has "DataReader" role → read:data permission
```

**ABAC (Attribute-Based Access Control)**:
```
Decision = f(agent attributes, resource attributes, environment)
- Agent attributes: department, security_level, mfa_enabled
- Resource attributes: classification, owner, sensitivity
- Environment: time_of_day, location, network, risk_score
```

**Features**:
- Real-time rule evaluation (<20ms)
- Dynamic policy updates without redeployment
- Time-based restrictions (business hours only)
- Geolocation constraints
- Risk-score evaluation
- Security alerts on permission denial

---

### 3. Session Manager

**Responsibility**: Manages agent sessions and prevents hijacking

**Core Functions**:
```python
create_session(agent_id, metadata) → Session
validate_session(session_id) → bool
end_session(session_id) → void
get_active_sessions(agent_id) → List[Session]
detect_anomalies(session_id) → RiskScore
```

**Session Lifecycle**:
1. **Creation**: Generate UUID, capture device fingerprint, set TTL
2. **Validation**: Check expiration, verify device consistency
3. **Monitoring**: Track request patterns, detect impossible travel
4. **Termination**: Explicit logout or automatic expiration

**Anomaly Detection**:
- Impossible travel (teleportation detection)
- Unrecognized devices
- Concurrent session limits violation
- Unusual API patterns
- Peak data transfer detection

---

### 4. Credential Manager

**Responsibility**: Secure lifecycle management of credentials

**Core Functions**:
```python
create_credential(agent_id, type, ttl_days) → Credential
rotate_credential(credential_id) → NewCredential
revoke_credential(credential_id) → void
list_credentials(agent_id) → List[Credential]
```

**Security Measures**:
- **Storage**: AES-256-GCM encryption at rest
- **Rotation**: Automatic monthly rotation (configurable)
- **Audit**: Immutable log of all credential operations
- **Zero-Knowledge**: Plaintext credentials never logged
- **Expiration**: Automatic archival after TTL

**Credential Types**:
- TLS certificates (X.509)
- API keys (32-byte random)
- OAuth tokens with refresh
- Service account keys

---

### 5. Federated Identity Manager

**Responsibility**: Integrates with external identity providers

**Supported Providers**:
- Azure Active Directory (Entra ID)
- AWS IAM
- Okta
- Generic OIDC/OAuth2

**Core Functions**:
```python
federate_identity(agent_id, provider, external_id)
validate_federated_token(provider, token) → bool
sync_permissions_from_provider(provider)
handle_external_deprovisioning(agent_id)
```

**Features**:
- Two-way synchronization
- Automatic permission sync from external system
- Account deprovisioning on external deletion
- Cross-system audit trail
- Token validation with provider

---

### 6. Transport Security Manager

**Responsibility**: Protects all network communication

**Protocols**:
- **mTLS 1.3**: Mutual authentication between agent and server
- **Certificate Pinning**: Prevents man-in-the-middle attacks
- **Perfect Forward Secrecy**: Session keys are ephemeral
- **HSTS**: Enforces HTTPS always

**Functions**:
```python
verify_client_certificate(cert) → AgentIdentity
establish_secure_channel(agent_id) → SecureConnection
validate_tls_version()
enforce_cipher_suite_requirements()
```

---

### Layer 3: Data Persistence

```
┌──────────────────────────────────────────────────────────────┐
│                  Data Layer                                   │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────────────┐    ┌──────────────────┐            │
│  │ PostgreSQL           │    │ Redis Cache      │            │
│  │ (Persistent)         │    │ (In-Memory)      │            │
│  │                      │    │                  │            │
│  │ • users              │    │ • Active agents  │            │
│  │ • agents             │    │ • Session tokens │            │
│  │ • audit_events       │    │ • Permission     │            │
│  │ • sessions           │    │   cache          │            │
│  │ • permissions        │    │ • Rate limits    │            │
│  │ • certificates       │    │                  │            │
│  └──────────────────────┘    └──────────────────┘            │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

#### Data Schema

**Core tables**:

```sql
-- Users/Service Accounts
users (
  id UUID PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password_hash BYTEA NOT NULL,      -- Bcrypt 12-round
  role TEXT DEFAULT 'user',
  status TEXT DEFAULT 'active',
  created_at TIMESTAMP,
  last_login TIMESTAMP
)

-- AI Agents
agents (
  id TEXT PRIMARY KEY,               -- Unique per agent
  name TEXT NOT NULL,
  type TEXT,                         -- 'llm', 'worker', 'service'
  status TEXT DEFAULT 'active',
  metadata JSONB,                    -- Custom attributes
  created_at TIMESTAMP,
  updated_at TIMESTAMP
)

-- Sessions
sessions (
  id UUID PRIMARY KEY,
  agent_id TEXT NOT NULL,
  started_at TIMESTAMP,
  ended_at TIMESTAMP,
  status TEXT DEFAULT 'active',
  device_fingerprint TEXT,
  ip_address INET,
  user_agent TEXT
)

-- Immutable audit log
audit_events (
  id BIGSERIAL PRIMARY KEY,
  timestamp TIMESTAMP DEFAULT NOW(),
  agent_id TEXT,
  action TEXT NOT NULL,              -- 'login', 'read', 'write', etc.
  resource TEXT,
  result TEXT,                       -- 'allow', 'deny', 'error'
  reason TEXT,
  details JSONB,
  INDEX ON (agent_id, timestamp)    -- For fast queries
)

-- Role-based permissions
permissions (
  id SERIAL PRIMARY KEY,
  agent_id TEXT NOT NULL,
  resource TEXT NOT NULL,
  action TEXT NOT NULL,
  granted_at TIMESTAMP,
  granted_by TEXT,
  expires_at TIMESTAMP                -- Optional expiration
)
```

#### In-Memory Cache (Redis)

**Purpose**: Sub-millisecond access to frequently needed data

**Cached Items**:
```
agents:{agent_id}                    → Agent object
sessions:{session_id}                → Session metadata
permissions:{agent_id}               → Permission list
rate_limits:{agent_id}:{endpoint}    → Request count
```

**Cache Strategy**:
- TTL: 5 minutes for agents, 24h for permissions
- Invalidation: Immediate on update
- Consistency: Write-through to database

---

## Data Flow

### Authentication Flow

```
STEP 1: Agent sends request
├─ HTTP/mTLS to /api/v1/authenticate
├─ Body: { "credentials": {...}, "method": "tls" }
└─ Headers: mTLS certificate

STEP 2: Transport Security validates TLS
├─ Verify client certificate validity
├─ Extract agent ID from certificate
├─ Decrypt message (TLS session)
└─ Pass to Authentication Manager

STEP 3: Authentication Manager processes
├─ Lookup credential in database
├─ Verify signature/expiration
├─ Calculate trust score:
│  ├─ Credential type (5-100 points)
│  ├─ Age in days (0-20 points)
│  ├─ Rotation history (0-10 points)
│  └─ TOTAL: 95/100
├─ Log attempt to audit trail
└─ Return AuthResult { success: true, trust_score: 95 }

STEP 4: Session Manager called
├─ Check/Create session token
├─ Store in Redis cache
├─ Set 24-hour expiration
└─ Return session_id

STEP 5: Return to agent
├─ HTTP 200 OK
├─ Body: { "session_id": "xyz", "expires_in": 86400 }
├─ Log successful auth to database
└─ Send audit event
```

### Authorization Flow

```
STEP 1: Agent sends action request
├─ GET /api/v1/data/customers
├─ Headers: { "session_id": "xyz" }
└─ Context: timestamp, ip_address, etc.

STEP 2: Session validation
├─ Redis lookup: sessions:xyz
├─ Check not expired
├─ Check device fingerprint consistent
└─ Pass if valid

STEP 3: Authorization Manager evaluates
├─ Lookup agent permissions from database
│  ├─ Agent roles: ["data_reader", "auditor"]
│  ├─ Resource "data/customers": permission found? ✓
│  └─ Action "read": permission scope includes? ✓
│
├─ Evaluate ABAC constraints
│  ├─ Time: Business hours? 09:00-17:00 EST ✓
│  ├─ Environment: Production status? active ✓
│  ├─ Risk score: <50? (current: 15) ✓
│  └─ Device: Recognized? ✓
│
└─ Decision: ALLOW

STEP 4: Log to audit trail
├─ Authorization event recorded
├─ Status: ALLOW
├─ Reason: "valid permissions + context
└─ Saved to audit_events table

STEP 5: Execute operation
├─ Retrieve data
├─ Encrypt response
├─ Return to agent
└─ Log operation completion
```

### Session Anomaly Detection

```
Real-time monitoring:

IF (new_request.ip_address != previous_session.ip_address)
  AND time_difference < 60_seconds
  THEN flag as "impossible_travel"
       risk_score += 50
       
IF (request_count > rate_limit)
  THEN flag as "rate_limit_exceeded"
       risk_score += 30

IF (request_from_new_device)
  THEN require_mfa = true
       flag as "new_device"
       risk_score += 20

IF (risk_score > 75)
  THEN suspend_session()
       alert_security_team()
       force_re_authentication()
```

---

## Component Interactions

### Scenario: File Access Request

```
Timeline of component interactions:

T0ms   | Agent sends: GET /files/contracts.pdf (with mTLS cert)
T1ms   | Transport Security Manager
       ├─ Validates TLS handshake ✓
       ├─ Extracts agent ID from cert
       └─ Decrypts HTTP message
T2ms   | Authentication Manager
       ├─ Verifies cert signature (valid)
       ├─ Checks cert expiration (not expired)
       ├─ Calculates trust: 92/100
       └─ Result: AUTHENTICATED
T3ms   | Session Manager
       ├─ Validates session token (active)
       ├─ Checks expiration (6h remaining)
       ├─ Verifies device fingerprint (match)
       └─ Result: SESSION_VALID
T4ms   | Audit Logger
       ├─ Log: "agent-42 requested read /files/contracts.pdf"
       └─ Status: pending_auth
T5-15ms| Authorization Manager
       ├─ Lookup agent permissions (from Redis cache hit)
       ├─ Agent roles: ["lawyer", "auditor"]
       ├─ Check "file:read" permission
       ├─ Verify context constraints:
       │  ├─ Time: 14:30 (within 09:00-17:00) ✓
       │  ├─ Location: authorized_network ✓
       │  ├─ Device: recognized ✓
       │  └─ Risk: low (score: 5) ✓
       └─ Decision: ALLOW
T16ms  | Audit Logger
       ├─ Update log: "Authorization: ALLOW"
       └─ Reason: "matching_role + context_valid"
T17-20ms| Data Layer
       ├─ Query database: SELECT file
       ├─ Apply encryption layer
       └─ Package response
T21ms  | Transport Security Manager
       ├─ Encrypt response with session key
       ├─ Create TLS packet
       └─ Send to agent
T22ms  | Audit Logger
       ├─ Final log: "Operation complete: SUCCESS"
       ├─ Duration: 22ms
       └─ Save to audit_events table

TOTAL TIME: <50ms (within target)
```

---

## Performance Characteristics

| Operation | Latency | Bottleneck | Optimization |
|-----------|---------|-----------|--------------|
| Credential validation | 5-8ms | Crypto operations | Hardware acceleration |
| Session lookup | <1ms | Redis lookup | In-memory cache |
| Permission check | 3-5ms | DB query | Role cache + indexes |
| Auth complete | 15-25ms | Logging | Async audit writes |
| Authorization full | 20-50ms | Policy evaluation | ABAC rule index |
| API endpoint (end-to-end) | 30-60ms | TLS handshake | Session reuse |

**Target**: <100ms for 99th percentile

---

## High-Availability Design

**Redundancy**:
- Database: Master-slave replication
- Cache: Redis cluster with sentinel
- API servers: Horizontal scaling behind load balancer
- Stateless components: Can restart without data loss

**Failover**:
- Automatic database failover: 2-5 seconds
- Session recovery: From Redis cluster
- Audit continuity: Persist to secondary buffer

---

## Security Isolation

```
┌─────────────────────────────────────────┐
│        Untrusted Agent Request          │
└────────────────────┬────────────────────┘
                     │
        mTLS Mutual Authentication
                     │
        ┌────────────▼────────────┐
        │ TLS 1.3 Encrypted       │
        │ Channel (AES-256-GCM)   │
        └────────────┬────────────┘
                     │
        Cryptographic Verification
                     │
        ┌────────────▼─────────────┐
        │ Trusted Agent Identity   │
        └────────────┬─────────────┘
                     │
    Permission & Context Evaluation
                     │
        ┌────────────▼──────────────┐
        │ Access Control Decision   │
        │ (RBAC + ABAC)            │
        └────────────┬──────────────┘
                     │
         ┌───────────▼────────────┐
         │ Audit Trail Recorded   │
         │ (Immutable Log)        │
         └───────────┬────────────┘
                     │
         ┌───────────▼──────────────┐
         │ Operation Executed      │
         │ (If allowed)            │
         └──────────────────────────┘
```

---

<div align="center">

**Architecture proven for enterprise at scale**

**[← Back to Documentation](../README.md)**

</div>
