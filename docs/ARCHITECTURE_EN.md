# 🏗️ Detailed System Architecture - Agentic-IAM

## Table of Contents

1. [Layers Overview](#layers-overview)
2. [Data Flow](#data-flow)
3. [Component Interactions](#component-interactions)
4. [Practical Examples](#practical-examples)

---

## Layers Overview

### Presentation Layer

```
┌─────────────────────────────────────────┐
│         Presentation Layer              │
├─────────────────────────────────────────┤
│  [Streamlit Dashboard] → http://localhost:8501
│  [REST API]            → http://localhost:8000
│  [GraphQL API]         → http://localhost:8000/graphql
└─────────────────────────────────────────┘
```

**Streamlit Dashboard** (`app.py`)
- Secure login system
- Interactive dashboard
- Agent management
- User management  
- Audit log viewer
- System settings

**REST API** (`api/main.py`)
- GET /health - Health check
- POST /api/agents - Create agent
- GET /api/agents - List agents
- POST /api/authenticate - Authenticate
- POST /api/authorize - Check permissions
- GET /api/events - Events log

**GraphQL API** (`api/graphql.py`)
- Query agents
- Query events
- Query permissions
- Mutation to register agents
- Mutation to update agents

---

### Business Logic Layer

```
┌──────────────────────────────────────────────────────────┐
│              Business Logic Layer                        │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  Authentication Manager                                 │
│  ├─ Verify credentials                                  │
│  ├─ Calculate trust scores                              │
│  ├─ Enforce brute-force protection                      │
│  └─ Log authentication events                           │
│                                                          │
│  Authorization Manager                                  │
│  ├─ Evaluate RBAC policies                              │
│  ├─ Evaluate ABAC policies                              │
│  ├─ Check context (environment, time, location)         │
│  └─ Log authorization decisions                         │
│                                                          │
│  Session Manager                                        │
│  ├─ Create sessions                                     │
│  ├─ Validate sessions                                   │
│  ├─ Manage expiration                                   │
│  └─ Detect suspicious patterns                          │
│                                                          │
│  Credential Manager                                     │
│  ├─ Create credentials                                  │
│  ├─ Store securely (encrypted)                          │
│  ├─ Auto-rotate credentials                             │
│  └─ Revoke expired credentials                          │
│                                                          │
│  Federated Identity Manager                             │
│  ├─ Link with external systems                          │
│  ├─ Sync permissions                                    │
│  ├─ Validate federated tokens                           │
│  └─ Manage trust relationships                          │
│                                                          │
│  Transport Security Manager                             │
│  ├─ Enforce mTLS                                        │
│  ├─ Verify certificates                                 │
│  ├─ Manage encryption keys                              │
│  └─ Support quantum-safe algorithms                     │
│                                                          │
│  Audit Manager                                          │
│  ├─ Log all operations                                  │
│  ├─ Generate audit trails                               │
│  ├─ Generate compliance reports                         │
│  └─ Track security events                               │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

#### Authentication Manager Details

**Responsibilities**:
```
✓ Verify credential validity
✓ Calculate trust scores
✓ Log authentication attempts
✓ Enforce rate limiting
```

**How it works**:
1. Extract credentials from request
2. Verify signature and validity
3. Check expiration
4. Calculate trust level
5. Log the attempt
6. Block on X failed attempts

**Key Methods**:
- `authenticate()` - Main verification
- `verify_credential()` - Check validity
- `calculate_trust_level()` - Compute score
- `is_credential_valid()` - Quick check

#### Authorization Manager Details

**Responsibilities**:
```
✓ Check RBAC policies
✓ Evaluate ABAC rules
✓ Assess context
✓ Log decisions
```

**How it works**:
1. Get agent's roles
2. Get role permissions
3. Check RBAC policies
4. Evaluate ABAC rules
5. Check context conditions
6. Make decision
7. Log decision

**Key Methods**:
- `authorize()` - Check permission
- `check_permission()` - Verify single permission
- `get_agent_permissions()` - List permissions
- `get_agent_roles()` - List roles

#### Session Manager Details

**Responsibilities**:
```
✓ Create sessions
✓ Validate sessions
✓ Handle expiration
✓ Detect threats
```

**How it works**:
1. Generate unique session ID
2. Record start time
3. Store metadata (IP, device, etc)
4. Set expiration time
5. Track activity
6. Detect suspicious patterns
7. Clean up expired sessions

**Key Methods**:
- `create_session()` - Start new session
- `validate_session()` - Check validity
- `end_session()` - Close session
- `renew_session()` - Extend expiration

#### Credential Manager Details

**Responsibilities**:
```
✓ Generate credentials
✓ Store securely
✓ Auto-rotate
✓ Revoke credentials
```

**How it works**:
1. Generate random secure credential
2. Encrypt before storing
3. Isolate by agent
4. Set expiration
5. Auto-rotate every X days
6. Invalidate old credentials
7. Retrieve safely on demand

**Key Methods**:
- `create_credential()` - Generate new
- `get_credential()` - Retrieve
- `rotate_credential()` - Create new + revoke old
- `revoke_credential()` - Invalidate

#### Federated Identity Manager Details

**Responsibilities**:
```
✓ Link with external providers
✓ Sync permissions
✓ Verify tokens
✓ Manage trust
```

**Supported Providers**:
- Azure AD
- AWS IAM
- Okta
- OpenID Connect

**Key Methods**:
- `federate_identity()` - Link identities
- `validate_federated_token()` - Verify token
- `sync_permissions()` - Sync from provider

#### Audit Manager Details

**Responsibilities**:
```
✓ Log operations
✓ Track who did what
✓ Record status
✓ Generate reports
```

**Events Logged**:
- Login/logout
- Authorization decisions
- Credential rotation
- Permission changes
- Status changes
- All errors

**Key Methods**:
- `log_event()` - Record event
- `get_events()` - Search events
- `generate_report()` - Create report

---

### Data Layer

```
┌──────────────────────────────────────────────────────┐
│           Data Persistence Layer                     │
├──────────────────────────────────────────────────────┤
│                                                      │
│  SQLite / PostgreSQL Database                       │
│  ├─ users table                                     │
│  ├─ agents table                                    │
│  ├─ events table                                    │
│  ├─ sessions table                                  │
│  └─ permissions table                               │
│                                                      │
│  Agent Registry (In-Memory)                         │
│  ├─ Fast lookup cache                               │
│  ├─ Live agent tracking                             │
│  └─ Sync with database                              │
│                                                      │
└──────────────────────────────────────────────────────┘
```

**Tables**:

```sql
-- Users
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash BLOB NOT NULL,
    email TEXT UNIQUE NOT NULL,
    role TEXT DEFAULT 'user',
    status TEXT DEFAULT 'active',
    created_at TIMESTAMP
);

-- Agents
CREATE TABLE agents (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    type TEXT,
    status TEXT DEFAULT 'active',
    metadata TEXT,
    created_at TIMESTAMP
);

-- Events
CREATE TABLE events (
    id INTEGER PRIMARY KEY,
    event_type TEXT NOT NULL,
    agent_id TEXT,
    action TEXT,
    details TEXT,
    status TEXT DEFAULT 'success',
    created_at TIMESTAMP
);

-- Sessions
CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    started_at TIMESTAMP,
    ended_at TIMESTAMP,
    status TEXT DEFAULT 'active'
);

-- Permissions
CREATE TABLE permissions (
    id INTEGER PRIMARY KEY,
    agent_id TEXT NOT NULL,
    resource TEXT NOT NULL,
    action TEXT NOT NULL,
    granted_at TIMESTAMP
);
```

---

## Data Flow

### Authentication Flow

```
1. Agent sends request
   ├─ Agent ID
   ├─ Credentials
   └─ Authentication method

2. Transport Security Manager
   ├─ Verify mTLS certificate
   ├─ Decrypt message
   └─ Allow continuation

3. Authentication Manager
   ├─ Extract credentials
   ├─ Verify signature
   ├─ Check expiration
   ├─ Calculate trust score
   └─ Return result

4. Log event
   ├─ Test result
   ├─ Agent ID
   └─ Timestamp

5. Return result
   ├─ Success with trust level
   └─ Or failure with reason
```

### Authorization Flow

```
1. Agent requests operation
   ├─ Agent ID
   ├─ Resource
   ├─ Action
   └─ Context

2. Authorization Manager
   ├─ Get agent roles
   ├─ Get role permissions
   ├─ Evaluate RBAC
   ├─ Evaluate ABAC
   ├─ Check context
   └─ Make decision

3. Decision
   ├─ Allow
   └─ Or deny with reason

4. Log decision
   ├─ Operation type
   ├─ Agent ID
   ├─ Resource
   ├─ Action
   ├─ Decision
   └─ Reason if denied

5. Execute operation
   ├─ If allowed, proceed
   └─ If denied, return error
```

### Session Creation Flow

```
1. Agent starts session
   ├─ Agent ID
   ├─ IP address
   ├─ Device info
   └─ Other metadata

2. Session Manager
   ├─ Generate unique ID
   ├─ Record start time
   ├─ Set expiration
   └─ Store metadata

3. Store session
   ├─ In memory (fast)
   └─ In database (persistent)

4. Return session ID
   ├─ Send to agent
   └─ Agent uses in requests

5. Validation on each request
   ├─ Check if valid
   ├─ Check if expired
   └─ Detect suspicious patterns

6. Session end
   ├─ Mark as ended
   ├─ Clean up resources
   └─ Log event
```

---

## Component Interactions

### Scenario 1: Agent Reads a File

```
Workflow:

1. Agent sends read request on /files/data.json
   
2. Transport Security Manager
   ├─ Verifies mTLS certificate ✓
   └─ Decrypts message ✓

3. Authentication Manager
   ├─ Extracts agent credentials ✓
   ├─ Verifies credentials ✓
   └─ Calculates trust level: 0.95 ✓

4. Session Manager
   ├─ Gets session ID from request ✓
   ├─ Validates session ✓
   ├─ Checks expiration ✓
   └─ All checks pass ✓

5. Audit Manager
   ├─ Logs: "agent-001 attempted read /files/data.json"
   └─ Status: pending

6. Authorization Manager
   ├─ Gets agent roles: ["reader"]
   ├─ Gets permissions: ["file:read"]
   ├─ Checks context ✓
   └─ Decision: ALLOW ✓

7. Audit Manager
   ├─ Updates: "Authorization: ALLOW"
   └─ Saves to database

8. Execute operation
   ├─ Read file ✓
   ├─ Send content to agent ✓
   └─ Encrypt (TLS) ✓

9. Final audit log
   ├─ Status: success
   └─ Save to database

Result: ✅ Agent gets file successfully
```

### Scenario 2: Agent Attempts Unauthorized Operation

```
Workflow:

1. Agent sends write request on /files/data.json

2. Transport Security ✓, Authentication ✓, Session ✓
   (Steps 2-5 pass like scenario 1)

3. Authorization Manager
   ├─ Gets agent roles: ["reader"]
   ├─ Gets permissions: ["file:read"] only
   ├─ Checks permission: file:write ❌
   └─ Decision: DENY (insufficient_permissions)

4. Audit Manager + Security Alert
   ├─ Logs: "Authorization: DENY"
   ├─ Creates security alert
   ├─ Increments failed attempts
   ├─ Possible agent blocking
   └─ Saves to database

5. Return error to agent
   ├─ HTTP 403 Forbidden
   └─ Message: "Permission denied"

Result: ❌ Request denied + logged
```

---

## Practical Examples

### Complete Authentication Example

```python
async def authenticate_and_verify():
    """Complete authentication workflow"""
    
    settings = Settings()
    iam = AgenticIAM(settings)
    await iam.initialize()
    
    # 1. Create agent identity
    identity = AgentIdentity.generate("my-agent")
    iam.agent_registry.register(identity)
    
    # 2. Authenticate
    result = await iam.authentication_manager.authenticate(
        agent_id="my-agent",
        credentials={"api_key": "secret"},
        method="api_key"
    )
    
    if result.success:
        print(f"✅ Authenticated with trust level: {result.trust_level}")
        
        # 3. Create session
        session = await iam.session_manager.create_session(
            agent_id="my-agent",
            metadata={"ip": "192.168.1.1"}
        )
        
        # 4. Check authorization
        decision = await iam.authorization_manager.authorize(
            agent_id="my-agent",
            resource="database://users",
            action="read"
        )
        
        if decision.allow:
            print("✅ Authorized to read database")
        else:
            print(f"❌ Authorization denied: {decision.reason}")
        
        # 5. End session
        await iam.session_manager.end_session(session.session_id)
    
    await iam.shutdown()
```

---

This is the complete architectural guide for Agentic-IAM!
