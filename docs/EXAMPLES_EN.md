# 💻 Practical Code Examples - Agentic-IAM

## Quick Examples

### 1. Register a New Agent

```python
from core.agentic_iam import AgenticIAM
from agent_identity import AgentIdentity
import asyncio

async def register_agent():
    """Register a new AI agent"""
    settings = Settings()
    iam = AgenticIAM(settings)
    await iam.initialize()
    
    # Generate identity
    identity = AgentIdentity.generate(
        agent_id="assistant-001",
        metadata={
            "name": "AI Assistant",
            "type": "llm",
            "version": "2.0"
        }
    )
    
    # Register
    iam.agent_registry.register(identity)
    
    print(f"✅ Agent registered: {identity.agent_id}")
    print(f"Public Key: {identity.get_public_key()}")
    
    await iam.shutdown()

asyncio.run(register_agent())
```

### 2. Authenticate Agent

```python
async def authenticate_agent():
    """Verify agent credentials"""
    
    settings = Settings()
    iam = AgenticIAM(settings)
    await iam.initialize()
    
    result = await iam.authentication_manager.authenticate(
        agent_id="assistant-001",
        credentials={"api_key": "secret-key"},
        method="api_key"
    )
    
    if result.success:
        print(f"✅ Verified - Trust level: {result.trust_level}")
    else:
        print(f"❌ Authentication failed")
    
    await iam.shutdown()

asyncio.run(authenticate_agent())
```

### 3. Check Permissions

```python
async def check_permissions():
    """Check what agent can do"""
    
    settings = Settings()
    iam = AgenticIAM(settings)
    await iam.initialize()
    
    # Single permission check
    decision = await iam.authorization_manager.authorize(
        agent_id="assistant-001",
        resource="database://users",
        action="read"
    )
    
    if decision.allow:
        print("✅ Permission granted")
    else:
        print(f"❌ Permission denied: {decision.reason}")
    
    # Check multiple permissions
    operations = [
        ("database://users", "read"),
        ("database://users", "write"),
        ("file://config", "read"),
    ]
    
    print("\nPermission Report:")
    for resource, action in operations:
        decision = await iam.authorization_manager.authorize(
            agent_id="assistant-001",
            resource=resource,
            action=action
        )
        
        status = "✅" if decision.allow else "❌"
        print(f"{status} {resource:30} {action}")
    
    await iam.shutdown()

asyncio.run(check_permissions())
```

### 4. Manage Sessions

```python
async def manage_sessions():
    """Create and manage sessions"""
    
    settings = Settings()
    iam = AgenticIAM(settings)
    await iam.initialize()
    
    # Create
    session = await iam.session_manager.create_session(
        agent_id="assistant-001",
        metadata={"ip": "192.168.1.100"}
    )
    
    print(f"📌 Session ID: {session.session_id}")
    
    # Validate
    is_valid = await iam.session_manager.validate_session(session.session_id)
    print(f"Valid: {'✅' if is_valid else '❌'}")
    
    # Renew
    if is_valid:
        renewed = await iam.session_manager.renew_session(session.session_id)
        print(f"Renewed until: {renewed.expected_end_time}")
    
    # End
    await iam.session_manager.end_session(session.session_id)
    print("✅ Session ended")
    
    await iam.shutdown()

asyncio.run(manage_sessions())
```

### 5. Manage Credentials

```python
async def manage_credentials():
    """Create, rotate, revoke credentials"""
    
    settings = Settings()
    iam = AgenticIAM(settings)
    await iam.initialize()
    
    # Create
    cred = await iam.credential_manager.create_credential(
        agent_id="assistant-001",
        credential_type="api_key",
        ttl_days=90
    )
    
    print(f"✅ Created: {cred.credential_id}")
    
    # Get
    secret = await iam.credential_manager.get_credential(cred.credential_id)
    print(f"Secret retrieved")
    
    # Rotate
    new_cred = await iam.credential_manager.rotate_credential(cred.credential_id)
    print(f"✅ Rotated - New ID: {new_cred.credential_id}")
    
    # Revoke
    await iam.credential_manager.revoke_credential(new_cred.credential_id)
    print("✅ Revoked")
    
    await iam.shutdown()

asyncio.run(manage_credentials())
```

### 6. REST API Usage

```python
import requests

BASE_URL = "http://localhost:8000"

# Health check
response = requests.get(f"{BASE_URL}/health")
print(response.json())

# List agents
response = requests.get(f"{BASE_URL}/api/agents")
agents = response.json()
print(f"Agents: {len(agents)}")

# Authenticate
auth_data = {
    "agent_id": "assistant-001",
    "credentials": {"api_key": "secret"},
    "method": "api_key"
}
response = requests.post(f"{BASE_URL}/api/authenticate", json=auth_data)
print(response.json())

# Authorize
auth_data = {
    "agent_id": "assistant-001",
    "resource": "database://users",
    "action": "read"
}
response = requests.post(f"{BASE_URL}/api/authorize", json=auth_data)
print(response.json())
```

### 7. GraphQL API Usage

```python
import requests

BASE_URL = "http://localhost:8000/graphql"

# Query agents
query = """
query {
    agents {
        id
        name
        status
    }
}
"""

response = requests.post(
    BASE_URL,
    json={"query": query}
)

agents = response.json()['data']['agents']
for agent in agents:
    print(f"• {agent['id']} - {agent['name']}")

# Query specific agent
query = """
query {
    agent(id: "assistant-001") {
        id
        name
        permissions {
            resource
            action
        }
    }
}
"""

response = requests.post(BASE_URL, json={"query": query})
agent = response.json()['data']['agent']
print(f"Permissions for {agent['name']}:")
for perm in agent['permissions']:
    print(f"  • {perm['resource']} - {perm['action']}")
```

### 8. Database Operations

```python
from database import Database

db = Database()

# Add agent
db.add_agent(
    agent_id="agent-001",
    name="AI Assistant",
    agent_type="llm"
)

# Log event
db.log_event(
    event_type="authentication_success",
    agent_id="agent-001",
    action="authenticate",
    details="Agent logged in successfully",
    status="success"
)

# Get events
events = db.get_events(agent_id="agent-001", limit=50)
for event in events:
    print(f"{event['event_type']} - {event['status']}")

# Add permission
db.add_permission(
    agent_id="agent-001",
    resource="database://users",
    action="read"
)

# Get permissions
perms = db.get_agent_permissions(agent_id="agent-001")
for perm in perms:
    print(f"{perm['resource']} - {perm['action']}")
```

### 9. Logging

```python
from audit_compliance import AuditManager

audit_mgr = AuditManager()

async def log_operations():
    """Log important operations"""
    
    # Log success
    await audit_mgr.log_event(
        event_type="agent_created",
        agent_id="new-agent",
        action="create",
        details="New agent registered",
        status="success"
    )
    
    # Log failure
    await audit_mgr.log_event(
        event_type="authorization_denied",
        agent_id="suspicious-agent",
        action="delete_database",
        details="Attempted unauthorized delete",
        status="failure"
    )
    
    # Search events
    events = audit_mgr.get_events(
        event_type="authorization_denied",
        limit=100
    )
    
    print(f"Found {len(events)} denied authorizations")
    
    # Generate report
    report = audit_mgr.generate_report(
        framework="gdpr",
        period="monthly"
    )
    
    print(f"Report: {report}")
```

### 10. Complete Workflow

```python
async def complete_workflow():
    """Full authentication and authorization workflow"""
    
    settings = Settings()
    iam = AgenticIAM(settings)
    await iam.initialize()
    
    print("=== Agentic-IAM Complete Workflow ===\n")
    
    # 1. Register
    print("1️⃣ Registering agent...")
    identity = AgentIdentity.generate("demo-agent")
    iam.agent_registry.register(identity)
    print("   ✅ Registered\n")
    
    # 2. Authenticate
    print("2️⃣ Authenticating...")
    auth = await iam.authentication_manager.authenticate(
        agent_id="demo-agent",
        credentials={"api_key": "demo-secret"},
        method="api_key"
    )
    print(f"   ✅ Trust level: {auth.trust_level}\n")
    
    # 3. Create session
    print("3️⃣ Creating session...")
    session = await iam.session_manager.create_session(
        agent_id="demo-agent"
    )
    print(f"   ✅ Session ID: {session.session_id}\n")
    
    # 4. Check authorization
    print("4️⃣ Checking authorization...")
    decision = await iam.authorization_manager.authorize(
        agent_id="demo-agent",
        resource="api://endpoint",
        action="call"
    )
    print(f"   {'✅ Allowed' if decision.allow else '❌ Denied'}\n")
    
    # 5. Create credential
    print("5️⃣ Creating credential...")
    cred = await iam.credential_manager.create_credential(
        agent_id="demo-agent",
        credential_type="api_key",
        ttl_days=30
    )
    print(f"   ✅ Credential ID: {cred.credential_id}\n")
    
    # 6. End session
    print("6️⃣ Ending session...")
    await iam.session_manager.end_session(session.session_id)
    print("   ✅ Session ended\n")
    
    print("=== Workflow Complete ===")
    
    await iam.shutdown()

asyncio.run(complete_workflow())
```

---

These examples cover the main use cases of Agentic-IAM!
