# ⚡ Quick Start & Best Practices - Agentic-IAM

## Quick Start (5 Minutes)

### Step 1: Setup Environment (1 minute)

```bash
cd C:\Users\Lenovo\Desktop\Agentic-IAM-main
.\.venv\Scripts\Activate
# Should see: (.venv) C:\...
```

### Step 2: Install Dependencies (1 minute)

```bash
pip install -r requirements.txt
```

### Step 3: Run (1 minute)

**Option 1 - Dashboard**:
```bash
python run_gui.py
# Open: http://localhost:8501
```

**Option 2 - API**:
```bash
python api/main.py
# API: http://localhost:8000
```

### Step 4: Access (2 minutes)

```
Dashboard:  http://localhost:8501
REST API:   http://localhost:8000
GraphQL:    http://localhost:8000/graphql
```

### Step 5: Login (1 minute)

| Role | Username | Password |
|------|----------|----------|
| Admin | admin | admin123 |
| User | user | user123 |

---

## Best Practices

### Security

#### ✅ Do:
```python
# Generate strong credentials
from secrets import token_urlsafe
secure_key = token_urlsafe(32)

# Don't log sensitive data
secret = get_credential(id)
# Don't print secret

# Use hashed passwords
password_hash = bcrypt.hash(password)
```

#### ❌ Don't:
```python
# Don't store plain passwords
password = "admin123"

# Don't put credentials in code
api_key = "sk-12345..."

# Don't print sensitive data
print(f"Password: {password}")  # ❌
```

---

### Performance

#### ✅ Do:
```python
# Use limits in queries
events = db.get_events(
    agent_id="agent-001",
    limit=100,  # Limit results
    start_date=datetime.now() - timedelta(days=7)  # Limit period
)

# Use caching
cached = await cache.get(f"perms:{agent_id}")
if not cached:
    perms = await fetch_permissions(agent_id)
    await cache.set(f"perms:{agent_id}", perms, ttl=3600)
```

#### ❌ Don't:
```python
# Don't fetch all data
events = db.get_events()  # Entire database!

# Don't repeat queries
for agent in agents:
    perms = await fetch_permissions(agent.id)  # Millions of queries!

# Don't use blocking operations in loops
for agent in agents:
    await slow_operation(agent)  # Slow!
```

---

### Error Handling

#### ✅ Do:
```python
try:
    result = await authenticate(agent_id, credentials)
except AuthenticationError as e:
    logger.error(f"Auth failed: {e}")
    return {"success": False, "reason": "invalid_credentials"}
except DatabaseError as e:
    logger.error(f"Database error: {e}")
    return {"success": False, "reason": "server_error"}
except Exception as e:
    logger.error(f"Unexpected error: {e}", exc_info=True)
    return {"success": False, "reason": "unknown_error"}
```

#### ❌ Don't:
```python
# Don't ignore errors
result = await authenticate(agent_id, credentials)
if result:  # What if exception?
    ...

# Don't print raw exceptions
except Exception as e:
    print(e)  # Not logged!

# Don't suppress all exceptions
try:
    ...
except:
    pass  # Error disappeared!
```

---

### Logging

#### ✅ Do:
```python
logger.info("Agent registered: assistant-001")
logger.warning(f"Failed auth attempt: {agent_id}")
logger.error(f"Database connection failed: {e}")
logger.debug(f"Agent permissions: {permissions}")
```

#### ❌ Don't:
```python
# Don't use print for logging
print("Agent registered")  # Not logged!

# Don't log sensitive data
logger.info(f"Password: {password}")  # ❌

# Don't ignore errors
try:
    ...
except:
    pass  # Error lost!
```

---

### Testing

#### ✅ Do:
```python
import pytest

@pytest.mark.asyncio
async def test_authentication_success():
    """Test successful authentication"""
    result = await authenticate("agent-001", {"key": "valid"})
    assert result.success == True
    assert result.trust_level > 0.5

@pytest.mark.asyncio
async def test_authorization_denied():
    """Test permission denial"""
    decision = await authorize(
        "user-agent",
        "sensitive-file",
        "delete"
    )
    assert decision.allow == False
```

#### ❌ Don't:
```python
# Don't test only happy path
def authenticate(...):
    # No tests! ❌

# Don't test only success cases
# Always test error cases too!
```

---

### Code Comments

#### ✅ Do:
```python
async def rotate_credential(credential_id: str) -> Credential:
    """
    Rotate credentials.
    
    Steps:
    1. Verify current credentials
    2. Create new credentials
    3. Revoke old credentials
    
    Args:
        credential_id: ID to rotate
    
    Returns:
        New credential
    
    Raises:
        CredentialNotFoundError: If not found
    """
    # Step 1: Verify
    old_cred = await self.get_credential(credential_id)
    if not old_cred:
        raise CredentialNotFoundError(...)
    
    # Step 2: Create new
    new_cred = await self.create_credential(...)
    
    # Step 3: Revoke old
    await self.revoke_credential(credential_id)
    
    return new_cred
```

#### ❌ Don't:
```python
# Don't write unclear code
async def rc(cid):
    x = await g(cid)  # What?
    y = await c(x.aid, ...)  # Why?
    await rv(cid)
    return y

# Don't use abbreviations
# Don't skip comments on complex code
```

---

## Troubleshooting

### Error: ModuleNotFoundError

```bash
# Activate virtual environment
.\.venv\Scripts\Activate

# Reinstall
pip install -r requirements.txt --force-reinstall
```

### Error: Database file not found

```bash
# Create data directory
mkdir data

# Restart application
python run_gui.py
```

### Error: Port already in use

```bash
# Windows - kill process
taskkill /PID <process_id> /F

# Linux/Mac - kill process
kill -9 <process_id>

# Or use different port
streamlit run app.py --server.port 8502
```

### Error: Slow response

**Solution**: Use query limits

```python
events = db.get_events(
    agent_id="agent-001",
    limit=100,  # Limit results
    start_date=datetime.now() - timedelta(days=7)  # Limit date
)
```

### Error: High memory usage

**Solution**: Clean up dead sessions

```python
async def cleanup():
    """Clean expired sessions"""
    dead_sessions = await session_manager.get_expired_sessions()
    for session in dead_sessions:
        await session_manager.end_session(session.session_id)
    logger.info(f"Cleaned {len(dead_sessions)} sessions")

# Run every hour
schedule.every(1).hours.do(cleanup)
```

---

## Frequently Asked Questions

### Q: How to change user password?

From dashboard:
- User Management → Select User → Change Password

Or programmatically:
```python
db = Database()
db.change_password(username="admin", new_password="new-pass")
```

---

### Q: Can I use PostgreSQL instead of SQLite?

Yes! Modify `database.py`:

```python
import psycopg2

connection_string = "postgresql://user:pass@localhost/db"
conn = psycopg2.connect(connection_string)
```

---

### Q: How to add agent programmatically?

```python
from core.agentic_iam import AgenticIAM

iam = AgenticIAM(settings)
await iam.initialize()

identity = AgentIdentity.generate("new-agent")
iam.agent_registry.register(identity)

await iam.shutdown()
```

---

### Q: How to get compliance reports?

```python
from datetime import datetime, timedelta

report = iam.compliance_manager.generate_report(
    framework="gdpr",
    start_date=datetime.now() - timedelta(days=7),
    end_date=datetime.now()
)

with open("report.html", "w") as f:
    f.write(report.as_html())
```

---

### Q: How to monitor performance?

```python
import time

start = time.time()
result = await authenticate(agent, credentials)
duration = time.time() - start

logger.info(f"Auth took {duration:.2f}s")

if duration > 0.1:
    logger.warning(f"Slow auth: {duration:.2f}s")
```

---

### Q: How to support multiple languages?

```python
translations = {
    "en": {
        "home": "Home",
        "agents": "Agents",
    },
    "es": {
        "home": "Inicio",
        "agents": "Agentes",
    }
}

st.write(translations[language]["home"])
```

---

### Q: How to backup database?

```python
import shutil
from datetime import datetime

# Backup
backup_name = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
shutil.copy("data/agentic_iam.db", f"backups/{backup_name}")

# Restore
shutil.copy(f"backups/{backup_name}", "data/agentic_iam.db")

# Schedule backup
schedule.every().day.at("02:00").do(backup_database)
```

---

### Q: How to send security alerts?

```python
async def send_alert(event_type, details):
    """Send security alert"""
    
    # Email
    send_email(
        to="admin@example.com",
        subject=f"Security Alert: {event_type}",
        body=details
    )
    
    # Slack
    send_slack(
        channel="#security",
        message=f"⚠️ {event_type}: {details}"
    )
    
    # SMS
    send_sms(
        phone="+1234567890",
        message=f"⚠️ {event_type}"
    )

# Use
if unauthorized_access:
    await send_alert("UNAUTHORIZED_ACCESS", f"Agent {id} attempted...")
```

---

## Performance Tips

**Optimize Queries**:
```python
# Add indexes
db.execute("""
    CREATE INDEX idx_agents_status ON agents(status);
    CREATE INDEX idx_events_agent_id ON events(agent_id);
""")

# Use pagination
events = db.get_events(offset=100, limit=50)

# Use database directly (faster)
agents = db.query("SELECT * FROM agents LIMIT 100")
```

**Scale Up**:
```python
# Use PostgreSQL for millions of records
# Add Redis for caching
# Use connection pooling
# Implement rate limiting
```

---

## Security Checklist

```
✅ Change default credentials
✅ Enable TLS/mTLS
✅ Use strong password hashing
✅ Implement audit logging
✅ Regular credential rotation
✅ Monitor suspicious activity
✅ Keep dependencies updated
✅ Use environment variables for secrets
✅ Implement rate limiting
✅ Regular security audits
```

---

Congratulations! You now understand Agentic-IAM! 🎉
