# API Documentation Structure

## Authentication Endpoints

### POST /api/v1/auth/authenticate
Authenticate an agent and create a session.

**Request:**
```json
{
  "agent_id": "agent:example",
  "method": "jwt",
  "credentials": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  },
  "source_ip": "192.168.1.1",
  "user_agent": "Mozilla/5.0..."
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "agent_id": "agent:example",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_at": "2025-12-30T10:30:00Z",
  "session_id": "sess_123456",
  "trust_level": 0.95,
  "auth_method": "jwt"
}
```

## Agent Management Endpoints

### GET /api/v1/agents
List all registered agents with optional filtering.

**Query Parameters:**
- `status`: Filter by status (active, inactive, suspended)
- `agent_type`: Filter by agent type
- `limit`: Results per page (default: 100)
- `offset`: Pagination offset (default: 0)

**Response (200 OK):**
```json
{
  "agents": [
    {
      "agent_id": "agent:example",
      "status": "active",
      "agent_type": "ai_agent",
      "description": "Example AI Agent",
      "capabilities": ["read", "write", "execute"],
      "trust_score": 0.95,
      "active_sessions": 2
    }
  ],
  "total": 1,
  "page": 1,
  "page_size": 100
}
```

### POST /api/v1/agents
Register a new agent.

**Request:**
```json
{
  "agent_id": "agent:new_agent",
  "agent_type": "ai_agent",
  "description": "New AI Agent",
  "capabilities": ["read", "write"],
  "metadata": {
    "version": "1.0.0",
    "environment": "production"
  }
}
```

**Response (201 Created):**
```json
{
  "agent_id": "agent:new_agent",
  "status": "active",
  "registration_date": "2025-12-29T10:00:00Z",
  "last_accessed": "2025-12-29T10:00:00Z"
}
```

## Session Management Endpoints

### GET /api/v1/sessions
List all active sessions.

**Query Parameters:**
- `agent_id`: Filter by agent
- `status_filter`: Filter by status (active, expired, terminated)
- `limit`: Results per page (default: 100)

**Response (200 OK):**
```json
[
  {
    "session_id": "sess_123456",
    "agent_id": "agent:example",
    "status": "active",
    "trust_level": 0.95,
    "auth_method": "jwt",
    "created_at": "2025-12-29T10:00:00Z",
    "expires_at": "2025-12-29T11:00:00Z"
  }
]
```

### POST /api/v1/sessions
Create a new session.

**Request:**
```json
{
  "agent_id": "agent:example",
  "auth_method": "jwt",
  "trust_level": 0.9,
  "ttl": 3600
}
```

**Response (201 Created):**
```json
{
  "session_id": "sess_new_123",
  "agent_id": "agent:example",
  "status": "active",
  "expires_at": "2025-12-29T11:00:00Z"
}
```

## Authorization Endpoints

### POST /api/v1/authz/check
Check if an agent is authorized to perform an action.

**Request:**
```json
{
  "agent_id": "agent:example",
  "resource": "/api/v1/sensitive_data",
  "action": "read",
  "context": {
    "ip_address": "192.168.1.1",
    "time_of_day": "business_hours"
  }
}
```

**Response (200 OK):**
```json
{
  "agent_id": "agent:example",
  "resource": "/api/v1/sensitive_data",
  "action": "read",
  "decision": "allow",
  "reason": "Agent has required permissions"
}
```

## Audit & Compliance Endpoints

### GET /api/v1/audit/events
Query audit events.

**Query Parameters:**
- `event_types`: Comma-separated event types
- `agent_id`: Filter by agent
- `start_time`: ISO 8601 datetime
- `end_time`: ISO 8601 datetime
- `limit`: Results per query (default: 100)

**Response (200 OK):**
```json
{
  "events": [
    {
      "event_id": "evt_123456",
      "event_type": "AUTH_SUCCESS",
      "agent_id": "agent:example",
      "timestamp": "2025-12-29T10:15:30Z",
      "severity": "INFO",
      "outcome": "success",
      "details": {
        "method": "jwt",
        "session_id": "sess_123456"
      }
    }
  ],
  "total": 1
}
```

## Intelligence & Trust Scoring

### GET /api/v1/intelligence/trust-score/{agent_id}
Get trust score for an agent.

**Response (200 OK):**
```json
{
  "agent_id": "agent:example",
  "overall_score": 0.95,
  "risk_level": "low",
  "confidence": 0.98,
  "components": {
    "authentication_history": 0.98,
    "resource_access_patterns": 0.92,
    "behavioral_consistency": 0.95
  },
  "recommendations": [
    "Continue monitoring access patterns",
    "Review occasional deviations"
  ]
}
```

## Error Responses

All endpoints may return error responses in the following format:

**400 Bad Request:**
```json
{
  "error": {
    "code": 400,
    "message": "Invalid request parameters",
    "type": "ValidationError"
  }
}
```

**401 Unauthorized:**
```json
{
  "error": {
    "code": 401,
    "message": "Authentication required",
    "type": "AuthenticationError"
  }
}
```

**403 Forbidden:**
```json
{
  "error": {
    "code": 403,
    "message": "Agent not authorized",
    "type": "AuthorizationError"
  }
}
```

**404 Not Found:**
```json
{
  "error": {
    "code": 404,
    "message": "Resource not found",
    "type": "NotFoundError"
  }
}
```

**500 Internal Server Error:**
```json
{
  "error": {
    "code": 500,
    "message": "Internal server error",
    "type": "InternalServerError"
  }
}
```

## Rate Limiting

All endpoints are rate-limited. Response headers include:
- `X-RateLimit-Limit`: Maximum requests per minute
- `X-RateLimit-Remaining`: Remaining requests in current window
- `X-RateLimit-Reset`: Unix timestamp when limit resets

**429 Too Many Requests:**
```json
{
  "error": {
    "code": 429,
    "message": "Rate limit exceeded",
    "retry_after": 60
  }
}
```

## Authentication Methods

### JWT Authentication
Include token in Authorization header:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### mTLS
Use client certificates for mutual TLS authentication.

### API Key
Include key in X-API-Key header:
```
X-API-Key: your-api-key-here
```

## Webhooks

Subscribe to events via webhooks for real-time notifications.

### Event Types
- `agent.created`
- `agent.updated`
- `agent.deleted`
- `session.created`
- `session.terminated`
- `auth.success`
- `auth.failure`
- `audit.event`

### Webhook Payload
```json
{
  "event_type": "auth.success",
  "timestamp": "2025-12-29T10:15:30Z",
  "agent_id": "agent:example",
  "data": {
    "session_id": "sess_123456",
    "method": "jwt"
  }
}
```
