# Customer Integration Guide

This guide describes the recommended enterprise integration path for connecting a customer system to Agentic-IAM.

## Recommended Pattern

Use the following stack as the default integration approach:

1. REST over HTTPS for all business operations.
2. OAuth 2.0 / OpenID Connect with JWT bearer tokens for user and service authentication.
3. mTLS for internal service-to-service calls or high-trust environments.
4. API keys only for restricted admin or reporting endpoints.

This matches the current API surface exposed by the FastAPI application and the OIDC verification flow already present in the codebase.

## Base URLs

- API root: `/api/v1`
- Swagger UI: `/docs`
- ReDoc: `/redoc`
- OpenAPI spec: `/openapi.json`
- GraphQL: `/graphql`

## Authentication Flow

### 1. User or service gets a token

The customer system obtains an access token from its identity provider, such as Microsoft Entra ID, Okta, Keycloak, or another OIDC-compliant provider.

### 2. Token is sent to Agentic-IAM

Use this header on every protected request:

```http
Authorization: Bearer <access_token>
```

### 3. Token validation

Agentic-IAM validates the token against the issuer JWKS and checks issuer and audience claims.

## When to Use Each Method

### REST + OIDC/JWT

Use for most customer integrations, dashboards, backend services, and automation.

### mTLS

Use when the customer system is a backend service, internal gateway, or regulated workload that needs certificate-based trust.

### API Key

Use only for limited admin or reporting endpoints where a simpler shared-secret model is acceptable.

## Core Endpoints for Customer Systems

| Area | Example Paths | Typical Use |
| --- | --- | --- |
| Authentication | `/api/v1/auth` | Login, session creation, token verification |
| Agents | `/api/v1/agents` | Register, list, update, delete agents |
| Authorization | `/api/v1/authz` | Policy checks and access decisions |
| Sessions | `/api/v1/sessions` | Session tracking and lifecycle |
| Intelligence | `/api/v1/intelligence` | Trust scoring and behavior analysis |
| Audit | `/api/v1/audit` | Audit events and compliance tracking |
| Reports | `/reports` | Report listing, signing, and retrieval |
| Alerts | `/alerts` | Security alerts and incident intake |

## Typical Request Example

```bash
curl -X GET "http://localhost:8000/api/v1/agents" \
  -H "Authorization: Bearer <access_token>" \
  -H "Accept: application/json"
```

## Example OIDC Setup

1. Register the customer system as an application in the identity provider.
2. Configure the issuer and audience expected by Agentic-IAM.
3. Make sure the issuer publishes JWKS.
4. Send the resulting token in the Authorization header.

## Recommended Enterprise Deployment Pattern

- Put a reverse proxy or API gateway in front of Agentic-IAM.
- Terminate TLS at the gateway or at the app layer depending on compliance needs.
- Enforce OIDC at the edge when possible.
- Use mTLS between internal services if the customer network supports it.
- Keep API keys restricted to admin-only flows.

## Error Handling

- `401 Unauthorized`: missing or invalid token, missing API key, or invalid signature.
- `403 Forbidden`: authenticated but not allowed, or mTLS required but not present.
- `503 Service Unavailable`: IAM subsystem not initialized.

## Notes for Integrators

- Prefer REST + OIDC/JWT as the default contract.
- Use GraphQL only when the customer needs flexible read aggregation.
- Use signed URLs for time-limited report access.
