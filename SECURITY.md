# 🛡️ Agentic-IAM Security Guide

## Overview

This document provides comprehensive security information about Agentic-IAM v2.0, including implemented protections, best practices, and attack prevention strategies.

---

## Security Features Implementation

### 1. ✅ SQL Injection Prevention

**Implementation**: Parameterized Queries + Input Validation

```python
from utils.security import SQLInjectionProtection

# Detection
is_malicious = SQLInjectionProtection.detect_sql_injection(user_input)

# Prevention
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))  # ✅ Safe
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")     # ❌ Unsafe
```

**Protected**: All database queries in Agentic-IAM use parameterized queries.

**Dangerous Patterns Detected**:
- `' or '1'='1` (Classic bypass)
- `--` (Comment injection)
- `UNION SELECT` (Data extraction)
- `DROP TABLE` (Destructive commands)
- `EXEC()` (Code execution)

---

### 2. ✅ Cross-Site Scripting (XSS) Prevention

**Implementation**: HTML Escaping + Input Sanitization

```python
from utils.security import XSSProtection, InputValidator

# Sanitization
safe_input = InputValidator.sanitize_string(user_input)
safe_html = XSSProtection.sanitize_html(html_content)

# URL Validation
if XSSProtection.validate_url(url):
    # Safe to use
```

**Protected Elements**:
- User input fields (Escaped)
- HTML rendering (Sanitized)
- Dynamic content (Validated)
- URLs (Checked for dangerous schemes)

**Dangerous Schemes Blocked**:
- `javascript:` - Code execution
- `data:` - Data URLs
- `vbscript:` - Visual Basic commands

---

### 3. ✅ Cross-Site Request Forgery (CSRF) Protection

**Implementation**: CSRF Tokens + SameSite Cookies

```python
from utils.security import SessionSecurityManager

# Generate token
csrf_token = SessionSecurityManager.generate_csrf_token()

# Validate token
is_valid = SessionSecurityManager.validate_csrf_token(
    request_token,
    session_token
)

# Secure cookies
cookies = SessionSecurityManager.secure_cookie_params()
# Includes: secure=True, httponly=True, samesite='Strict'
```

**Protection Strategy**:
- Unique token per session
- Token validation on state-changing operations
- SameSite cookie as backup
- Constant-time token comparison (prevents timing attacks)

---

### 4. ✅ Brute Force & Account Lockout Protection

**Implementation**: Rate Limiting + Account Lockout

```python
from utils.security import RateLimiter, AccountSecurity

# Rate Limiter
rate_limiter = RateLimiter(max_attempts=5, window_seconds=300)
if not rate_limiter.is_allowed(username):
    return "Too many attempts"

# Account Lockout
account_security = AccountSecurity(max_failed_attempts=5)
if account_security.is_account_locked(username):
    return "Account locked"

# Record attempt
account_security.record_failed_attempt(username)
```

**Protection Parameters**:
- 5 failed login attempts trigger lockout
- 5-minute rate limit window
- 5-minute account lockout duration
- Automatic unlock after timeout

---

### 5. ✅ DDoS Protection

**Implementation**: IP-Based Rate Limiting

```python
from utils.security import DDoSProtection

ddos_protection = DDoSProtection(requests_per_minute=60)
if not ddos_protection.check_rate_limit(client_ip):
    return "Rate limit exceeded"
```

**Protection Strategy**:
- Per-IP request tracking
- 60 requests per minute limit
- 1-minute rolling window
- Automatic cleanup of old entries

---

### 6. ✅ Input Validation & Sanitization

**Implementation**: Comprehensive Input Validation

```python
from utils.security import InputValidator

# Email Validation
if InputValidator.validate_email(email):
    # Valid email format
    pass

# Username Validation
if InputValidator.validate_username(username):
    # 3-32 chars, alphanumeric, hyphens, underscores
    pass

# Password Strength
is_strong, msg = InputValidator.validate_password_strength(password)
# Requires: 8+ chars, uppercase, lowercase, numbers, special chars

# Agent ID Validation
if InputValidator.validate_agent_id(agent_id):
    # Valid format: agent_xxxxx
    pass

# String Sanitization
safe_string = InputValidator.sanitize_string(user_input, max_length=255)
# Removes dangerous chars, HTML escape, length limit
```

**Validation Rules**:
- Email: RFC 5322 compliant (max 254 chars)
- Username: 3-32 chars, no special chars
- Password: 8+ chars, mixed case, numbers, symbols
- Agent ID: `agent_` prefix + alphanumeric
- Strings: Max 255 chars, HTML escaped, null-byte free

---

### 7. ✅ Password Security

**Implementation**: Bcrypt Hashing + Strength Requirements

**Password Rules**:
```
✅ Minimum 8 characters
✅ Uppercase letters (A-Z)
✅ Lowercase letters (a-z)
✅ Numbers (0-9)
✅ Special characters (!@#$%^&*)
```

**Hashing**:
- Algorithm: bcrypt
- Work factor: 12 (automatically updated)
- Cost: ~0.3 seconds per hash
- Salt: Unique per user

**Example**:
```python
from database import get_database

db = get_database()
# Passwords automatically hashed on storage
db.create_user("user", "email@example.com", "SecurePass123!", "user")

# Authentication verifies hash
user = db.authenticate_user("user", "SecurePass123!")
```

---

### 8. ✅ Session Security

**Implementation**: Secure Token Generation + Cookie Management

```python
from utils.security import SessionSecurityManager

# Generate session token
token = SessionSecurityManager.generate_session_token(length=32)
# Uses secrets module (cryptographically secure)

# Generate CSRF token
csrf_token = SessionSecurityManager.generate_csrf_token()

# Get secure cookie parameters
params = SessionSecurityManager.secure_cookie_params()
# {
#   'secure': True,          # HTTPS only
#   'httponly': True,        # Not accessible via JS
#   'samesite': 'Strict',    # CSRF protection
#   'max_age': 3600          # 1 hour expiry
# }
```

**Protection**:
- Cryptographically secure random generation
- HTTP-only flag prevents JavaScript access
- Secure flag requires HTTPS
- SameSite=Strict prevents cross-site sending
- 1-hour session expiry

---

### 9. ✅ Security HTTP Headers

**Implementation**: OWASP Recommended Headers

```python
from utils.security import SecurityHeaders

headers = SecurityHeaders.get_security_headers()
# Returns:
# {
#   'X-Content-Type-Options': 'nosniff',
#   'X-Frame-Options': 'DENY',
#   'X-XSS-Protection': '1; mode=block',
#   'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
#   'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'",
#   'Referrer-Policy': 'strict-origin-when-cross-origin',
#   'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
# }
```

**Header Protection**:
- **X-Content-Type-Options**: Prevents MIME type sniffing
- **X-Frame-Options**: Prevents clickjacking
- **X-XSS-Protection**: Browser XSS protection
- **HSTS**: Forces HTTPS for 1 year
- **CSP**: Restricts script sources
- **Referrer-Policy**: Controls referrer information
- **Permissions-Policy**: Disables unnecessary APIs

---

### 10. ✅ Audit Logging & Monitoring

**Implementation**: Comprehensive Security Event Logging

```python
from utils.security import AuditLogger

# Log failed login
AuditLogger.log_failed_login("admin", "Invalid credentials")

# Log successful login
AuditLogger.log_successful_login("admin")

# Log permission denied
AuditLogger.log_permission_denied("user", "agents", "delete")

# Log suspicious activity
AuditLogger.log_suspicious_activity("admin", "Multiple failed logins")

# Custom security event
AuditLogger.log_security_event(
    event_type="config_change",
    user="admin",
    action="update",
    resource="settings",
    result="success",
    details="Changed password policy"
)
```

**Logged Events**:
- Login attempts (success/failure)
- Permission denied actions
- Suspicious activities
- Configuration changes
- User management operations
- Agent lifecycle events

---

## Security Architecture

```
┌─────────────────────────────────────────────────┐
│           Frontend (Streamlit)                  │
│    • Input Validation                           │
│    • XSS Prevention                             │
│    • CSRF Token Generation                      │
└────────────────┬────────────────────────────────┘
                 │
┌────────────────▼────────────────────────────────┐
│         Application Security Layer              │
│    • Rate Limiting                              │
│    • Account Lockout                            │
│    • Session Management                         │
│    • RBAC/ABAC Authorization                    │
└────────────────┬────────────────────────────────┘
                 │
┌────────────────▼────────────────────────────────┐
│         Data Validation Layer                   │
│    • SQL Injection Prevention                   │
│    • XSS Sanitization                           │
│    • Input Sanitization                         │
│    • URL Validation                             │
└────────────────┬────────────────────────────────┘
                 │
┌────────────────▼────────────────────────────────┐
│         Database Layer                          │
│    • Parameterized Queries                      │
│    • Bcrypt Password Hashing                    │
│    • Audit Logging                              │
│    • Encrypted Storage (optional)               │
└─────────────────────────────────────────────────┘
```

---

## Threat Model & Mitigation

### 1. SQL Injection
| Threat | Mitigation | Status |
|--------|-----------|--------|
| Unauthorized data access | Parameterized queries | ✅ |
| Data modification | Input validation | ✅ |
| Data deletion | SQL injection detection | ✅ |

### 2. XSS (Cross-Site Scripting)
| Threat | Mitigation | Status |
|--------|-----------|--------|
| Session hijacking | HTTPOnly cookies | ✅ |
| Credential theft | HTML escaping | ✅ |
| Malware distribution | Input sanitization | ✅ |

### 3. CSRF (Cross-Site Request Forgery)
| Threat | Mitigation | Status |
|--------|-----------|--------|
| Unauthorized actions | CSRF tokens | ✅ |
| State changes | SameSite cookies | ✅ |

### 4. Brute Force Attacks
| Threat | Mitigation | Status |
|--------|-----------|--------|
| Account compromise | Account lockout | ✅ |
| Credential guessing | Rate limiting | ✅ |
| Dictionary attacks | Rate limiting | ✅ |

### 5. DDoS Attacks
| Threat | Mitigation | Status |
|--------|-----------|--------|
| Service unavailability | IP rate limiting | ✅ |
| Resource exhaustion | Request throttling | ✅ |

### 6. Session Attacks
| Threat | Mitigation | Status |
|--------|-----------|--------|
| Session fixation | Secure token generation | ✅ |
| Session hijacking | HTTPOnly + Secure flags | ✅ |
| Session fixation | Token rotation | ✅ |

### 7. Privilege Escalation
| Threat | Mitigation | Status |
|--------|-----------|--------|
| Unauthorized access | RBAC/Permission checks | ✅ |
| Role bypass | Permission validation | ✅ |

---

## Compliance & Standards

### OWASP Top 10 (2021) Coverage

| # | Vulnerability | Agentic-IAM | Implementation |
|---|---|---|---|
| 1 | Broken Access Control | ✅ | RBAC + Permission checks |
| 2 | Cryptographic Failures | ✅ | Bcrypt + HTTPS |
| 3 | Injection | ✅ | Parameterized queries + validation |
| 4 | Insecure Design | ✅ | Security review + testing |
| 5 | Security Misconfiguration | ✅ | Secure defaults |
| 6 | Vulnerable Components | ✅ | Regular updates |
| 7 | Authentication Failures | ✅ | Strong auth + MFA |
| 8 | Data Integrity Failures | ✅ | Audit logging |
| 9 | Logging & Monitoring Failures | ✅ | Comprehensive logging |
| 10 | SSRF | ✅ | URL validation |

### CWE Coverage

| CWE | Description | Status |
|-----|---|---|
| CWE-89 | SQL Injection | ✅ Prevented |
| CWE-79 | Cross-site Scripting | ✅ Prevented |
| CWE-352 | CSRF | ✅ Prevented |
| CWE-287 | Improper Authentication | ✅ Prevented |
| CWE-307 | Improper Restriction of Excessive Authentication Attempts | ✅ Prevented |
| CWE-613 | Insufficient Session Expiration | ✅ Prevented |

---

## Security Checklist for Deployment

### Pre-Deployment

- [ ] Change all default passwords
- [ ] Review database configuration
- [ ] Enable HTTPS/SSL certificates
- [ ] Configure firewall rules
- [ ] Set up backup strategy
- [ ] Enable audit logging
- [ ] Test all security features
- [ ] Review user permissions
- [ ] Validate input validation
- [ ] Test rate limiting

### Post-Deployment

- [ ] Monitor audit logs daily
- [ ] Check for failed login attempts
- [ ] Review user activities
- [ ] Update dependencies weekly
- [ ] Backup database daily
- [ ] Verify HTTPS is working
- [ ] Test disaster recovery
- [ ] Update security policies
- [ ] Train users on security
- [ ] Document security procedures

---

## Best Practices for Users

### Password Security
1. Use strong, unique passwords
2. Minimum 8 characters with mixed case, numbers, symbols
3. Never reuse passwords
4. Use password manager
5. Don't share passwords

### Session Security
1. Log out when finished
2. Don't access from public WiFi
3. Clear browser cache regularly
4. Use HTTPS only
5. Enable browser security features

### General Security
1. Report suspicious activities
2. Don't click suspicious links
3. Keep software updated
4. Use antivirus software
5. Enable firewall

---

## Incident Response

### If Account is Compromised
1. Change password immediately
2. Contact administrator
3. Check audit logs for unauthorized actions
4. Reset sessions
5. Review permission changes

### If Security Breach is Suspected
1. Contact administrator immediately
2. Isolate affected systems
3. Review audit logs
4. Change all passwords
5. Enable enhanced monitoring
6. Document incident

---

## Security Resources

- [OWASP Top 10](https://owasp.org/Top10/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [SANS Top 25](https://www.sans.org/top25-software-errors/)

---

## Support

For security issues, contact: security@agentic-iam.dev

**Last Updated**: February 13, 2026  
**Version**: 2.0  
**Status**: Production Ready ✅
