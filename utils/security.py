"""
Security Module for Agentic-IAM

Comprehensive security features to protect against common attacks:
- SQL Injection
- XSS (Cross-Site Scripting)
- CSRF (Cross-Site Request Forgery)
- Rate Limiting
- Input Validation
- CORS Protection
- Security Headers
- Account Lockout
- Brute Force Protection
"""

import hashlib
import hmac
import secrets
import re
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from functools import wraps
import json
from urllib.parse import quote, unquote
from html import escape

logger = logging.getLogger(__name__)


class InputValidator:
    """Validates and sanitizes user input to prevent injection attacks"""
    
    @staticmethod
    def sanitize_string(value: str, max_length: int = 255) -> str:
        """Sanitize string input to prevent XSS and injection"""
        if not isinstance(value, str):
            return ""
        
        # Remove dangerous characters and limit length
        value = value[:max_length]
        # Escape HTML special characters
        value = escape(value)
        # Remove null bytes
        value = value.replace('\x00', '')
        return value.strip()
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email)) and len(email) <= 254
    
    @staticmethod
    def validate_username(username: str) -> bool:
        """Validate username format (alphanumeric, underscores, hyphens)"""
        pattern = r'^[a-zA-Z0-9_-]{3,32}$'
        return bool(re.match(pattern, username))
    
    @staticmethod
    def validate_password_strength(password: str) -> Tuple[bool, str]:
        """Validate password meets security requirements"""
        if len(password) < 8:
            return False, "Password must be at least 8 characters"
        
        if not re.search(r'[a-z]', password):
            return False, "Password must contain lowercase letters"
        
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain uppercase letters"
        
        if not re.search(r'[0-9]', password):
            return False, "Password must contain numbers"
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "Password must contain special characters"
        
        return True, "Password is strong"
    
    @staticmethod
    def validate_agent_id(agent_id: str) -> bool:
        """Validate agent ID format"""
        pattern = r'^agent_[a-zA-Z0-9]{1,32}$'
        return bool(re.match(pattern, agent_id))
    
    @staticmethod
    def validate_uuid(value: str) -> bool:
        """Validate UUID format"""
        pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        return bool(re.match(pattern, value.lower()))
    
    @staticmethod
    def validate_json(json_string: str) -> bool:
        """Validate JSON structure"""
        try:
            json.loads(json_string)
            return True
        except (json.JSONDecodeError, ValueError):
            return False
    
    @staticmethod
    def sql_safe_string(value: str) -> str:
        """Escape string for SQL (use with parameterized queries)"""
        # This is a fallback - always use parameterized queries instead
        value = value.replace("'", "''")
        value = value.replace('"', '""')
        return value


class SQLInjectionProtection:
    """Prevents SQL injection attacks"""
    
    @staticmethod
    def detect_sql_injection(value: str) -> bool:
        """Detect potential SQL injection patterns"""
        dangerous_patterns = [
            r"('\s*or\s*'1'\s*=\s*'1)",
            r"(--|\#|\/\*|\*\/)",
            r"(union\s+select|select\s+\*|insert\s+into|update\s+|delete\s+from)",
            r"(drop\s+table|drop\s+database|exec\s*\(|execute\s*\()",
            r"(cast\s*\(|convert\s*\()",
            r"(benchmark\s*\(|sleep\s*\()",
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                logger.warning(f"Potential SQL injection detected: {value[:50]}")
                return True
        
        return False
    
    @staticmethod
    def validate_query_param(param: str) -> bool:
        """Validate query parameter is safe"""
        return not SQLInjectionProtection.detect_sql_injection(param)


class RateLimiter:
    """Implements rate limiting to prevent brute force and DoS attacks"""
    
    def __init__(self, max_attempts: int = 5, window_seconds: int = 300):
        """
        Initialize rate limiter
        
        Args:
            max_attempts: Maximum attempts per window
            window_seconds: Time window in seconds
        """
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.attempts: Dict[str, List[datetime]] = {}
    
    def is_allowed(self, identifier: str) -> bool:
        """Check if action is allowed for identifier"""
        now = datetime.utcnow()
        
        if identifier not in self.attempts:
            self.attempts[identifier] = []
        
        # Clean old attempts outside window
        cutoff = now - timedelta(seconds=self.window_seconds)
        self.attempts[identifier] = [
            t for t in self.attempts[identifier] if t > cutoff
        ]
        
        if len(self.attempts[identifier]) >= self.max_attempts:
            logger.warning(f"Rate limit exceeded for {identifier}")
            return False
        
        self.attempts[identifier].append(now)
        return True
    
    def reset(self, identifier: str):
        """Reset attempts for identifier"""
        self.attempts[identifier] = []
    
    def get_remaining(self, identifier: str) -> int:
        """Get remaining attempts for identifier"""
        if identifier not in self.attempts:
            return self.max_attempts
        
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=self.window_seconds)
        valid_attempts = len([
            t for t in self.attempts[identifier] if t > cutoff
        ])
        
        return max(0, self.max_attempts - valid_attempts)


class SessionSecurityManager:
    """Manages secure session handling"""
    
    @staticmethod
    def generate_session_token(length: int = 32) -> str:
        """Generate cryptographically secure session token"""
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def generate_csrf_token(length: int = 32) -> str:
        """Generate CSRF protection token"""
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def validate_csrf_token(token: str, expected_token: str) -> bool:
        """Validate CSRF token using constant-time comparison"""
        return hmac.compare_digest(token, expected_token)
    
    @staticmethod
    def secure_cookie_params() -> Dict[str, Any]:
        """Get secure cookie parameters"""
        return {
            'secure': True,  # Only send over HTTPS
            'httponly': True,  # Not accessible via JavaScript
            'samesite': 'Strict',  # CSRF protection
            'max_age': 3600  # 1 hour expiry
        }


class AccountSecurity:
    """Manages account security features"""
    
    def __init__(self, max_failed_attempts: int = 5, lockout_duration: int = 300):
        """
        Initialize account security
        
        Args:
            max_failed_attempts: Failed attempts before lockout
            lockout_duration: Lockout duration in seconds
        """
        self.max_failed_attempts = max_failed_attempts
        self.lockout_duration = lockout_duration
        self.failed_attempts: Dict[str, List[datetime]] = {}
        self.locked_accounts: Dict[str, datetime] = {}
    
    def is_account_locked(self, username: str) -> bool:
        """Check if account is locked"""
        if username not in self.locked_accounts:
            return False
        
        lockout_end = self.locked_accounts[username]
        if datetime.utcnow() > lockout_end:
            del self.locked_accounts[username]
            return False
        
        logger.warning(f"Account locked: {username}")
        return True
    
    def record_failed_attempt(self, username: str):
        """Record failed login attempt"""
        if username not in self.failed_attempts:
            self.failed_attempts[username] = []
        
        self.failed_attempts[username].append(datetime.utcnow())
        
        # Clean old attempts (24 hours)
        cutoff = datetime.utcnow() - timedelta(hours=24)
        self.failed_attempts[username] = [
            t for t in self.failed_attempts[username] if t > cutoff
        ]
        
        # Lock account if too many failures
        if len(self.failed_attempts[username]) >= self.max_failed_attempts:
            self.locked_accounts[username] = (
                datetime.utcnow() + timedelta(seconds=self.lockout_duration)
            )
            logger.error(f"Account locked due to failed attempts: {username}")
    
    def record_successful_login(self, username: str):
        """Reset failed attempts on successful login"""
        if username in self.failed_attempts:
            self.failed_attempts[username] = []
        if username in self.locked_accounts:
            del self.locked_accounts[username]


class EncryptionManager:
    """Manages data encryption"""
    
    @staticmethod
    def hash_data(data: str, salt: Optional[bytes] = None) -> Tuple[str, str]:
        """
        Hash data using SHA-256
        
        Returns:
            Tuple of (hash, salt) encoded as hex strings
        """
        if salt is None:
            salt = secrets.token_bytes(32)
        
        hash_obj = hashlib.pbkdf2_hmac('sha256', data.encode(), salt, 100000)
        return hash_obj.hex(), salt.hex()
    
    @staticmethod
    def verify_hash(data: str, data_hash: str, salt_hex: str) -> bool:
        """Verify hashed data"""
        salt = bytes.fromhex(salt_hex)
        hash_obj = hashlib.pbkdf2_hmac('sha256', data.encode(), salt, 100000)
        return hmac.compare_digest(hash_obj.hex(), data_hash)


class SecurityHeaders:
    """Manages security HTTP headers"""
    
    @staticmethod
    def get_security_headers() -> Dict[str, str]:
        """Get recommended security headers"""
        return {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'",
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
        }


class AuditLogger:
    """Comprehensive audit logging for security events"""
    
    @staticmethod
    def log_security_event(
        event_type: str,
        user: str,
        action: str,
        resource: str,
        result: str,
        details: Optional[str] = None
    ):
        """Log security-relevant event"""
        timestamp = datetime.utcnow().isoformat()
        log_entry = {
            'timestamp': timestamp,
            'event_type': event_type,
            'user': user,
            'action': action,
            'resource': resource,
            'result': result,
            'details': details
        }
        
        logger.info(f"SECURITY_EVENT: {json.dumps(log_entry)}")
    
    @staticmethod
    def log_failed_login(username: str, reason: str = "Invalid credentials"):
        """Log failed login attempt"""
        AuditLogger.log_security_event(
            event_type="login_failure",
            user=username,
            action="authentication",
            resource="user_session",
            result="denied",
            details=reason
        )
    
    @staticmethod
    def log_successful_login(username: str):
        """Log successful login"""
        AuditLogger.log_security_event(
            event_type="login_success",
            user=username,
            action="authentication",
            resource="user_session",
            result="allowed"
        )
    
    @staticmethod
    def log_permission_denied(username: str, resource: str, action: str):
        """Log permission denied event"""
        AuditLogger.log_security_event(
            event_type="permission_denied",
            user=username,
            action=action,
            resource=resource,
            result="denied"
        )
    
    @staticmethod
    def log_suspicious_activity(username: str, activity: str):
        """Log suspicious activity"""
        AuditLogger.log_security_event(
            event_type="suspicious_activity",
            user=username,
            action="monitoring",
            resource="user_activity",
            result="flagged",
            details=activity
        )


class DDoSProtection:
    """Protects against Distributed Denial of Service attacks"""
    
    def __init__(self, requests_per_minute: int = 60):
        self.max_requests = requests_per_minute
        self.request_log: Dict[str, List[datetime]] = {}
    
    def check_rate_limit(self, ip_address: str) -> bool:
        """Check if IP exceeds rate limit"""
        now = datetime.utcnow()
        
        if ip_address not in self.request_log:
            self.request_log[ip_address] = []
        
        # Clean requests older than 1 minute
        cutoff = now - timedelta(minutes=1)
        self.request_log[ip_address] = [
            t for t in self.request_log[ip_address] if t > cutoff
        ]
        
        if len(self.request_log[ip_address]) >= self.max_requests:
            logger.warning(f"DDoS protection triggered for IP: {ip_address}")
            return False
        
        self.request_log[ip_address].append(now)
        return True


class XSSProtection:
    """Prevents Cross-Site Scripting attacks"""
    
    @staticmethod
    def sanitize_html(html_content: str) -> str:
        """Sanitize HTML to prevent XSS"""
        dangerous_tags = ['<script', '<iframe', '<object', '<embed', 'javascript:']
        
        for tag in dangerous_tags:
            if tag.lower() in html_content.lower():
                logger.warning("Dangerous HTML tag detected")
                html_content = html_content.replace(tag, '')
        
        return escape(html_content)
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """Validate URL is safe"""
        dangerous_schemes = ['javascript:', 'data:', 'vbscript:']
        
        for scheme in dangerous_schemes:
            if url.lower().startswith(scheme):
                return False
        
        # Check URL format
        return url.startswith(('http://', 'https://', '/'))


__all__ = [
    'InputValidator',
    'SQLInjectionProtection',
    'RateLimiter',
    'SessionSecurityManager',
    'AccountSecurity',
    'EncryptionManager',
    'SecurityHeaders',
    'AuditLogger',
    'DDoSProtection',
    'XSSProtection',
]
