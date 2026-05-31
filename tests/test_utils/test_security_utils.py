import time
import re

from utils.security import (
    InputValidator,
    SQLInjectionProtection,
    RateLimiter,
    SessionSecurityManager,
    AccountSecurity,
    EncryptionManager,
    SecurityHeaders,
    AuditLogger,
    DDoSProtection,
    XSSProtection,
)


def test_input_validator_basic():
    assert InputValidator.sanitize_string('<b>hi</b>') == '&lt;b&gt;hi&lt;/b&gt;'
    assert InputValidator.validate_email('a@b.com')
    assert not InputValidator.validate_email('bad@@')
    assert InputValidator.validate_username('user_1')
    ok, msg = InputValidator.validate_password_strength('Aa1!aaaa')
    assert ok
    assert InputValidator.validate_agent_id('agent_123')
    assert not InputValidator.validate_agent_id('123')
    assert InputValidator.validate_json('{"a":1}')
    assert not InputValidator.validate_json('notjson')
    assert "''" in InputValidator.sql_safe_string("O'Neill")


def test_sql_injection_detection():
    assert SQLInjectionProtection.detect_sql_injection("' or '1'='1")
    assert not SQLInjectionProtection.detect_sql_injection('normal')
    assert SQLInjectionProtection.validate_query_param('normal')


def test_rate_limiter_behavior():
    rl = RateLimiter(max_attempts=2, window_seconds=1)
    ident = 'test-id'
    assert rl.is_allowed(ident)
    assert rl.is_allowed(ident)
    assert not rl.is_allowed(ident)
    # reset and allow again
    rl.reset(ident)
    assert rl.get_remaining(ident) == 2


def test_session_tokens_and_csrf():
    t1 = SessionSecurityManager.generate_session_token(16)
    t2 = SessionSecurityManager.generate_csrf_token(16)
    assert isinstance(t1, str) and isinstance(t2, str)
    assert SessionSecurityManager.validate_csrf_token(t2, t2)
    assert not SessionSecurityManager.validate_csrf_token(t2, t1)


def test_account_security_lockout():
    ac = AccountSecurity(max_failed_attempts=2, lockout_duration=1)
    user = 'u1'
    assert not ac.is_account_locked(user)
    ac.record_failed_attempt(user)
    assert not ac.is_account_locked(user)
    ac.record_failed_attempt(user)
    assert ac.is_account_locked(user)
    # wait for lockout to expire
    time.sleep(1.1)
    assert not ac.is_account_locked(user)


def test_encryption_hash_verify():
    h, s = EncryptionManager.hash_data('secret')
    assert EncryptionManager.verify_hash('secret', h, s)
    assert not EncryptionManager.verify_hash('wrong', h, s)


def test_security_headers_and_audit_logger():
    headers = SecurityHeaders.get_security_headers()
    assert 'X-Frame-Options' in headers
    # Audit logger should not raise
    AuditLogger.log_failed_login('u1', 'reason')
    AuditLogger.log_successful_login('u1')
    AuditLogger.log_permission_denied('u1', 'res', 'act')
    AuditLogger.log_suspicious_activity('u1', 'act')


def test_ddos_and_xss_protection():
    dd = DDoSProtection(requests_per_minute=2)
    ip = '1.2.3.4'
    assert dd.check_rate_limit(ip)
    assert dd.check_rate_limit(ip)
    assert not dd.check_rate_limit(ip)
    s = XSSProtection.sanitize_html('<script>alert(1)</script>hello')
    assert '<script' not in s
    assert XSSProtection.validate_url('http://example.com')
    assert not XSSProtection.validate_url('javascript:alert(1)')
