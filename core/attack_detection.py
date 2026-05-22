"""Attack detection engine - identifies and blocks malicious activities."""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.orm import Session

from core.db import AttackEvent, BlockedIP, FailedLoginAttempt, SecurityAlert


class AttackDetector:
    """Detects various attack patterns."""

    # SQL Injection patterns
    SQL_INJECTION_PATTERNS = [
        r"(\bUNION\b.*\bSELECT\b)",
        r"(\bOR\b\s*'?1'?\s*=\s*'?1'?)",
        r"(\bDROP\b\s+\bTABLE\b)",
        r"(\bINSERT\b.*\bVALUES\b)",
        r"(\bDELETE\b.*\bFROM\b)",
        r"(;.*--)",
        r"(\*/)",
    ]

    # XSS patterns
    XSS_PATTERNS = [
        r"(<script[\s\S]*?</script>)",
        r"(javascript:)",
        r"(on\w+\s*=)",
        r"(<iframe[\s\S]*?</iframe>)",
    ]

    @staticmethod
    def detect_sql_injection(payload: str) -> bool:
        """Check if payload contains SQL injection patterns."""
        if not payload:
            return False
        payload_upper = payload.upper()
        for pattern in AttackDetector.SQL_INJECTION_PATTERNS:
            if re.search(pattern, payload_upper, re.IGNORECASE):
                return True
        return False

    @staticmethod
    def detect_xss(payload: str) -> bool:
        """Check if payload contains XSS patterns."""
        if not payload:
            return False
        for pattern in AttackDetector.XSS_PATTERNS:
            if re.search(pattern, payload, re.IGNORECASE):
                return True
        return False

    @staticmethod
    def detect_brute_force(
        db: Session, username: str, source_ip: str, threshold: int = 5, window_minutes: int = 10
    ) -> bool:
        """Detect brute force attacks - multiple failed attempts in short time."""
        time_window = datetime.utcnow() - timedelta(minutes=window_minutes)
        count = (
            db.query(FailedLoginAttempt)
            .filter(
                FailedLoginAttempt.username == username,
                FailedLoginAttempt.source_ip == source_ip,
                FailedLoginAttempt.attempted_at >= time_window,
            )
            .count()
        )
        return count >= threshold

    @staticmethod
    def is_ip_blocked(db: Session, ip: str) -> bool:
        """Check if IP is blocked and not expired."""
        block = (
            db.query(BlockedIP)
            .filter(
                BlockedIP.ip_address == ip,
                BlockedIP.is_active,
            )
            .first()
        )

        if not block:
            return False

        # Check if block has expired
        if block.expires_at and datetime.utcnow() > block.expires_at:
            block.is_active = False
            db.commit()
            return False

        return True


class AttackLogger:
    """Logs attacks to database."""

    @staticmethod
    def log_attack(
        db: Session,
        attack_type: str,
        source_ip: str,
        payload: str = "",
        target_endpoint: str = "",
        severity: str = "medium",
        description: str = "",
        metadata: Optional[dict] = None,
    ) -> AttackEvent:
        """Log an attack event to database."""
        attack_event = AttackEvent(
            attack_type=attack_type,
            source_ip=source_ip,
            payload=payload[:500] if payload else None,  # Truncate large payloads
            target_endpoint=target_endpoint,
            severity=severity,
            description=description,
            metadata=json.dumps(metadata) if metadata else None,
            detected_at=datetime.utcnow(),
            status="detected",
        )
        db.add(attack_event)
        db.commit()
        return attack_event

    @staticmethod
    def log_alert(
        db: Session,
        alert_type: str,
        title: str,
        message: str,
        severity: str = "medium",
        source_ip: str = "",
        attack_event_id: Optional[int] = None,
    ) -> SecurityAlert:
        """Log a security alert to database."""
        alert = SecurityAlert(
            alert_type=alert_type,
            title=title,
            message=message,
            severity=severity,
            source_ip=source_ip,
            attack_event_id=attack_event_id,
            created_at=datetime.utcnow(),
        )
        db.add(alert)
        db.commit()
        return alert

    @staticmethod
    def block_ip(
        db: Session,
        ip: str,
        reason: str = "",
        duration_seconds: Optional[int] = None,
        attack_event_id: Optional[int] = None,
    ) -> BlockedIP:
        """Block an IP address."""
        now = datetime.utcnow()
        expires_at = None
        if duration_seconds:
            expires_at = now + timedelta(seconds=duration_seconds)

        block = BlockedIP(
            ip_address=ip,
            reason=reason,
            attack_event_id=attack_event_id,
            block_duration_seconds=duration_seconds,
            blocked_at=now,
            expires_at=expires_at,
            is_active=True,
        )
        db.add(block)
        db.commit()
        return block

    @staticmethod
    def log_failed_login(
        db: Session,
        username: str,
        source_ip: str,
        reason: str = "invalid_credentials",
    ) -> FailedLoginAttempt:
        """Log a failed login attempt."""
        attempt = FailedLoginAttempt(
            username=username,
            source_ip=source_ip,
            attempted_at=datetime.utcnow(),
            reason=reason,
        )
        db.add(attempt)
        db.commit()
        return attempt
