"""Database ORM models for attack tracking and security alerts."""

from datetime import datetime

from sqlalchemy import TIMESTAMP, Boolean, Column, ForeignKey, Integer, String, Text
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class AttackEvent(Base):
    """Logs detected and blocked attacks."""

    __tablename__ = "attack_events"

    id = Column(Integer, primary_key=True)
    attack_type = Column(
        String, nullable=False
    )  # sql_injection, brute_force, xss, rate_limit, etc.
    source_ip = Column(String, nullable=False)
    target_endpoint = Column(String)
    payload = Column(Text)
    severity = Column(String, default="medium")  # low, medium, high, critical
    detected_at = Column(TIMESTAMP, default=datetime.utcnow)
    status = Column(String, default="detected")  # detected, blocked, mitigated
    description = Column(Text)
    metadata = Column(Text)  # JSON


class SecurityAlert(Base):
    """Real-time security notifications for dashboard."""

    __tablename__ = "security_alerts"

    id = Column(Integer, primary_key=True)
    alert_type = Column(String, nullable=False)  # attack_detected, attack_blocked, etc.
    title = Column(String, nullable=False)
    message = Column(Text, nullable=False)
    severity = Column(String, default="medium")
    source_ip = Column(String)
    attack_event_id = Column(Integer, ForeignKey("attack_events.id"))
    is_resolved = Column(Boolean, default=False)
    created_at = Column(TIMESTAMP, default=datetime.utcnow)
    resolved_at = Column(TIMESTAMP)


class BlockedIP(Base):
    """Temporarily or permanently blocked IP addresses."""

    __tablename__ = "blocked_ips"

    id = Column(Integer, primary_key=True)
    ip_address = Column(String, unique=True, nullable=False)
    reason = Column(String)
    attack_event_id = Column(Integer, ForeignKey("attack_events.id"))
    block_duration_seconds = Column(Integer)  # NULL = permanent
    blocked_at = Column(TIMESTAMP, default=datetime.utcnow)
    expires_at = Column(TIMESTAMP)
    is_active = Column(Boolean, default=True)


class FailedLoginAttempt(Base):
    """Tracks failed login attempts for brute force detection."""

    __tablename__ = "failed_login_attempts"

    id = Column(Integer, primary_key=True)
    username = Column(String, nullable=False)
    source_ip = Column(String, nullable=False)
    attempted_at = Column(TIMESTAMP, default=datetime.utcnow)
    reason = Column(String)  # invalid_credentials, account_locked, etc.
