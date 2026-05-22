"""add security audit and attack tracking tables

Revision ID: 0002_security_audit
Revises: 0001_initial
Create Date: 2026-05-18 01:00:00.000000
"""

import sqlalchemy as sa

from alembic import op

revision = "0002_security_audit"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade():
    # Attack events table - logs all suspected/confirmed attacks
    op.create_table(
        "attack_events",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("attack_type", sa.String, nullable=False),  # e.g. 'sql_injection', 'brute_force', 'rate_limit'
        sa.Column("source_ip", sa.String, nullable=False),
        sa.Column("target_endpoint", sa.String),
        sa.Column("payload", sa.Text),  # The malicious payload or request
        sa.Column("severity", sa.String, server_default="medium"),  # low, medium, high, critical
        sa.Column("detected_at", sa.TIMESTAMP, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("status", sa.String, server_default="detected"),  # detected, blocked, mitigated
        sa.Column("description", sa.Text),
        sa.Column("metadata", sa.Text),  # JSON with additional context
    )

    # Security alerts table - notifications for dashboard/monitoring
    op.create_table(
        "security_alerts",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "alert_type", sa.String, nullable=False
        ),  # e.g. 'attack_detected', 'attack_blocked', 'threshold_exceeded'
        sa.Column("title", sa.String, nullable=False),
        sa.Column("message", sa.Text, nullable=False),
        sa.Column("severity", sa.String, server_default="medium"),  # low, medium, high, critical
        sa.Column("source_ip", sa.String),
        sa.Column("attack_event_id", sa.Integer, sa.ForeignKey("attack_events.id"), nullable=True),
        sa.Column("is_resolved", sa.Boolean, server_default="0"),
        sa.Column("created_at", sa.TIMESTAMP, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("resolved_at", sa.TIMESTAMP),
    )

    # Blocked IPs table - temporary or permanent IP blocks
    op.create_table(
        "blocked_ips",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("ip_address", sa.String, unique=True, nullable=False),
        sa.Column("reason", sa.String),
        sa.Column("attack_event_id", sa.Integer, sa.ForeignKey("attack_events.id")),
        sa.Column("block_duration_seconds", sa.Integer),  # NULL means permanent
        sa.Column("blocked_at", sa.TIMESTAMP, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("expires_at", sa.TIMESTAMP),
        sa.Column("is_active", sa.Boolean, server_default="1"),
    )

    # Failed login attempts tracking
    op.create_table(
        "failed_login_attempts",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("username", sa.String, nullable=False),
        sa.Column("source_ip", sa.String, nullable=False),
        sa.Column("attempted_at", sa.TIMESTAMP, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("reason", sa.String),  # e.g. 'invalid_credentials', 'account_locked'
    )

    # Indices for faster queries
    op.create_index("ix_attack_events_source_ip", "attack_events", ["source_ip"])
    op.create_index("ix_attack_events_attack_type", "attack_events", ["attack_type"])
    op.create_index("ix_attack_events_detected_at", "attack_events", ["detected_at"])
    op.create_index("ix_security_alerts_created_at", "security_alerts", ["created_at"])
    op.create_index("ix_blocked_ips_ip_address", "blocked_ips", ["ip_address"])
    op.create_index("ix_failed_login_attempts_username", "failed_login_attempts", ["username"])
    op.create_index("ix_failed_login_attempts_source_ip", "failed_login_attempts", ["source_ip"])


def downgrade():
    op.drop_index("ix_failed_login_attempts_source_ip")
    op.drop_index("ix_failed_login_attempts_username")
    op.drop_index("ix_blocked_ips_ip_address")
    op.drop_index("ix_security_alerts_created_at")
    op.drop_index("ix_attack_events_detected_at")
    op.drop_index("ix_attack_events_attack_type")
    op.drop_index("ix_attack_events_source_ip")
    op.drop_table("failed_login_attempts")
    op.drop_table("blocked_ips")
    op.drop_table("security_alerts")
    op.drop_table("attack_events")
