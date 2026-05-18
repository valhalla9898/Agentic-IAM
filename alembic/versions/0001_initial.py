"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-05-18 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

revision = '0001_initial'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'users',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('username', sa.String, unique=True, nullable=False),
        sa.Column('password_hash', sa.LargeBinary, nullable=False),
        sa.Column('email', sa.String, unique=True, nullable=False),
        sa.Column('role', sa.String, nullable=False, server_default='user'),
        sa.Column('full_name', sa.String, server_default=''),
        sa.Column('status', sa.String, server_default='active'),
        sa.Column('created_at', sa.TIMESTAMP, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('last_login', sa.TIMESTAMP),
    )

    op.create_table(
        'agents',
        sa.Column('id', sa.String, primary_key=True),
        sa.Column('name', sa.String, nullable=False),
        sa.Column('type', sa.String),
        sa.Column('status', sa.String, server_default='active'),
        sa.Column('created_at', sa.TIMESTAMP, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('updated_at', sa.TIMESTAMP, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('metadata', sa.Text),
    )

    op.create_table(
        'events',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('event_type', sa.String, nullable=False),
        sa.Column('agent_id', sa.String, nullable=True),
        sa.Column('action', sa.String),
        sa.Column('details', sa.Text),
        sa.Column('created_at', sa.TIMESTAMP, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('status', sa.String, server_default='success'),
    )

    op.create_table(
        'sessions',
        sa.Column('id', sa.String, primary_key=True),
        sa.Column('agent_id', sa.String, nullable=False),
        sa.Column('started_at', sa.TIMESTAMP, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('ended_at', sa.TIMESTAMP),
        sa.Column('status', sa.String, server_default='active'),
        sa.Column('metadata', sa.Text),
    )

    op.create_table(
        'tasks',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('agent_id', sa.String, nullable=False),
        sa.Column('task_type', sa.String, nullable=False),
        sa.Column('details', sa.Text),
        sa.Column('status', sa.String, server_default='pending'),
        sa.Column('created_at', sa.TIMESTAMP, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('updated_at', sa.TIMESTAMP, server_default=sa.text('CURRENT_TIMESTAMP')),
    )

    op.create_table(
        'agent_permissions',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('agent_id', sa.String, nullable=False),
        sa.Column('user_id', sa.Integer, nullable=False),
        sa.Column('permission', sa.String, nullable=False),
        sa.Column('granted_at', sa.TIMESTAMP, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('granted_by', sa.Integer),
    )

    op.create_table(
        'agent_capabilities',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('agent_id', sa.String, nullable=False),
        sa.Column('capability', sa.String, nullable=False),
        sa.Column('enabled', sa.Boolean, server_default='1'),
        sa.Column('created_at', sa.TIMESTAMP, server_default=sa.text('CURRENT_TIMESTAMP')),
    )

    op.create_table(
        'system_settings',
        sa.Column('setting_key', sa.String, primary_key=True),
        sa.Column('setting_value', sa.Text, nullable=False),
        sa.Column('updated_at', sa.TIMESTAMP, server_default=sa.text('CURRENT_TIMESTAMP')),
    )


def downgrade():
    op.drop_table('system_settings')
    op.drop_table('agent_capabilities')
    op.drop_table('agent_permissions')
    op.drop_table('tasks')
    op.drop_table('sessions')
    op.drop_table('events')
    op.drop_table('agents')
    op.drop_table('users')
