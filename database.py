"""
Database Management Module for Agentic-IAM

Handles SQLite database operations for logging events and storing agent data.
"""

import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# Optional secret manager integration
try:
    from secrets.key_vault import secret_manager
except ImportError:
    secret_manager = None
import logging

import bcrypt

try:
    from audit_exporter import append_audit_entry
except ImportError:
    append_audit_entry = None

logger = logging.getLogger(__name__)


def _default_db_path() -> str:
    """Return the default database path in a user-local application data folder."""
    base_dir = os.getenv("AGENTIC_IAM_DATA_DIR")
    if base_dir:
        return str(Path(base_dir) / "agentic_iam.db")

    local_app_data = os.getenv("LOCALAPPDATA") or os.getenv("APPDATA")
    if local_app_data:
        return str(Path(local_app_data) / "Agentic-IAM" / "agentic_iam.db")

    return str(Path("data") / "agentic_iam.db")


class Database:
    """SQLite database manager for Agentic-IAM"""

    def __init__(self, db_path: Optional[str] = None):
        """Initialize database connection"""
        self.db_path = db_path or _default_db_path()
        self._ensure_db_path()
        self.init_tables()

    def _ensure_db_path(self):
        """Ensure database directory exists"""
        db_dir = Path(self.db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)

    def get_connection(self):
        """Get database connection"""
        return sqlite3.connect(self.db_path)

    def init_tables(self):
        """Initialize database tables"""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Users table for dashboard authentication
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash BLOB NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    role TEXT DEFAULT 'user',
                    full_name TEXT DEFAULT '',
                    status TEXT DEFAULT 'active',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP
                )
            """)

            # Agents table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS agents (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    type TEXT,
                    status TEXT DEFAULT 'active',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    metadata TEXT
                )
            """)

            # Events/Audit log table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    agent_id TEXT,
                    action TEXT,
                    details TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'success',
                    FOREIGN KEY (agent_id) REFERENCES agents(id)
                )
            """)

            # Sessions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ended_at TIMESTAMP,
                    status TEXT DEFAULT 'active',
                    metadata TEXT,
                    FOREIGN KEY (agent_id) REFERENCES agents(id)
                )
            """)

            # Tasks table for operational and remediation work
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    task_type TEXT NOT NULL,
                    details TEXT,
                    status TEXT DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (agent_id) REFERENCES agents(id)
                )
            """)

            # Agent permissions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS agent_permissions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    user_id INTEGER NOT NULL,
                    permission TEXT NOT NULL,
                    granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    granted_by INTEGER,
                    FOREIGN KEY (agent_id) REFERENCES agents(id),
                    FOREIGN KEY (user_id) REFERENCES users(id),
                    FOREIGN KEY (granted_by) REFERENCES users(id)
                )
            """)

            # Agent capabilities tracking table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS agent_capabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    capability TEXT NOT NULL,
                    enabled BOOLEAN DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (agent_id) REFERENCES agents(id)
                )
            """)

            # Persistent system configuration for onboarding and integration settings
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS system_settings (
                    setting_key TEXT PRIMARY KEY,
                    setting_value TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Security telemetry tables for attack monitoring and auto-containment
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS attack_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    attack_type TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    target_endpoint TEXT,
                    payload TEXT,
                    severity TEXT DEFAULT 'medium',
                    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'detected',
                    description TEXT,
                    metadata TEXT
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_type TEXT NOT NULL,
                    title TEXT NOT NULL,
                    message TEXT NOT NULL,
                    severity TEXT DEFAULT 'medium',
                    source_ip TEXT,
                    attack_event_id INTEGER,
                    is_resolved BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    resolved_at TIMESTAMP,
                    FOREIGN KEY (attack_event_id) REFERENCES attack_events(id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT UNIQUE NOT NULL,
                    reason TEXT,
                    attack_event_id INTEGER,
                    block_duration_seconds INTEGER,
                    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1,
                    FOREIGN KEY (attack_event_id) REFERENCES attack_events(id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_notification_queue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_name TEXT NOT NULL,
                    target_url TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    attempts INTEGER DEFAULT 0,
                    max_attempts INTEGER DEFAULT 3,
                    last_error TEXT,
                    next_retry_at TIMESTAMP,
                    last_attempt_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_audit_chain (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chain_name TEXT NOT NULL,
                    previous_hash TEXT,
                    current_hash TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS incident_exports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    export_type TEXT NOT NULL,
                    file_name TEXT,
                    summary TEXT,
                    export_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_cases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_key TEXT UNIQUE NOT NULL,
                    title TEXT NOT NULL,
                    status TEXT DEFAULT 'open',
                    severity TEXT DEFAULT 'medium',
                    summary TEXT,
                    correlation_id TEXT,
                    attack_types TEXT,
                    source_ips TEXT,
                    attack_ids TEXT,
                    alert_ids TEXT,
                    blocked_ips TEXT,
                    recommended_actions TEXT,
                    playbook_name TEXT,
                    integrity_hash TEXT,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    closed_at TIMESTAMP
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_playbook_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER,
                    case_key TEXT,
                    playbook_name TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    auto_applied BOOLEAN DEFAULT 0,
                    details TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (case_id) REFERENCES security_cases(id)
                )
            """)

            # Ensure schema migrations for older DBs: add missing columns
            cursor.execute("PRAGMA table_info(users)")
            existing_cols = [r[1] for r in cursor.fetchall()]
            if "full_name" not in existing_cols:
                cursor.execute("ALTER TABLE users ADD COLUMN full_name TEXT DEFAULT ''")
            if "status" not in existing_cols:
                cursor.execute("ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'active'")

            # Optional demo seed users for local workshops only.
            allow_demo_seed = os.getenv("AGENTIC_IAM_ALLOW_DEMO_USERS", "false").lower() == "true"
            if allow_demo_seed:
                cursor.execute("SELECT COUNT(*) FROM users")
                has_users = cursor.fetchone()[0] > 0
                if not has_users:
                    self._seed_demo_users(cursor)

            conn.commit()
            logger.info("Database tables initialized successfully")

    def record_attack_event(
        self,
        attack_type: str,
        source_ip: str,
        target_endpoint: Optional[str] = None,
        payload: Optional[str] = None,
        severity: str = "medium",
        status: str = "detected",
        description: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> Optional[int]:
        """Persist an attack event to the local telemetry store."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO attack_events (
                        attack_type, source_ip, target_endpoint, payload,
                        severity, status, description, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        attack_type,
                        source_ip,
                        target_endpoint,
                        payload,
                        severity,
                        status,
                        description,
                        json.dumps(metadata or {}),
                    ),
                )
                conn.commit()
                return cursor.lastrowid
        except sqlite3.DatabaseError as exc:
            logger.error(f"Error recording attack event: {exc}")
            return None

    def record_security_alert(
        self,
        alert_type: str,
        title: str,
        message: str,
        severity: str = "medium",
        source_ip: Optional[str] = None,
        attack_event_id: Optional[int] = None,
        is_resolved: bool = False,
    ) -> Optional[int]:
        """Persist a security alert to the local telemetry store."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO security_alerts (
                        alert_type, title, message, severity, source_ip,
                        attack_event_id, is_resolved
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        alert_type,
                        title,
                        message,
                        severity,
                        source_ip,
                        attack_event_id,
                        int(is_resolved),
                    ),
                )
                conn.commit()
                return cursor.lastrowid
        except sqlite3.DatabaseError as exc:
            logger.error(f"Error recording security alert: {exc}")
            return None

    def block_ip(
        self,
        ip_address: str,
        reason: str,
        attack_event_id: Optional[int] = None,
        duration_seconds: Optional[int] = None,
        is_active: bool = True,
    ) -> bool:
        """Record or refresh a blocked IP entry."""
        try:
            expires_at = None
            if duration_seconds:
                expires_at = datetime.utcnow().timestamp() + int(duration_seconds)
                expires_at = datetime.utcfromtimestamp(expires_at).isoformat()

            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO blocked_ips (
                        ip_address, reason, attack_event_id,
                        block_duration_seconds, expires_at, is_active
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(ip_address) DO UPDATE SET
                        reason = excluded.reason,
                        attack_event_id = excluded.attack_event_id,
                        block_duration_seconds = excluded.block_duration_seconds,
                        expires_at = excluded.expires_at,
                        is_active = excluded.is_active,
                        blocked_at = CURRENT_TIMESTAMP
                    """,
                    (
                        ip_address,
                        reason,
                        attack_event_id,
                        duration_seconds,
                        expires_at,
                        int(is_active),
                    ),
                )
                conn.commit()
                return True
        except sqlite3.DatabaseError as exc:
            logger.error(f"Error blocking IP {ip_address}: {exc}")
            return False

    def list_attack_events(self, limit: int = 100) -> List[Dict]:
        """Return recent attack events ordered newest first."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT id, attack_type, source_ip, target_endpoint, payload,
                           severity, detected_at, status, description, metadata
                    FROM attack_events
                    ORDER BY detected_at DESC
                    LIMIT ?
                    """,
                    (limit,),
                )
                rows = cursor.fetchall()
                items = []
                for row in rows:
                    items.append(
                        {
                            "id": row[0],
                            "attack_type": row[1],
                            "source_ip": row[2],
                            "target_endpoint": row[3],
                            "payload": row[4],
                            "severity": row[5],
                            "detected_at": row[6],
                            "status": row[7],
                            "description": row[8],
                            "metadata": json.loads(row[9]) if row[9] else {},
                        }
                    )
                return items
        except Exception as exc:
            logger.error(f"Error listing attack events: {exc}")
            return []

    def list_security_alerts(self, limit: int = 100, active_only: bool = False) -> List[Dict]:
        """Return recent security alerts."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                query = """
                    SELECT id, alert_type, title, message, severity, source_ip,
                           attack_event_id, is_resolved, created_at, resolved_at
                    FROM security_alerts
                """
                params = []
                if active_only:
                    query += " WHERE is_resolved = 0"
                query += " ORDER BY created_at DESC LIMIT ?"
                params.append(limit)
                cursor.execute(query, params)
                rows = cursor.fetchall()
                items = []
                for row in rows:
                    items.append(
                        {
                            "id": row[0],
                            "alert_type": row[1],
                            "title": row[2],
                            "message": row[3],
                            "severity": row[4],
                            "source_ip": row[5],
                            "attack_event_id": row[6],
                            "is_resolved": bool(row[7]),
                            "created_at": row[8],
                            "resolved_at": row[9],
                        }
                    )
                return items
        except Exception as exc:
            logger.error(f"Error listing security alerts: {exc}")
            return []

    def list_blocked_ips(self, active_only: bool = True) -> List[Dict]:
        """Return blocked IP records."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                query = """
                    SELECT ip_address, reason, attack_event_id, block_duration_seconds,
                           blocked_at, expires_at, is_active
                    FROM blocked_ips
                """
                params = []
                if active_only:
                    query += " WHERE is_active = 1"
                query += " ORDER BY blocked_at DESC"
                cursor.execute(query, params)
                rows = cursor.fetchall()
                items = []
                for row in rows:
                    items.append(
                        {
                            "ip": row[0],
                            "reason": row[1],
                            "attack_event_id": row[2],
                            "block_duration_seconds": row[3],
                            "blocked_at": row[4],
                            "expires_at": row[5],
                            "is_active": bool(row[6]),
                        }
                    )
                return items
        except Exception as exc:
            logger.error(f"Error listing blocked IPs: {exc}")
            return []

    def enqueue_security_notification(
        self,
        target_name: str,
        target_url: str,
        payload: Dict,
        status: str = "pending",
        attempts: int = 0,
        max_attempts: int = 3,
        last_error: Optional[str] = None,
        next_retry_at: Optional[str] = None,
    ) -> Optional[int]:
        """Store a notification dispatch request for later retry."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO security_notification_queue (
                        target_name, target_url, payload, status,
                        attempts, max_attempts, last_error, next_retry_at,
                        last_attempt_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    """,
                    (
                        target_name,
                        target_url,
                        json.dumps(payload),
                        status,
                        attempts,
                        max_attempts,
                        last_error,
                        next_retry_at,
                    ),
                )
                conn.commit()
                return cursor.lastrowid
        except Exception as exc:
            logger.error(f"Error enqueuing security notification: {exc}")
            return None

    def list_security_notifications(self, limit: int = 100, status: Optional[str] = None) -> List[Dict]:
        """Return queued or dispatched security notifications."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                query = """
                    SELECT id, target_name, target_url, payload, status, attempts,
                           max_attempts, last_error, next_retry_at, last_attempt_at,
                           created_at, updated_at
                    FROM security_notification_queue
                """
                params: List = []
                if status:
                    query += " WHERE status = ?"
                    params.append(status)
                query += " ORDER BY created_at DESC LIMIT ?"
                params.append(limit)
                cursor.execute(query, params)
                rows = cursor.fetchall()
                items = []
                for row in rows:
                    items.append(
                        {
                            "id": row[0],
                            "target_name": row[1],
                            "target_url": row[2],
                            "payload": json.loads(row[3]) if row[3] else {},
                            "status": row[4],
                            "attempts": row[5],
                            "max_attempts": row[6],
                            "last_error": row[7],
                            "next_retry_at": row[8],
                            "last_attempt_at": row[9],
                            "created_at": row[10],
                            "updated_at": row[11],
                        }
                    )
                return items
        except Exception as exc:
            logger.error(f"Error listing security notifications: {exc}")
            return []

    def update_security_notification(
        self,
        notification_id: int,
        status: str,
        attempts: int,
        last_error: Optional[str] = None,
        next_retry_at: Optional[str] = None,
    ) -> bool:
        """Update queue bookkeeping after a dispatch attempt."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    UPDATE security_notification_queue
                    SET status = ?, attempts = ?, last_error = ?, next_retry_at = ?,
                        last_attempt_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (status, attempts, last_error, next_retry_at, notification_id),
                )
                conn.commit()
                return cursor.rowcount > 0
        except Exception as exc:
            logger.error(f"Error updating security notification {notification_id}: {exc}")
            return False

    def record_security_chain_entry(
        self, chain_name: str, current_hash: str, payload: Dict, previous_hash: Optional[str] = None
    ) -> Optional[int]:
        """Append a tamper-evident hash chain entry for incident records."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO security_audit_chain (
                        chain_name, previous_hash, current_hash, payload
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (chain_name, previous_hash, current_hash, json.dumps(payload)),
                )
                conn.commit()
                return cursor.lastrowid
        except Exception as exc:
            logger.error(f"Error recording security chain entry: {exc}")
            return None

    def list_security_chain_entries(self, limit: int = 50, chain_name: Optional[str] = None) -> List[Dict]:
        """Return recent tamper-evident chain entries."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                query = """
                    SELECT id, chain_name, previous_hash, current_hash, payload, created_at
                    FROM security_audit_chain
                """
                params: List = []
                if chain_name:
                    query += " WHERE chain_name = ?"
                    params.append(chain_name)
                query += " ORDER BY created_at DESC LIMIT ?"
                params.append(limit)
                cursor.execute(query, params)
                rows = cursor.fetchall()
                return [
                    {
                        "id": row[0],
                        "chain_name": row[1],
                        "previous_hash": row[2],
                        "current_hash": row[3],
                        "payload": json.loads(row[4]) if row[4] else {},
                        "created_at": row[5],
                    }
                    for row in rows
                ]
        except Exception as exc:
            logger.error(f"Error listing security chain entries: {exc}")
            return []

    def record_incident_export(
        self, export_type: str, export_hash: str, summary: str = "", file_name: Optional[str] = None
    ) -> bool:
        """Record that a report/export was generated for traceability."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO incident_exports (export_type, file_name, summary, export_hash)
                    VALUES (?, ?, ?, ?)
                    """,
                    (export_type, file_name, summary, export_hash),
                )
                conn.commit()
                return True
        except Exception as exc:
            logger.error(f"Error recording incident export: {exc}")
            return False

    def upsert_security_case(
        self,
        case_key: str,
        title: str,
        severity: str,
        status: str,
        summary: str,
        correlation_id: Optional[str] = None,
        attack_types: Optional[List[str]] = None,
        source_ips: Optional[List[str]] = None,
        attack_ids: Optional[List[int]] = None,
        alert_ids: Optional[List[int]] = None,
        blocked_ips: Optional[List[str]] = None,
        recommended_actions: Optional[List[str]] = None,
        playbook_name: Optional[str] = None,
        integrity_hash: Optional[str] = None,
        first_seen: Optional[str] = None,
        last_seen: Optional[str] = None,
    ) -> Optional[int]:
        """Insert or update a correlated security case."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO security_cases (
                        case_key, title, status, severity, summary, correlation_id,
                        attack_types, source_ips, attack_ids, alert_ids, blocked_ips,
                        recommended_actions, playbook_name, integrity_hash,
                        first_seen, last_seen, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(case_key) DO UPDATE SET
                        title = excluded.title,
                        status = excluded.status,
                        severity = excluded.severity,
                        summary = excluded.summary,
                        correlation_id = excluded.correlation_id,
                        attack_types = excluded.attack_types,
                        source_ips = excluded.source_ips,
                        attack_ids = excluded.attack_ids,
                        alert_ids = excluded.alert_ids,
                        blocked_ips = excluded.blocked_ips,
                        recommended_actions = excluded.recommended_actions,
                        playbook_name = excluded.playbook_name,
                        integrity_hash = excluded.integrity_hash,
                        first_seen = excluded.first_seen,
                        last_seen = excluded.last_seen,
                        updated_at = CURRENT_TIMESTAMP
                    """,
                    (
                        case_key,
                        title,
                        status,
                        severity,
                        summary,
                        correlation_id,
                        json.dumps(attack_types or []),
                        json.dumps(source_ips or []),
                        json.dumps(attack_ids or []),
                        json.dumps(alert_ids or []),
                        json.dumps(blocked_ips or []),
                        json.dumps(recommended_actions or []),
                        playbook_name,
                        integrity_hash,
                        first_seen,
                        last_seen,
                    ),
                )
                conn.commit()
                cursor.execute("SELECT id FROM security_cases WHERE case_key = ?", (case_key,))
                row = cursor.fetchone()
                return row[0] if row else None
        except Exception as exc:
            logger.error(f"Error upserting security case {case_key}: {exc}")
            return None

    def list_security_cases(self, limit: int = 100, active_only: bool = False) -> List[Dict]:
        """Return recent correlated security cases."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                query = """
                    SELECT id, case_key, title, status, severity, summary, correlation_id,
                           attack_types, source_ips, attack_ids, alert_ids, blocked_ips,
                           recommended_actions, playbook_name, integrity_hash,
                           first_seen, last_seen, created_at, updated_at, closed_at
                    FROM security_cases
                """
                params: List = []
                if active_only:
                    query += " WHERE status IN ('open', 'contained')"
                query += " ORDER BY COALESCE(last_seen, created_at) DESC LIMIT ?"
                params.append(limit)
                cursor.execute(query, params)
                rows = cursor.fetchall()
                cases = []
                for row in rows:
                    cases.append(
                        {
                            "id": row[0],
                            "case_key": row[1],
                            "title": row[2],
                            "status": row[3],
                            "severity": row[4],
                            "summary": row[5],
                            "correlation_id": row[6],
                            "attack_types": json.loads(row[7]) if row[7] else [],
                            "source_ips": json.loads(row[8]) if row[8] else [],
                            "attack_ids": json.loads(row[9]) if row[9] else [],
                            "alert_ids": json.loads(row[10]) if row[10] else [],
                            "blocked_ips": json.loads(row[11]) if row[11] else [],
                            "recommended_actions": json.loads(row[12]) if row[12] else [],
                            "playbook_name": row[13],
                            "integrity_hash": row[14],
                            "first_seen": row[15],
                            "last_seen": row[16],
                            "created_at": row[17],
                            "updated_at": row[18],
                            "closed_at": row[19],
                        }
                    )
                return cases
        except Exception as exc:
            logger.error(f"Error listing security cases: {exc}")
            return []

    def close_security_case(self, case_id: int) -> bool:
        """Mark a case as closed and set the closed_at timestamp."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    UPDATE security_cases
                    SET status = 'closed', closed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (case_id,),
                )
                conn.commit()
                return cursor.rowcount > 0
        except Exception as exc:
            logger.error(f"Error closing security case {case_id}: {exc}")
            return False

    def record_security_playbook_run(
        self,
        case_id: Optional[int],
        playbook_name: str,
        status: str,
        details: str,
        auto_applied: bool = False,
        case_key: Optional[str] = None,
    ) -> Optional[int]:
        """Store an auto-response playbook execution record."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO security_playbook_runs (
                        case_id, case_key, playbook_name, status, auto_applied, details, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    """,
                    (case_id, case_key, playbook_name, status, int(auto_applied), details),
                )
                conn.commit()
                return cursor.lastrowid
        except Exception as exc:
            logger.error(f"Error recording playbook run: {exc}")
            return None

    def list_security_playbook_runs(self, limit: int = 100, case_id: Optional[int] = None) -> List[Dict]:
        """Return recent playbook executions."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                query = """
                    SELECT id, case_id, case_key, playbook_name, status, auto_applied, details,
                           created_at, updated_at
                    FROM security_playbook_runs
                """
                params: List = []
                if case_id is not None:
                    query += " WHERE case_id = ?"
                    params.append(case_id)
                query += " ORDER BY created_at DESC LIMIT ?"
                params.append(limit)
                cursor.execute(query, params)
                rows = cursor.fetchall()
                return [
                    {
                        "id": row[0],
                        "case_id": row[1],
                        "case_key": row[2],
                        "playbook_name": row[3],
                        "status": row[4],
                        "auto_applied": bool(row[5]),
                        "details": row[6],
                        "created_at": row[7],
                        "updated_at": row[8],
                    }
                    for row in rows
                ]
        except sqlite3.DatabaseError as exc:
            logger.error(f"Error listing playbook runs: {exc}")
            return []

    def resolve_security_alert(self, alert_id: int) -> bool:
        """Mark a security alert as resolved."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    UPDATE security_alerts
                    SET is_resolved = 1, resolved_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (alert_id,),
                )
                conn.commit()
                return cursor.rowcount > 0
        except Exception as exc:
            logger.error(f"Error resolving alert {alert_id}: {exc}")
            return False

    def get_system_setting(self, key: str, default=None):
        """Return a stored system setting value."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT setting_value FROM system_settings WHERE setting_key = ?", (key,))
                row = cursor.fetchone()
                if not row:
                    return default

                raw_value = row[0]
                try:
                    return json.loads(raw_value)
                except json.JSONDecodeError:
                    return raw_value
        except sqlite3.DatabaseError as exc:
            logger.error(f"Error getting system setting {key}: {exc}")
            return default

    def set_system_setting(self, key: str, value) -> bool:
        """Store a system setting value."""
        try:
            serialized_value = json.dumps(value)
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO system_settings (setting_key, setting_value, updated_at)
                    VALUES (?, ?, datetime('now'))
                    ON CONFLICT(setting_key) DO UPDATE SET
                        setting_value = excluded.setting_value,
                        updated_at = datetime('now')
                    """,
                    (key, serialized_value),
                )
                conn.commit()
                return True
        except sqlite3.DatabaseError as exc:
            logger.error(f"Error setting system setting {key}: {exc}")
            return False

    def get_system_settings(self) -> Dict[str, object]:
        """Return all stored system settings as a dictionary."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT setting_key, setting_value FROM system_settings ORDER BY setting_key")
                rows = cursor.fetchall()
                settings = {}
                for key, raw_value in rows:
                    try:
                        settings[key] = json.loads(raw_value)
                    except json.JSONDecodeError:
                        settings[key] = raw_value
                return settings
        except sqlite3.DatabaseError as exc:
            logger.error(f"Error listing system settings: {exc}")
            return {}

    def has_users(self) -> bool:
        """Check whether at least one user exists."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT 1 FROM users LIMIT 1")
                return cursor.fetchone() is not None
        except sqlite3.DatabaseError as exc:
            logger.error(f"Error checking users: {exc}")
            return False

    @staticmethod
    def _seed_demo_users(cursor):
        """Seed demo users when explicitly enabled via environment variable."""
        demo_users = [
            ("admin", "admin@agentic-iam.local", "admin", "Administrator"),
            ("operator", "operator@agentic-iam.local", "operator", "System Operator"),
            ("user", "user@agentic-iam.local", "user", "Default User"),
        ]
        for username, email, role, full_name in demo_users:
            password_hash = bcrypt.hashpw(os.urandom(24).hex().encode("utf-8"), bcrypt.gensalt())
            cursor.execute(
                """
                INSERT INTO users (username, password_hash, email, role, full_name, status)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (username, sqlite3.Binary(password_hash), email, role, full_name, "active"),
            )

    # Agent operations
    def add_agent(self, agent_id: str, name: str, agent_type: str = "standard", metadata: Dict = None) -> bool:
        """Add new agent to database"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO agents (id, name, type, metadata)
                    VALUES (?, ?, ?, ?)
                """,
                    (agent_id, name, agent_type, json.dumps(metadata or {})),
                )
                conn.commit()

                # Log event
                self.log_event("agent_created", agent_id, "create", f"Agent {name} created")
                logger.info(f"Agent {agent_id} added to database")
                return True
        except sqlite3.IntegrityError:
            logger.error(f"Agent {agent_id} already exists")
            return False
        except Exception as e:
            logger.error(f"Error adding agent: {e}")
            return False

    def get_agent(self, agent_id: str) -> Optional[Dict]:
        """Get agent details"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM agents WHERE id = ?", (agent_id,))
                row = cursor.fetchone()
                if row:
                    return {
                        "id": row[0],
                        "name": row[1],
                        "type": row[2],
                        "status": row[3],
                        "created_at": row[4],
                        "updated_at": row[5],
                        "metadata": json.loads(row[6]) if row[6] else {},
                    }
        except Exception as e:
            logger.error(f"Error getting agent: {e}")
        return None

    def list_agents(self) -> List[Dict]:
        """List all agents"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM agents ORDER BY created_at DESC")
                rows = cursor.fetchall()
                agents = []
                for row in rows:
                    agents.append(
                        {
                            "id": row[0],
                            "name": row[1],
                            "type": row[2],
                            "status": row[3],
                            "created_at": row[4],
                            "updated_at": row[5],
                            "metadata": json.loads(row[6]) if row[6] else {},
                        }
                    )
                return agents
        except Exception as e:
            logger.error(f"Error listing agents: {e}")
        return []

    def update_agent(self, agent_id: str, **kwargs) -> bool:
        """Update agent information"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                updates = []
                values = []

                for key, value in kwargs.items():
                    if key in ["name", "type", "status"]:
                        updates.append(f"{key} = ?")
                        values.append(value)

                if not updates:
                    return False

                updates.append("updated_at = ?")
                values.append(datetime.now().isoformat())
                values.append(agent_id)

                query = f"UPDATE agents SET {', '.join(updates)} WHERE id = ?"
                cursor.execute(query, values)
                conn.commit()

                self.log_event("agent_updated", agent_id, "update", f"Agent {agent_id} updated")
                return True
        except sqlite3.DatabaseError as e:
            logger.error(f"Error updating agent: {e}")
            return False

    # Event logging operations
    def log_event(
        self,
        event_type: str,
        agent_id: Optional[str] = None,
        action: Optional[str] = None,
        details: Optional[str] = None,
        status: str = "success",
    ) -> bool:
        """Log an event to database"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO events (event_type, agent_id, action, details, status)
                    VALUES (?, ?, ?, ?, ?)
                """,
                    (event_type, agent_id, action, details, status),
                )
                conn.commit()
                logger.info(f"Event logged: {event_type} for agent {agent_id}")
                # Try to append to append-only audit ledger for tamper-evidence
                try:
                    if append_audit_entry:
                        append_audit_entry(
                            {
                                "event_type": event_type,
                                "agent_id": agent_id,
                                "action": action,
                                "details": details,
                                "status": status,
                            }
                        )
                except Exception as e:
                    logger.debug("append_audit_entry failed: %s", e)
                return True
        except sqlite3.DatabaseError as e:
            logger.error(f"Error logging event: {e}")
            return False

    def create_task(self, agent_id: str, task_type: str, details: str, status: str = "pending") -> bool:
        """Create a task for an agent."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO tasks (agent_id, task_type, details, status)
                    VALUES (?, ?, ?, ?)
                """,
                    (agent_id, task_type, details, status),
                )
                conn.commit()

                self.log_event(
                    "task_created",
                    agent_id,
                    task_type,
                    details,
                )
                logger.info(f"Task created for agent {agent_id}: {task_type}")
                return True
        except Exception as e:
            logger.error(f"Error creating task: {e}")
            return False

    def list_tasks(self, limit: int = 100) -> List[Dict]:
        """List recent tasks."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT id, agent_id, task_type, details, status, created_at, updated_at
                    FROM tasks
                    ORDER BY created_at DESC
                    LIMIT ?
                    """,
                    (limit,),
                )
                rows = cursor.fetchall()
                tasks = []
                for row in rows:
                    tasks.append(
                        {
                            "id": row[0],
                            "agent_id": row[1],
                            "task_type": row[2],
                            "details": row[3],
                            "status": row[4],
                            "created_at": row[5],
                            "updated_at": row[6],
                        }
                    )
                return tasks
        except Exception as e:
            logger.error(f"Error listing tasks: {e}")
            return []

    def get_events(self, agent_id: Optional[str] = None, limit: int = 100) -> List[Dict]:
        """Get events from database"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                if agent_id:
                    cursor.execute(
                        """
                        SELECT * FROM events
                        WHERE agent_id = ?
                        ORDER BY created_at DESC
                        LIMIT ?
                    """,
                        (agent_id, limit),
                    )
                else:
                    cursor.execute(
                        """
                        SELECT * FROM events
                        ORDER BY created_at DESC
                        LIMIT ?
                    """,
                        (limit,),
                    )

                rows = cursor.fetchall()
                events = []
                for row in rows:
                    events.append(
                        {
                            "id": row[0],
                            "event_type": row[1],
                            "agent_id": row[2],
                            "action": row[3],
                            "details": row[4],
                            "created_at": row[5],
                            "status": row[6],
                        }
                    )
                return events
        except Exception as e:
            logger.error(f"Error getting events: {e}")
        return []

    # Session operations
    def create_session(self, session_id: str, agent_id: str, metadata: Dict = None) -> bool:
        """Create a session for an agent"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO sessions (id, agent_id, metadata)
                    VALUES (?, ?, ?)
                """,
                    (session_id, agent_id, json.dumps(metadata or {})),
                )
                conn.commit()
                self.log_event("session_created", agent_id, "session_start", f"Session {session_id} started")
                return True
        except Exception as e:
            logger.error(f"Error creating session: {e}")
            return False

    def end_session(self, session_id: str) -> bool:
        """End a session"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    UPDATE sessions
                    SET status = 'ended', ended_at = ?
                    WHERE id = ?
                """,
                    (datetime.now().isoformat(), session_id),
                )
                conn.commit()

                # Get agent_id for logging
                cursor.execute("SELECT agent_id FROM sessions WHERE id = ?", (session_id,))
                result = cursor.fetchone()
                if result:
                    self.log_event("session_ended", result[0], "session_end", f"Session {session_id} ended")

                return True
        except Exception as e:
            logger.error(f"Error ending session: {e}")
            return False

    def get_agent_sessions(self, agent_id: str) -> List[Dict]:
        """Get all sessions for an agent"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT * FROM sessions
                    WHERE agent_id = ?
                    ORDER BY started_at DESC
                """,
                    (agent_id,),
                )

                rows = cursor.fetchall()
                sessions = []
                for row in rows:
                    sessions.append(
                        {
                            "id": row[0],
                            "agent_id": row[1],
                            "started_at": row[2],
                            "ended_at": row[3],
                            "status": row[4],
                            "metadata": json.loads(row[5]) if row[5] else {},
                        }
                    )
                return sessions
        except Exception as e:
            logger.error(f"Error getting sessions: {e}")
        return []

    def list_users(self) -> list:
        """List all users"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id, username, email, role, full_name, status, created_at, last_login FROM users")
                rows = cursor.fetchall()
                users = []
                for row in rows:
                    users.append(
                        {
                            "id": row[0],
                            "username": row[1],
                            "email": row[2],
                            "role": row[3],
                            "full_name": row[4],
                            "status": row[5],
                            "created_at": row[6],
                            "last_login": row[7],
                        }
                    )
                return users
        except Exception as e:
            logger.error(f"Error listing users: {e}")
            return []

    def authenticate_user(self, username: str, password: str) -> dict:
        """Authenticate a user"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT id, username, email, role, password_hash, full_name, status, created_at, last_login
                    FROM users WHERE username = ?
                """,
                    (username,),
                )
                row = cursor.fetchone()
                if row:
                    stored_hash = row[4]
                    # Ensure stored_hash is bytes
                    if isinstance(stored_hash, memoryview):
                        stored_hash = stored_hash.tobytes()
                    if isinstance(stored_hash, str):
                        stored_hash = stored_hash.encode("utf-8")
                    if bcrypt.checkpw(password.encode("utf-8"), stored_hash):
                        # Update last login
                        cursor.execute(
                            """
                            UPDATE users SET last_login = datetime('now') WHERE id = ?
                        """,
                            (row[0],),
                        )
                        conn.commit()
                        return {
                            "id": row[0],
                            "username": row[1],
                            "email": row[2],
                            "role": row[3],
                            "full_name": row[5],
                            "status": row[6],
                            "created_at": row[7],
                            "last_login": row[8],
                        }
        except Exception as e:
            logger.error(f"Error authenticating user: {e}")
        return None

    def create_user(self, username: str, email: str, password: str, role: str = "user") -> bool:
        """Create a new user"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
                cursor.execute(
                    """
                    INSERT INTO users (username, password_hash, email, role, full_name, status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
                """,
                    (username, sqlite3.Binary(password_hash), email, role, "", "active"),
                )
                conn.commit()
                return True
        except sqlite3.IntegrityError:
            logger.error(f"User {username} already exists")
        except Exception as e:
            logger.error(f"Error creating user: {e}")
        return False

    def change_password(self, user_id: int, new_password: str) -> bool:
        """Change user password"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                password_hash = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt())
                cursor.execute(
                    """
                    UPDATE users SET password_hash = ? WHERE id = ?
                """,
                    (sqlite3.Binary(password_hash), user_id),
                )
                conn.commit()
                return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Error changing password: {e}")
        return False

    def get_user_by_id(self, user_id: int) -> dict:
        """Get user by ID"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT id, username, email, role, full_name, status, created_at, last_login
                    FROM users WHERE id = ?
                """,
                    (user_id,),
                )
                row = cursor.fetchone()
                if row:
                    return {
                        "id": row[0],
                        "username": row[1],
                        "email": row[2],
                        "role": row[3],
                        "full_name": row[4],
                        "status": row[5],
                        "created_at": row[6],
                        "last_login": row[7],
                    }
        except Exception as e:
            logger.error(f"Error getting user by ID: {e}")
        return None

    def update_user_role(self, user_id: int, new_role: str) -> bool:
        """Update user role"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    UPDATE users SET role = ? WHERE id = ?
                """,
                    (new_role, user_id),
                )
                conn.commit()
                return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Error updating user role: {e}")
        return False

    def update_user_status(self, user_id: int, new_status: str) -> bool:
        """Update user status (active/suspended)"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    UPDATE users SET status = ? WHERE id = ?
                """,
                    (new_status, user_id),
                )
                conn.commit()
                return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Error updating user status: {e}")
        return False

    def delete_user(self, user_id: int) -> bool:
        """Delete a user"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
                conn.commit()
                return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Error deleting user: {e}")
        return False

    def delete_agent(self, agent_id: str) -> bool:
        """Delete an agent and its dependent records while preserving audit history."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT 1 FROM agents WHERE id = ?", (agent_id,))
                if not cursor.fetchone():
                    return False

                cursor.execute("UPDATE events SET agent_id = NULL WHERE agent_id = ?", (agent_id,))
                cursor.execute("DELETE FROM sessions WHERE agent_id = ?", (agent_id,))
                cursor.execute("DELETE FROM agent_permissions WHERE agent_id = ?", (agent_id,))
                cursor.execute("DELETE FROM agent_capabilities WHERE agent_id = ?", (agent_id,))
                cursor.execute("DELETE FROM agents WHERE id = ?", (agent_id,))
                conn.commit()
                return cursor.rowcount > 0
        except sqlite3.DatabaseError as e:
            logger.error(f"Error deleting agent: {e}")
        return False

    def update_agent_status(self, agent_id: str, new_status: str) -> bool:
        """Update agent status (active/inactive/suspended)."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE agents SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", (new_status, agent_id)
                )
                conn.commit()
                return cursor.rowcount > 0
        except sqlite3.DatabaseError as e:
            logger.error(f"Error updating agent status: {e}")
        return False


# Global database instance
_db_instance = None


def get_database(db_path: Optional[str] = None) -> Database:
    """Get or create global database instance"""
    global _db_instance
    if _db_instance is None:
        # Allow DB path override from environment or secret manager
        resolved_path = os.getenv("DB_PATH")
        if not resolved_path and secret_manager:
            try:
                resolved_path = secret_manager.get_secret("DB_PATH")
            except Exception as e:
                logger.debug("secret_manager.get_secret(DB_PATH) failed: %s", e)
                resolved_path = None

        if not resolved_path:
            resolved_path = db_path

        _db_instance = Database(resolved_path)
    return _db_instance
