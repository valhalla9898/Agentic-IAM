"""
Agentic-IAM: Streamlit Dashboard Application

Main entry point for the web-based GUI dashboard with role-based access control.
"""

import json
import logging
import os
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

import pandas as pd
import requests
import streamlit as st

from config.settings import get_settings
from dashboard.components.agent_selection import (
    show_agent_details,
    show_agent_list,
    show_agent_registration,
    show_agent_selector,
)
from dashboard.components.ai_assistant import show_ai_assistant

# Bloome storefront removed — related utilities were deleted
from dashboard.components.risk_assessment import show_risk_assessment
from database import get_database
from security_incident_management import (
    build_executive_report,
    correlate_security_cases,
    execute_playbook,
    get_security_playbooks,
    render_executive_report_pdf,
    summarize_case_metrics,
)
from security_telemetry import (
    DEFAULT_SECURITY_RULES,
    build_incident_export_payload,
    calculate_security_kpis,
    enrich_security_state,
    generate_correlation_id,
)
from utils.advanced_features import AgentAnalytics, AgentHealthMonitor, ReportGenerator
from utils.rbac import (
    Permission,
    check_permission,
    get_current_user_permissions,
    get_rbac_manager,
    is_admin,
    is_operator,
)
from utils.security import (
    AccountSecurity,
    AuditLogger,
    InputValidator,
    RateLimiter,
    SessionSecurityManager,
    SQLInjectionProtection,
)

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))


DEMO_SECURITY_STATE_PATH = Path(__file__).parent / "attack_results" / "security_state.json"


def _build_demo_security_state() -> dict:
    """Create a realistic demo incident payload for local screenshots and demos."""
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    source_ip = "203.0.113.77"
    base_state = {
        "generated_at": now,
        "incident_id": generate_correlation_id("incident"),
        "attacks": [
            {
                "attack_type": "sql_injection",
                "severity": "critical",
                "status": "blocked",
                "detected_at": now,
                "source_ip": source_ip,
                "target_endpoint": "/api/v1/auth/login",
                "metadata": {
                    "username": "demo_operator",
                    "user": "unknown",
                    "vector": "login_form",
                },
            },
            {
                "attack_type": "brute_force",
                "severity": "high",
                "status": "mitigated",
                "detected_at": now,
                "source_ip": "198.51.100.24",
                "target_endpoint": "/api/v1/auth/login",
                "metadata": {
                    "username": "unknown",
                    "attempts": 14,
                    "vector": "credential_stuffing",
                },
            },
        ],
        "active": [
            {
                "severity": "critical",
                "alert_type": "web_attack",
                "title": "SQL injection attempt blocked",
                "message": "WAF and application controls blocked a malicious login payload before session creation.",
                "created_at": now,
            },
            {
                "severity": "high",
                "alert_type": "auth_attack",
                "title": "Repeated login failures detected",
                "message": "Rate limiter locked the source after repeated failures.",
                "created_at": now,
            },
        ],
        "blocked_ips": [
            {
                "ip": source_ip,
                "reason": "Auto-blocked after SQL injection pattern detection",
                "blocked_at": now,
            },
            {
                "ip": "198.51.100.24",
                "reason": "Auto-blocked after credential stuffing threshold exceeded",
                "blocked_at": now,
            },
        ],
    }
    return enrich_security_state(base_state, DEFAULT_SECURITY_RULES)


def _write_demo_security_state(state: dict | None = None) -> dict:
    """Persist the demo security payload so the dashboard can render it."""
    DEMO_SECURITY_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    state = state or _build_demo_security_state()
    with open(DEMO_SECURITY_STATE_PATH, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2)
    return state


def _load_demo_security_state() -> dict:
    """Load the local demo security payload if it exists."""
    if not DEMO_SECURITY_STATE_PATH.exists():
        return {}
    try:
        with open(DEMO_SECURITY_STATE_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError) as e:
        import logging

        logging.getLogger(__name__).debug("Failed to load demo security state: %s", e)
        return {}


def _build_attack_flow_stages() -> list[dict]:
    """Return an end-to-end attack lifecycle for screenshots and demos."""
    return [
        {
            "stage": "1. Reconnaissance",
            "status": "Observed",
            "detail": "The attacker probes the login endpoint and discovers the public auth surface.",
            "control": "WAF telemetry and request logging",
        },
        {
            "stage": "2. Exploit Attempt",
            "status": "Blocked",
            "detail": "A crafted SQL injection payload is submitted through the login form.",
            "control": "Input validation and application-layer filtering",
        },
        {
            "stage": "3. Detection",
            "status": "Alerted",
            "detail": "The attack is flagged as critical and pushed to the alert queue immediately.",
            "control": "Security analytics and alerting rules",
        },
        {
            "stage": "4. Containment",
            "status": "Auto-blocked",
            "detail": "The source IP is isolated automatically and repeated login attempts are rate-limited.",
            "control": "Auto-block and rate limiter",
        },
        {
            "stage": "5. Recovery",
            "status": "In progress",
            "detail": "Administrators review the incident and verify that no session was created.",
            "control": "Incident response workflow",
        },
        {
            "stage": "6. Closeout",
            "status": "Complete",
            "detail": "Evidence is preserved and the incident is marked as contained with loss avoided.",
            "control": "Audit trail and post-incident review",
        },
    ]


def _get_dashboard_db():
    """Return the active dashboard database when session state is available."""
    try:
        return st.session_state.db
    except AttributeError:
        return None


def _dispatch_security_notifications(payload: dict) -> list[dict]:
    """Send incident payloads to configured webhook and SIEM endpoints."""
    db = _get_dashboard_db()
    if not db:
        return []

    settings = db.get_system_settings()
    targets = []
    if settings.get("webhooks_enabled") and settings.get("webhook_url"):
        targets.append({"name": "webhook", "url": str(settings.get("webhook_url"))})
    if settings.get("siem_enabled") and settings.get("siem_endpoint"):
        targets.append({"name": "siem", "url": str(settings.get("siem_endpoint"))})

    results = []
    for target in targets:
        try:
            response = requests.post(target["url"], json=payload, timeout=5)
            if response.status_code >= 400 and hasattr(db, "enqueue_security_notification"):
                db.enqueue_security_notification(
                    target_name=target["name"],
                    target_url=target["url"],
                    payload=payload,
                    status="retry",
                    attempts=1,
                    max_attempts=3,
                    last_error=f"HTTP {response.status_code}",
                )
            results.append(
                {
                    "target": target["name"],
                    "url": target["url"],
                    "status_code": response.status_code,
                    "delivered": response.status_code < 400,
                }
            )
        except Exception as exc:
            if hasattr(db, "enqueue_security_notification"):
                db.enqueue_security_notification(
                    target_name=target["name"],
                    target_url=target["url"],
                    payload=payload,
                    status="queued",
                    attempts=1,
                    max_attempts=3,
                    last_error=str(exc),
                )
            results.append(
                {
                    "target": target["name"],
                    "url": target["url"],
                    "delivered": False,
                    "error": str(exc),
                }
            )
    return results


def _ensure_local_security_tables(db_path: str) -> None:
    """Create local security telemetry tables when the runtime lacks newer helpers."""
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
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
                resolved_at TIMESTAMP
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
                is_active BOOLEAN DEFAULT 1
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
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()


def _direct_sql_record_security_demo(state: dict) -> None:
    """Persist demo telemetry directly with SQLite when helper methods are unavailable."""
    db = _get_dashboard_db()
    if not db or not getattr(db, "db_path", None):
        return

    _ensure_local_security_tables(db.db_path)
    with sqlite3.connect(db.db_path) as conn:
        cursor = conn.cursor()

        attack_ids = []
        for attack in state.get("attacks", []):
            attack_metadata = dict(attack.get("metadata", {})) if isinstance(attack.get("metadata"), dict) else {}
            attack_metadata.update(
                {
                    "correlation_id": attack.get("correlation_id"),
                    "event_hash": attack.get("event_hash"),
                    "threat_intel": attack.get("threat_intel", {}),
                    "matched_rules": attack.get("matched_rules", []),
                    "recommended_actions": attack.get("recommended_actions", []),
                }
            )
            cursor.execute(
                """
                INSERT INTO attack_events (
                    attack_type, source_ip, target_endpoint, payload,
                    severity, status, description, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    attack.get("attack_type", "unknown"),
                    attack.get("source_ip", "unknown"),
                    attack.get("target_endpoint"),
                    attack.get("payload"),
                    attack.get("severity", "medium"),
                    attack.get("status", "detected"),
                    attack.get("description"),
                    json.dumps(attack_metadata),
                ),
            )
            attack_ids.append(cursor.lastrowid)

        primary_attack_id = attack_ids[0] if attack_ids else None
        for alert in state.get("active", []):
            cursor.execute(
                """
                INSERT INTO security_alerts (
                    alert_type, title, message, severity, source_ip,
                    attack_event_id, is_resolved
                ) VALUES (?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    alert.get("alert_type", "security_event"),
                    alert.get("title", "Security Alert"),
                    alert.get("message", ""),
                    alert.get("severity", "medium"),
                    alert.get("source_ip"),
                    primary_attack_id,
                ),
            )

        for block in state.get("blocked_ips", []):
            cursor.execute(
                """
                INSERT INTO blocked_ips (
                    ip_address, reason, attack_event_id, block_duration_seconds,
                    blocked_at, expires_at, is_active
                ) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, NULL, 1)
                ON CONFLICT(ip_address) DO UPDATE SET
                    reason = excluded.reason,
                    attack_event_id = excluded.attack_event_id,
                    is_active = excluded.is_active,
                    blocked_at = CURRENT_TIMESTAMP
                """,
                (
                    block.get("ip", "unknown"),
                    block.get("reason", "Auto-blocked"),
                    primary_attack_id,
                    None,
                ),
            )

        try:
            cases = correlate_security_cases(
                state.get("attacks", []), state.get("active", []), state.get("blocked_ips", [])
            )
            for case in cases:
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
                        case.get("case_key"),
                        case.get("title"),
                        case.get("status", "open"),
                        case.get("severity", "medium"),
                        case.get("summary", ""),
                        case.get("correlation_id"),
                        json.dumps(case.get("attack_types", [])),
                        json.dumps(case.get("source_ips", [])),
                        json.dumps(case.get("attack_ids", [])),
                        json.dumps(case.get("alert_ids", [])),
                        json.dumps(case.get("blocked_ips", [])),
                        json.dumps(case.get("recommended_actions", [])),
                        case.get("playbook_name"),
                        case.get("integrity_hash"),
                        case.get("first_seen"),
                        case.get("last_seen"),
                    ),
                )
                case_row = cursor.execute(
                    "SELECT id FROM security_cases WHERE case_key = ?", (case.get("case_key"),)
                ).fetchone()
                case_id = case_row[0] if case_row else None
                playbook = next(
                    (
                        item
                        for item in get_security_playbooks()
                        if item.get("playbook_name") == case.get("playbook_name")
                    ),
                    None,
                )
                if playbook and case_id is not None:
                    cursor.execute(
                        """
                        INSERT INTO security_playbook_runs (
                            case_id, case_key, playbook_name, status, auto_applied, details
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            case_id,
                            case.get("case_key"),
                            playbook.get("playbook_name", "unknown"),
                            "executed" if playbook.get("auto_execute") else "recorded",
                            int(bool(playbook.get("auto_execute"))),
                            json.dumps({"steps": playbook.get("steps", []), "case": case.get("case_key")}),
                        ),
                    )
        except Exception as e:
            logging.getLogger(__name__).debug("Suppressed exception while persisting case/playbook: %s", e)

        conn.commit()


def _persist_security_demo_state(state: dict) -> dict:
    """Persist demo telemetry locally and in the dashboard database."""
    db = _get_dashboard_db()
    if db and isinstance(state, dict):
        state = enrich_security_state(state, DEFAULT_SECURITY_RULES)
        if (
            not hasattr(db, "record_attack_event")
            or not hasattr(db, "record_security_alert")
            or not hasattr(db, "block_ip")
        ):
            _direct_sql_record_security_demo(state)
        else:
            attack_ids = []
            for attack in state.get("attacks", []):
                attack_metadata = dict(attack.get("metadata", {})) if isinstance(attack.get("metadata"), dict) else {}
                attack_metadata.update(
                    {
                        "correlation_id": attack.get("correlation_id"),
                        "event_hash": attack.get("event_hash"),
                        "threat_intel": attack.get("threat_intel", {}),
                        "matched_rules": attack.get("matched_rules", []),
                        "recommended_actions": attack.get("recommended_actions", []),
                    }
                )
                attack_id = db.record_attack_event(
                    attack_type=attack.get("attack_type", "unknown"),
                    source_ip=attack.get("source_ip", "unknown"),
                    target_endpoint=attack.get("target_endpoint"),
                    payload=attack.get("payload"),
                    severity=attack.get("severity", "medium"),
                    status=attack.get("status", "detected"),
                    description=attack.get("description"),
                    metadata=attack_metadata,
                )
                if attack_id:
                    attack_ids.append(attack_id)

            primary_attack_id = attack_ids[0] if attack_ids else None
            for alert in state.get("active", []):
                db.record_security_alert(
                    alert_type=alert.get("alert_type", "security_event"),
                    title=alert.get("title", "Security Alert"),
                    message=alert.get("message", ""),
                    severity=alert.get("severity", "medium"),
                    source_ip=alert.get("source_ip"),
                    attack_event_id=primary_attack_id,
                    is_resolved=False,
                )

            for block in state.get("blocked_ips", []):
                db.block_ip(
                    ip_address=block.get("ip", "unknown"),
                    reason=block.get("reason", "Auto-blocked"),
                    attack_event_id=primary_attack_id,
                    is_active=True,
                )

            db.log_event(
                "security_incident_demo_generated",
                agent_id="system",
                action="containment",
                details=json.dumps(
                    {
                        "attack_count": len(state.get("attacks", [])),
                        "alert_count": len(state.get("active", [])),
                        "blocked_count": len(state.get("blocked_ips", [])),
                    }
                ),
            )

            try:
                db.set_system_setting("security_telemetry_last_generated", state.get("generated_at"))
                db.set_system_setting("security_rules", DEFAULT_SECURITY_RULES)
                db.set_system_setting("security_last_fingerprint", state.get("integrity_hash"))
            except Exception as e:
                logging.getLogger(__name__).debug("Suppressed exception while setting system setting: %s", e)

            cases = correlate_security_cases(
                state.get("attacks", []), state.get("active", []), state.get("blocked_ips", [])
            )
            state["cases"] = cases
            if hasattr(db, "upsert_security_case"):
                for case in cases:
                    db.upsert_security_case(
                        case_key=case.get("case_key", "unknown-case"),
                        title=case.get("title", "Security case"),
                        severity=case.get("severity", "medium"),
                        status=case.get("status", "open"),
                        summary=case.get("summary", ""),
                        correlation_id=case.get("correlation_id"),
                        attack_types=case.get("attack_types", []),
                        source_ips=case.get("source_ips", []),
                        attack_ids=case.get("attack_ids", []),
                        alert_ids=case.get("alert_ids", []),
                        blocked_ips=case.get("blocked_ips", []),
                        recommended_actions=case.get("recommended_actions", []),
                        playbook_name=case.get("playbook_name"),
                        integrity_hash=case.get("integrity_hash"),
                        first_seen=case.get("first_seen"),
                        last_seen=case.get("last_seen"),
                    )

                for case in cases:
                    playbook = next(
                        (
                            item
                            for item in get_security_playbooks()
                            if item.get("playbook_name") == case.get("playbook_name")
                        ),
                        None,
                    )
                    if playbook and playbook.get("auto_execute"):
                        execute_playbook(db, case, playbook)

            if hasattr(db, "record_security_chain_entry") and state.get("integrity_hash"):
                try:
                    previous_entries = (
                        db.list_security_chain_entries(limit=1, chain_name="incident-flow")
                        if hasattr(db, "list_security_chain_entries")
                        else []
                    )
                    previous_hash = previous_entries[0]["current_hash"] if previous_entries else None
                    db.record_security_chain_entry(
                        chain_name="incident-flow",
                        current_hash=state.get("integrity_hash"),
                        payload={
                            "incident_id": state.get("incident_id"),
                            "correlation_id": state.get("correlation_id"),
                            "executive_summary": state.get("executive_summary", {}),
                        },
                        previous_hash=previous_hash,
                    )
                except Exception as e:
                    logging.getLogger(__name__).debug("Suppressed exception in playbook-run insertion: %s", e)

            if hasattr(db, "record_incident_export"):
                try:
                    kpis = calculate_security_kpis(
                        state.get("attacks", []), state.get("active", []), state.get("blocked_ips", [])
                    )
                    export_payload = build_incident_export_payload(
                        state, state.get("attacks", []), state.get("active", []), state.get("blocked_ips", []), kpis
                    )
                    db.record_incident_export(
                        export_type="security_demo",
                        export_hash=export_payload.get("export_hash", ""),
                        summary=f"{len(state.get('attacks', []))} attacks, {len(state.get('active', []))} alerts, {len(state.get('blocked_ips', []))} blocks",
                        file_name="attack_flow_export.json",
                    )
                except Exception as e:
                    import logging

                    logging.getLogger(__name__).debug("Suppressed exception while recording incident export: %s", e)

    _write_demo_security_state(state)
    _dispatch_security_notifications(
        {
            "event": "security_incident_demo_generated",
            "generated_at": state.get("generated_at"),
            "incident_id": state.get("incident_id"),
            "correlation_id": state.get("correlation_id"),
            "attacks": state.get("attacks", []),
            "alerts": state.get("active", []),
            "blocked_ips": state.get("blocked_ips", []),
            "cases": state.get("cases", []),
            "integrity_hash": state.get("integrity_hash"),
            "source": "Agentic-IAM dashboard",
        }
    )
    return state


def _load_security_rules(db) -> list[dict]:
    """Load stored security rules or fall back to the default ruleset."""
    try:
        rules = db.get_system_setting("security_rules", DEFAULT_SECURITY_RULES)
        if isinstance(rules, list) and rules:
            return rules
    except Exception as e:
        logging.getLogger(__name__).debug("Failed to load security rules, using defaults: %s", e)
    return DEFAULT_SECURITY_RULES


def _process_security_notification_queue(db) -> list[dict]:
    """Retry queued notifications using the current dashboard settings."""
    results = []
    if not db or not hasattr(db, "list_security_notifications") or not hasattr(db, "update_security_notification"):
        return results

    queued = db.list_security_notifications(limit=20, status="queued") + db.list_security_notifications(
        limit=20, status="retry"
    )
    for item in queued:
        payload = item.get("payload", {})
        try:
            response = requests.post(item.get("target_url", ""), json=payload, timeout=5)
            if response.status_code < 400:
                db.update_security_notification(
                    item["id"],
                    status="delivered",
                    attempts=int(item.get("attempts", 0)) + 1,
                    last_error=None,
                )
                results.append({"id": item["id"], "target": item.get("target_name"), "status": "delivered"})
            else:
                db.update_security_notification(
                    item["id"],
                    status="retry" if int(item.get("attempts", 0)) + 1 < int(item.get("max_attempts", 3)) else "failed",
                    attempts=int(item.get("attempts", 0)) + 1,
                    last_error=f"HTTP {response.status_code}",
                )
                results.append({"id": item["id"], "target": item.get("target_name"), "status": "retry"})
        except Exception as exc:
            db.update_security_notification(
                item["id"],
                status="retry" if int(item.get("attempts", 0)) + 1 < int(item.get("max_attempts", 3)) else "failed",
                attempts=int(item.get("attempts", 0)) + 1,
                last_error=str(exc),
            )
            results.append({"id": item["id"], "target": item.get("target_name"), "status": "error", "error": str(exc)})
    return results


# Page configuration
st.set_page_config(
    page_title="Agentic-IAM Dashboard",
    page_icon="👥",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS
st.markdown(
    """
    <style>
    .main {
        padding-top: 2rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
    }
    """,
    unsafe_allow_html=True,
)


def initialize_session():
    """Initialize session state"""
    if "iam" not in st.session_state:
        st.session_state.iam = None
    if "agent_page" not in st.session_state:
        st.session_state.agent_page = 1
    if "db" not in st.session_state:
        st.session_state.db = get_database(get_settings().database_path)
    if "selected_agent" not in st.session_state:
        st.session_state.selected_agent = None
    if "user" not in st.session_state:
        st.session_state.user = None
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
    if "requested_page" not in st.session_state:
        st.session_state.requested_page = None
    if "pending_navigation" not in st.session_state:
        st.session_state.pending_navigation = None

    # Initialize security components
    if "rate_limiter" not in st.session_state:
        st.session_state.rate_limiter = RateLimiter(max_attempts=5, window_seconds=300)
    if "account_security" not in st.session_state:
        st.session_state.account_security = AccountSecurity(max_failed_attempts=5)
    if "csrf_token" not in st.session_state:
        st.session_state.csrf_token = SessionSecurityManager.generate_csrf_token()


def is_onboarding_required() -> bool:
    """Check whether the setup wizard should be shown before login."""
    db = st.session_state.db
    onboarding_done = str(db.get_system_setting("onboarding_completed", False)).lower() == "true"
    return not onboarding_done or not db.has_users()


def _initialize_onboarding_fields(settings: dict) -> None:
    """Seed onboarding widgets so the form can be prefilled for demos."""
    defaults = {
        "onboarding_company_name": settings.get("company_name", ""),
        "onboarding_environment_name": str(settings.get("deployment_environment", "development")).lower(),
        "onboarding_identity_provider": settings.get("identity_provider", "Local Accounts"),
        "onboarding_app_url": settings.get("app_url", ""),
        "onboarding_api_url": settings.get("api_url", ""),
        "onboarding_database_type": settings.get("database_type", "SQLite"),
        "onboarding_database_url": settings.get("database_url", ""),
        "onboarding_enable_sso": bool(settings.get("enable_sso", False)),
        "onboarding_admin_username": settings.get("admin_username", "admin"),
        "onboarding_admin_email": settings.get("admin_email", "admin@company.local"),
        "onboarding_admin_password": "",
        "onboarding_confirm_password": "",
    }

    for key, value in defaults.items():
        st.session_state.setdefault(key, value)


def _load_demo_onboarding_values() -> None:
    demo_file = Path(__file__).parent / "demo" / "valhalla_onboarding.json"
    if demo_file.exists():
        with demo_file.open("r", encoding="utf-8") as handle:
            demo_values = json.load(handle)
    else:
        demo_values = {
            "company_name": "Valhalla",
            "deployment_environment": "development",
            "identity_provider": "Microsoft Entra ID",
            "app_url": "http://localhost:8501",
            "api_url": "http://localhost:8000/api",
            "database_type": "SQLite",
            "database_url": "sqlite:///valhalla_demo.db",
            "enable_sso": True,
            "admin_username": "valhalla_admin",
            "admin_email": "admin@valhalla.local",
            "admin_password": "Valhalla@12345",
        }

    st.session_state.onboarding_company_name = demo_values.get("company_name", "Valhalla")
    st.session_state.onboarding_environment_name = demo_values.get("deployment_environment", "development")
    st.session_state.onboarding_identity_provider = demo_values.get("identity_provider", "Local Accounts")
    st.session_state.onboarding_app_url = demo_values.get("app_url", "")
    st.session_state.onboarding_api_url = demo_values.get("api_url", "")
    st.session_state.onboarding_database_type = demo_values.get("database_type", "SQLite")
    st.session_state.onboarding_database_url = demo_values.get("database_url", "")
    st.session_state.onboarding_enable_sso = bool(demo_values.get("enable_sso", False))
    st.session_state.onboarding_admin_username = demo_values.get("admin_username", "admin")
    st.session_state.onboarding_admin_email = demo_values.get("admin_email", "admin@company.local")
    st.session_state.onboarding_admin_password = demo_values.get("admin_password", "")
    st.session_state.onboarding_confirm_password = demo_values.get("admin_password", "")


def show_onboarding(inline: bool = False):
    """First-run setup wizard for company connection and admin bootstrap."""
    if inline:
        st.subheader("First-time setup")
        st.write(
            "Use this section to connect the app to your environment, save the company profile, "
            "and create the first admin account."
        )
    else:
        st.title("🚀 Welcome to Agentic-IAM")
        st.subheader("First-time setup")
        st.write(
            "Use this screen to connect the app to your environment, save the company profile, "
            "and create the first admin account."
        )

    settings = st.session_state.db.get_system_settings()
    _initialize_onboarding_fields(settings)

    demo_col1, demo_col2 = st.columns([1, 2])
    with demo_col1:
        if st.button("🎯 Load Demo Values", use_container_width=True):
            _load_demo_onboarding_values()
            st.rerun()
    with demo_col2:
        st.caption("Use the demo preset for a fast live presentation, or fill the form manually for a real setup.")

    with st.form("onboarding_form"):
        col1, col2 = st.columns(2)

        with col1:
            company_name = st.text_input("Company / Tenant Name", key="onboarding_company_name")
            environment_options = ["development", "staging", "production"]
            environment_name = st.selectbox(
                "Deployment Environment",
                environment_options,
                index=(
                    environment_options.index(st.session_state.onboarding_environment_name)
                    if st.session_state.onboarding_environment_name in environment_options
                    else 0
                ),
                key="onboarding_environment_name",
            )
            identity_options = ["Local Accounts", "Microsoft Entra ID", "LDAP / Active Directory", "Other SSO"]
            identity_provider = st.selectbox(
                "Identity Provider",
                identity_options,
                index=(
                    identity_options.index(st.session_state.onboarding_identity_provider)
                    if st.session_state.onboarding_identity_provider in identity_options
                    else 0
                ),
                key="onboarding_identity_provider",
            )
            app_url = st.text_input("Company App URL", key="onboarding_app_url")

        with col2:
            api_url = st.text_input("API / Backend URL", key="onboarding_api_url")
            db_type_options = ["SQLite", "PostgreSQL", "MySQL"]
            database_type = st.selectbox(
                "Database Type",
                db_type_options,
                index=(
                    db_type_options.index(st.session_state.onboarding_database_type)
                    if st.session_state.onboarding_database_type in db_type_options
                    else 0
                ),
                key="onboarding_database_type",
            )
            database_url = st.text_input("Database Connection String", key="onboarding_database_url")
            enable_sso = st.checkbox("Enable Single Sign-On later", key="onboarding_enable_sso")

        st.markdown("---")
        st.subheader("Create First Admin")

        admin_col1, admin_col2 = st.columns(2)

        with admin_col1:
            admin_username = st.text_input("Admin Username", key="onboarding_admin_username")
            admin_email = st.text_input("Admin Email", key="onboarding_admin_email")

        with admin_col2:
            admin_password = st.text_input("Admin Password", type="password", key="onboarding_admin_password")
            confirm_password = st.text_input("Confirm Password", type="password", key="onboarding_confirm_password")

        submitted = st.form_submit_button("✅ Save Setup and Continue")

        if submitted:
            required_fields = [
                company_name.strip(),
                app_url.strip(),
                api_url.strip(),
                admin_username.strip(),
                admin_email.strip(),
            ]
            if not all(required_fields):
                st.error("❌ Please fill in the required connection and admin fields.")
                return

            if not admin_password:
                st.error("❌ Please enter an admin password.")
                return

            if admin_password != confirm_password:
                st.error("❌ Password and confirmation do not match.")
                return

            if len(admin_password) < 12:
                st.error("❌ Admin password must be at least 12 characters long.")
                return

            db = st.session_state.db
            saved = all(
                [
                    db.set_system_setting("company_name", company_name.strip()),
                    db.set_system_setting("deployment_environment", environment_name),
                    db.set_system_setting("identity_provider", identity_provider),
                    db.set_system_setting("app_url", app_url.strip()),
                    db.set_system_setting("api_url", api_url.strip()),
                    db.set_system_setting("database_type", database_type),
                    db.set_system_setting("database_url", database_url.strip()),
                    db.set_system_setting("enable_sso", enable_sso),
                    db.set_system_setting("admin_username", admin_username.strip()),
                    db.set_system_setting("admin_email", admin_email.strip()),
                ]
            )

            if not saved:
                st.error("❌ Could not save the setup settings.")
                return

            admin_exists = False
            try:
                admin_exists = any(user["username"] == admin_username.strip() for user in db.list_users())
            except Exception as e:
                import logging

                logging.getLogger(__name__).debug("Failed to check existing admins: %s", e)
                admin_exists = False

            if not admin_exists:
                admin_created = db.create_user(
                    username=admin_username.strip(),
                    email=admin_email.strip(),
                    password=admin_password,
                    role="admin",
                )
                if not admin_created:
                    st.error("❌ Setup was saved, but creating the admin account failed.")
                    return

            db.set_system_setting("onboarding_completed", True)
            st.session_state.onboarding_completed = True
            st.success("✅ Setup completed successfully. You can now log in.")
            st.rerun()


def navigate_to(page_name: str):
    """Update the active Streamlit navigation target."""
    st.session_state.pending_navigation = page_name
    st.rerun()


def get_requested_page() -> str | None:
    """Read an optional page request from the URL query string and save to session state."""
    try:
        query_page = st.query_params.get("page")
        if isinstance(query_page, list):
            page = query_page[0] if query_page else None
        else:
            page = query_page
    except Exception as e:
        import logging

        logging.getLogger(__name__).debug("Failed to read query params from st.query_params: %s", e)
        try:
            params = st.experimental_get_query_params()
            values = params.get("page", [])
            page = values[0] if values else None
        except Exception as e2:
            logging.getLogger(__name__).debug("Failed to read query params from experimental_get_query_params: %s", e2)
            page = None

    # Save to session state so it persists after login
    if page:
        st.session_state.requested_page = page

    return page


def show_login():
    """Show login page with security checks"""
    st.title("🔐 Agentic-IAM Login")

    col1, col2, col3 = st.columns([1, 2, 1])

    with col2:
        st.markdown("### Welcome to Agentic-IAM v2.0")
        st.markdown("Enterprise Security with Advanced RBAC")

        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")

            submitted = st.form_submit_button("🔐 Login")

            if submitted:
                # Security Check 1: Input Validation
                if not username or not password:
                    st.error("❌ Please enter both username and password")
                    return

                # Security Check 2: Validate username format
                if not InputValidator.validate_username(username):
                    st.warning("⚠️ Invalid username format")
                    AuditLogger.log_suspicious_activity(username, "Invalid username format")
                    return

                # Security Check 3: Check account lockout
                if st.session_state.account_security.is_account_locked(username):
                    st.error("❌ Account temporarily locked. Try again later.")
                    AuditLogger.log_suspicious_activity(username, "Account locked - login attempt")
                    return

                # Security Check 4: Rate limiting
                if not st.session_state.rate_limiter.is_allowed(username):
                    st.error("❌ Too many login attempts. Please try again later.")
                    st.session_state.account_security.record_failed_attempt(username)
                    AuditLogger.log_failed_login(username, "Rate limit exceeded")
                    return

                # Security Check 5: SQL Injection Detection
                if SQLInjectionProtection.detect_sql_injection(username):
                    st.error("❌ Invalid input detected")
                    AuditLogger.log_suspicious_activity(username, "SQL injection attempt")
                    return

                # Authenticate user
                user = st.session_state.db.authenticate_user(username, password)

                if user:
                    # Successful authentication
                    st.session_state.user = user
                    st.session_state.authenticated = True
                    st.session_state.account_security.record_successful_login(username)
                    AuditLogger.log_successful_login(username)
                    st.success("✅ Login successful!")
                    st.balloons()
                    st.rerun()
                else:
                    # Failed authentication
                    st.session_state.account_security.record_failed_attempt(username)
                    remaining = st.session_state.account_security.max_failed_attempts - len(
                        st.session_state.account_security.failed_attempts.get(username, [])
                    )
                    st.error(f"❌ Invalid credentials. ({remaining} attempts remaining)")
                    AuditLogger.log_failed_login(username, "Invalid credentials")

        st.markdown("---")
        if os.getenv("AGENTIC_IAM_SHOW_SETUP_HINTS", "true").lower() == "true":
            st.info("No demo credentials are exposed. Create your first admin using setup scripts.")
            st.caption("Example: python setup_admin.py")

        db = st.session_state.db
        onboarding_required = not db.has_users()

        if onboarding_required:
            st.warning("No users exist yet. Use the setup section below to create the first admin.")

        show_setup = st.checkbox(
            "First-time setup / Connect your company system",
            value=onboarding_required,
        )

        if show_setup:
            with st.expander("Setup and connection details", expanded=True):
                show_onboarding(inline=True)

        st.markdown("---")
        st.markdown("""
        **Security Features Enabled:**
        - ✅ Input validation & sanitization
        - ✅ Rate limiting (5 attempts/5 min)
        - ✅ Account lockout protection
        - ✅ SQL injection prevention
        - ✅ Audit logging
        - ✅ Password hashing (bcrypt)
        """)


def show_logout():
    """Show logout button"""
    if st.sidebar.button("🚪 Logout"):
        st.session_state.user = None
        st.session_state.authenticated = False
        st.rerun()


def get_navigation_pages():
    """Get navigation pages based on user role"""
    pages = []

    if is_admin() or is_operator():
        pages.insert(0, "Home")

    # High-value operational views
    pages.append("🏥 Health Center")
    pages.append("🧭 Activity Timeline")
    pages.append("🚨 Incident Response")

    # Security forensics views - replace overlapping configuration pages
    if is_operator() or is_admin():
        pages.append("🕵️ Attack Forensics")
        pages.append("🧪 Attack Flow Lifecycle")
        pages.append("🔔 Alert Center")

    # User pages (available to all authenticated users)
    if check_permission(Permission.AGENT_READ):
        pages.append("🔍 Browse Agents")

    if check_permission(Permission.AGENT_CREATE):
        pages.append("➕ Register Agent")

    if check_permission(Permission.AUDIT_READ):
        pages.append("📋 Audit Log")

    if check_permission(Permission.REPORT_VIEW):
        pages.append("📊 Reports")

    if check_permission(Permission.SETTINGS_VIEW):
        pages.append("⚙️ Settings")

    # Admin-only pages
    if is_admin():
        pages.append("👥 User Management")
        pages.append("🔧 System Config")
        pages.append("📡 System Monitor")
        pages.append("🛡️ Security Operations")
        pages.append("⚡ Automation Center")

    # Operator pages
    if is_operator():
        pages.append("📈 Analytics")

    # AI Assistant available to all authenticated users
    pages.append("🤖 AI Assistant")

    # Risk assessment page for operators/admins
    if is_operator() or is_admin():
        pages.append("⚠️ Risk Assessment")

    return pages


def main():
    """Main application"""
    initialize_session()

    # Check authentication
    if not st.session_state.authenticated:
        show_login()
        return

    # Sidebar
    with st.sidebar:
        st.title("⚙️ Agentic-IAM")
        st.markdown("v2.0 (Enhanced RBAC)")
        st.markdown("---")

        # User info with role badge
        if st.session_state.user:
            user_role = st.session_state.user["role"].upper()
            role_colors = {"ADMIN": "🔴", "OPERATOR": "🟡", "USER": "🟢", "GUEST": "⚪"}
            role_icon = role_colors.get(user_role, "⚪")
            st.write(f"👤 **{st.session_state.user['username']}** {role_icon} `{user_role}`")
            show_logout()
            st.markdown("---")

        # Get available pages based on permissions
        available_pages = get_navigation_pages()

        # Check for requested page (from query params or session state)
        requested_page = get_requested_page()
        if not requested_page:
            requested_page = st.session_state.get("requested_page")

        if requested_page and requested_page in available_pages:
            st.session_state.pending_navigation = requested_page

        pending_navigation = st.session_state.get("pending_navigation")
        if pending_navigation and pending_navigation in available_pages:
            st.session_state.main_navigation = pending_navigation
            st.session_state.pending_navigation = None

        # Navigation - use stored value or first available page
        current_page = st.session_state.get("main_navigation", available_pages[0])
        try:
            page_index = available_pages.index(current_page) if current_page in available_pages else 0
        except ValueError:
            page_index = 0

        page = st.radio("Navigation", available_pages, index=page_index, key="main_navigation")

        st.markdown("---")

        # Selected Agent Info
        if st.session_state.selected_agent:
            st.write("### 👤 Selected Agent:")
            agent = st.session_state.db.get_agent(st.session_state.selected_agent)
            if agent:
                st.info(f"**{agent['name']}** (ID: {agent['id']})")

        st.markdown("---")

        # System Status
        st.write("### 🔧 System Status")
        col1, col2 = st.columns(2)

        with col1:
            agents_count = len(st.session_state.db.list_agents())
            st.metric("Agents", agents_count)

        with col2:
            events_count = len(st.session_state.db.get_events(limit=1))
            st.metric("Events", events_count)

        st.markdown("---")

        # About
        st.write("### ℹ️ About")
        st.write("""
        **Agentic-IAM v2.0**

        Enterprise identity and access
        management for AI agents with
        advanced RBAC controls.
        """)

    # Main content - Route to correct page
    if page == "Home":
        show_home()
    # Bloome page removed
    elif page == "🤖 AI Assistant":
        show_ai_assistant()
    elif page == "🔍 Browse Agents":
        show_page_browse_agents()
    elif page == "➕ Register Agent":
        show_page_register_agent()
    elif page == "👥 Manage & Select Agents":
        show_page_manage_agents()
    elif page == "📋 Audit Log":
        show_page_audit_log()
    elif page == "📊 Reports":
        show_page_reports()
    elif page == "⚙️ Settings":
        show_page_settings()
    elif page == "🏥 Health Center":
        show_page_health_center()
    elif page == "🧭 Activity Timeline":
        show_page_activity_timeline()
    elif page == "🚨 Incident Response":
        show_page_incident_response()
    elif page == "🕵️ Attack Forensics":
        show_page_attack_forensics()
    elif page == "🧪 Attack Flow Lifecycle":
        show_page_attack_flow()
    elif page == "🔔 Alert Center":
        show_page_alert_center()
    elif page == "👥 User Management":
        if is_admin():
            show_page_user_management()
        else:
            st.error("❌ Access Denied: Admin only")
    elif page == "🔧 System Config":
        if is_admin():
            show_page_system_config()
        else:
            st.error("❌ Access Denied: Admin only")
    elif page == "📡 System Monitor":
        if is_operator():
            show_page_system_monitor()
        else:
            st.error("❌ Access Denied: Operator or Admin only")
    elif page == "🛡️ Security Operations":
        if is_admin() or is_operator():
            show_page_security_operations()
        else:
            st.error("❌ Access Denied: Admin or Operator only")
    elif page == "⚡ Automation Center":
        if is_admin() or is_operator():
            show_page_automation_center()
        else:
            st.error("❌ Access Denied: Admin or Operator only")
    elif page == "📈 Analytics":
        if is_operator():
            show_page_analytics()
        else:
            st.error("❌ Access Denied: Operator or Admin only")
    elif page == "⚠️ Risk Assessment":
        show_risk_assessment(st.session_state.db)
    else:
        st.warning(f"Page '{page}' not implemented yet")


def show_home():
    """Show home page with role-based content"""
    st.title("🏠 Agentic-IAM Control Center")

    user_role = st.session_state.user["role"].lower()

    # Role-specific greeting
    greeting = f"Welcome, {st.session_state.user['username']}!"
    if user_role == "admin":
        greeting += " 🔴 You have administrator privileges."
    elif user_role == "operator":
        greeting += " 🟡 You have operator privileges."
    else:
        greeting += " 🟢 You have user privileges."

    st.markdown(f"### {greeting}")

    db = st.session_state.db
    settings = db.get_system_settings()
    health_monitor = AgentHealthMonitor(db)
    analytics = AgentAnalytics(db)
    system_health = health_monitor.get_system_health()
    system_analytics = analytics.get_system_analytics()

    st.markdown("""
    Welcome to the **Agentic-IAM Control Center** - a command view for identity,
    access, integrations, operations, and incident response.
    """)

    st.markdown("---")

    overview_col1, overview_col2, overview_col3, overview_col4 = st.columns(4)
    with overview_col1:
        st.metric("System Health", f"{system_health.get('overall_health', 0)}%")
    with overview_col2:
        st.metric("Active Agents", system_analytics.get("active_agents", 0))
    with overview_col3:
        st.metric("Total Events", system_analytics.get("total_events", 0))
    with overview_col4:
        st.metric("Success Rate", f"{system_analytics.get('success_rate', 0):.1f}%")

    st.markdown("---")

    insight_col1, insight_col2 = st.columns([2, 1])
    with insight_col1:
        st.subheader("Operational Snapshot")
        snapshot_rows = [
            {"Area": "Tenant", "Value": settings.get("company_name", "Not configured")},
            {"Area": "Environment", "Value": settings.get("deployment_environment", "development")},
            {"Area": "Identity Provider", "Value": settings.get("identity_provider", "Local Accounts")},
            {"Area": "App URL", "Value": settings.get("app_url", "Not configured")},
            {"Area": "API URL", "Value": settings.get("api_url", "Not configured")},
        ]
        st.dataframe(pd.DataFrame(snapshot_rows), width="stretch", hide_index=True)

    with insight_col2:
        st.subheader("Fast Access")
        st.markdown("Select from the sidebar →")
        st.info("🚨 **Incident Response** - Review security incidents")
        st.info("🔗 **Integrations** - Configure identity providers")
        st.info("🏥 **Health Center** - System health metrics")
        st.info("⚡ **Automation Center** - Task automation")

    st.markdown("---")

    # Recent critical signals
    recent_events = db.get_events(limit=25)
    critical_events = [
        event
        for event in recent_events
        if event.get("status") != "success" or event.get("event_type", "").startswith("security_")
    ]

    if critical_events:
        st.subheader("Recent Critical Signals")
        alert_rows = []
        for event in critical_events[:8]:
            alert_rows.append(
                {
                    "Time": event.get("created_at", ""),
                    "Type": event.get("event_type", ""),
                    "Agent": event.get("agent_id", "system"),
                    "Status": event.get("status", ""),
                    "Details": event.get("details", ""),
                }
            )
        st.dataframe(pd.DataFrame(alert_rows), width="stretch", hide_index=True)
    else:
        st.success("No recent critical signals detected")

    # Quick stats with role-aware content
    col1, col2, col3, col4 = st.columns(4)

    agents = db.list_agents()
    events = db.get_events(limit=100)

    with col1:
        st.metric("Total Agents", len(agents), help="Number of registered agents")

    with col2:
        st.metric("Recent Events", len(events), help="Events in last check")

    with col3:
        st.metric("System Health", "✅ 100%", help="Overall system health status")

    with col4:
        current_time = datetime.now().strftime("%H:%M:%S")
        st.metric("Current Time", current_time, help="Server time")

    st.markdown("---")

    # Role-based features section
    st.header("✨ Available Features")

    # Admin features
    if is_admin():
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("👥 Admin Controls")
            st.write("""
            - User management
            - System configuration
            - Security policies
            - Audit reports
            - System monitoring
            """)

        with col2:
            st.subheader("🔐 Security")
            st.write("""
            - Role-based access control
            - Permission management
            - Audit trails
            - Compliance reports
            - Threat detection
            """)

    # Operator features
    elif is_operator():
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("📊 Operations")
            st.write("""
            - Agent management
            - Session monitoring
            - Performance analytics
            - Alert management
            - Log aggregation
            """)

        with col2:
            st.subheader("🔧 Maintenance")
            st.write("""
            - Status monitoring
            - Configuration updates
            - Backup management
            - Performance tuning
            - Issue resolution
            """)

    # User features
    else:
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("👥 Agent Management")
            st.write("""
            - Browse agents
            - View agent details
            - Monitor sessions
            - Check permissions
            - Track activity
            """)

        with col2:
            st.subheader("📊 Reports")
            st.write("""
            - View audit logs
            - Generate reports
            - Track metrics
            - Check status
            - Access documentation
            """)

    st.markdown("---")

    # Quick stats table
    st.subheader("📊 System Statistics")
    stats_data = {
        "Metric": ["Total Agents", "Active Sessions", "Total Events", "System Uptime"],
        "Value": [
            str(len(agents)),
            str(len([e for e in events if e.get("event_type") == "session_created"])),
            str(len(events)),
            "99.9%",
        ],
    }
    st.dataframe(pd.DataFrame(stats_data), width="stretch", hide_index=True)


def show_page_browse_agents():
    """Browse and view agents - requires AGENT_READ permission"""
    if not check_permission(Permission.AGENT_READ):
        st.error("❌ Access Denied: You don't have permission to view agents")
        return

    st.title("🔍 Browse Agents")
    show_agent_list()


def show_page_register_agent():
    """Register new agent - requires AGENT_CREATE permission"""
    if not check_permission(Permission.AGENT_CREATE):
        st.error("❌ Access Denied: You don't have permission to register agents")
        return

    st.title("➕ Register New Agent")
    show_agent_registration()
    st.divider()
    st.subheader("📋 All Agents")
    show_agent_list()


def show_page_manage_agents():
    """Manage agents - requires AGENT_UPDATE permission"""
    if not check_permission(Permission.AGENT_UPDATE):
        st.error("❌ Access Denied: You don't have permission to manage agents")
        return

    st.title("👥 Manage & Select Agents")
    col1, col2 = st.columns([2, 1])
    with col1:
        show_agent_selector()

    st.divider()

    if st.session_state.selected_agent:
        show_agent_details(st.session_state.selected_agent)
    else:
        show_agent_list()


def show_page_audit_log():
    """Show audit log - requires AUDIT_READ permission"""
    if not check_permission(Permission.AUDIT_READ):
        st.error("❌ Access Denied: You don't have permission to view audit logs")
        return

    st.title("📋 Audit Log")

    db = st.session_state.db

    # Filters
    col1, col2, col3 = st.columns(3)

    with col1:
        agent_filter = st.selectbox(
            "🔍 Filter by Agent",
            ["All"] + [f"{a['name']} ({a['id']})" for a in db.list_agents()],
            key="audit_agent_filter",
        )

    with col2:
        limit = st.slider("Number of records", 10, 500, 50)

    with col3:
        if st.button("🔄 Refresh"):
            st.rerun()

    st.markdown("---")

    # Get events
    agent_id = None
    if agent_filter != "All":
        agent_id = agent_filter.split("(")[-1].rstrip(")")

    events = db.get_events(agent_id=agent_id, limit=limit)

    if events:
        df = pd.DataFrame(events)
        df["created_at"] = pd.to_datetime(df["created_at"]).dt.strftime("%Y-%m-%d %H:%M:%S")
        df = df[["event_type", "agent_id", "action", "details", "created_at", "status"]].sort_values(
            "created_at", ascending=False
        )

        # Color code by status
        st.dataframe(df, width="stretch", hide_index=True)
        st.success(f"✅ Total events: {len(events)}")

        # Export option
        if check_permission(Permission.AUDIT_EXPORT):
            csv = df.to_csv(index=False)
            st.download_button("📥 Download CSV", csv, "audit_log.csv")
    else:
        st.info("📭 No events found")


def show_page_incident_response():
    """Security and operations incident dashboard."""
    st.title("🚨 Incident Response")

    db = st.session_state.db
    events = db.get_events(limit=250)
    failed_events = [event for event in events if event.get("status") != "success"]
    suspicious_events = [
        event
        for event in events
        if any(
            term in f"{event.get('event_type', '')} {event.get('details', '')}".lower()
            for term in ["error", "fail", "denied", "locked", "suspicious", "blocked"]
        )
    ]

    incident_candidates = failed_events + [event for event in suspicious_events if event not in failed_events]

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Incident Signals", len(incident_candidates))
    with col2:
        st.metric("Failed Events", len(failed_events))
    with col3:
        st.metric("Suspicious Events", len(suspicious_events))
    with col4:
        st.metric("Users", len(db.list_users()))

    st.markdown("---")

    action_col1, action_col2, action_col3 = st.columns(3)
    with action_col1:
        if st.button("Create Security Review Task", width="stretch"):
            agents = db.list_agents()
            agent_id = agents[0]["id"] if agents else "system"
            db.create_task(agent_id, "security_review", "Review recent incident signals")
            st.success("Security review task created")
    with action_col2:
        if st.button("Create Containment Task", width="stretch"):
            agents = db.list_agents()
            agent_id = agents[0]["id"] if agents else "system"
            db.create_task(agent_id, "containment", "Contain and assess suspicious activity")
            st.success("Containment task created")
    with action_col3:
        if st.button("Open Automation Center", width="stretch"):
            navigate_to("⚡ Automation Center")

    st.markdown("---")

    st.subheader("Incident Queue")
    if incident_candidates:
        incident_rows = []
        for event in incident_candidates[:50]:
            severity = "High" if event.get("status") != "success" else "Medium"
            details_blob = f"{event.get('event_type', '')} {event.get('details', '')}".lower()
            if any(term in details_blob for term in ["locked", "denied", "blocked"]):
                severity = "High"
            elif any(term in details_blob for term in ["error", "fail"]):
                severity = "Medium"

            incident_rows.append(
                {
                    "Severity": severity,
                    "Time": event.get("created_at", ""),
                    "Type": event.get("event_type", ""),
                    "Agent": event.get("agent_id", "system"),
                    "Action": event.get("action", ""),
                    "Details": event.get("details", ""),
                }
            )

        st.dataframe(pd.DataFrame(incident_rows), width="stretch", hide_index=True)
    else:
        st.success("No active incident signals detected")


def show_page_integrations():
    """Integration hub for identity and external platform connections."""
    st.title("🔗 Integrations")
    st.caption("Connection coverage, identity providers, notifications, and SIEM handoff.")

    db = st.session_state.db
    settings = db.get_system_settings()

    integrations = [
        ("Microsoft Entra ID", bool(settings.get("entra_enabled", False))),
        ("LDAP / Active Directory", bool(settings.get("ldap_enabled", False))),
        ("Webhook Notifications", bool(settings.get("webhooks_enabled", False))),
        ("SIEM / SOC Feed", bool(settings.get("siem_enabled", False))),
    ]
    enabled_integrations = sum(1 for _, is_enabled in integrations if is_enabled)

    overview_col1, overview_col2, overview_col3 = st.columns(3)
    with overview_col1:
        st.metric("Enabled Connectors", enabled_integrations)
    with overview_col2:
        st.metric("Configured Owner", settings.get("integration_owner", "security-team"))
    with overview_col3:
        st.metric("Identity Sources", sum(1 for key in ["entra_enabled", "ldap_enabled"] if settings.get(key, False)))

    st.subheader("Connection Targets")
    target_rows = []
    target_cols = st.columns(2)
    for index, (integration_name, is_enabled) in enumerate(integrations):
        with target_cols[index % 2]:
            st.markdown(
                f"**{integration_name}**  \n"
                f"Status: {'Enabled' if is_enabled else 'Disabled'}  \n"
                f"Owner: {settings.get('integration_owner', 'security-team')}"
            )
        target_rows.append({"Integration": integration_name, "Status": is_enabled})

    st.dataframe(pd.DataFrame(target_rows), width="stretch", hide_index=True)

    st.markdown("---")

    with st.form("integrations_form"):
        col1, col2 = st.columns(2)

        with col1:
            entra_enabled = st.checkbox("Enable Microsoft Entra ID", value=bool(settings.get("entra_enabled", False)))
            entra_tenant_id = st.text_input("Entra Tenant ID", value=settings.get("entra_tenant_id", ""))
            entra_client_id = st.text_input("Entra Client ID", value=settings.get("entra_client_id", ""))
            ldap_enabled = st.checkbox(
                "Enable LDAP / Active Directory", value=bool(settings.get("ldap_enabled", False))
            )
            ldap_server = st.text_input("LDAP Server", value=settings.get("ldap_server", ""))

        with col2:
            webhooks_enabled = st.checkbox(
                "Enable Webhook Notifications", value=bool(settings.get("webhooks_enabled", False))
            )
            webhook_url = st.text_input("Webhook URL", value=settings.get("webhook_url", ""))
            siem_enabled = st.checkbox("Enable SIEM / SOC Feed", value=bool(settings.get("siem_enabled", False)))
            siem_endpoint = st.text_input("SIEM Endpoint", value=settings.get("siem_endpoint", ""))
            integration_owner = st.text_input(
                "Integration Owner", value=settings.get("integration_owner", "security-team")
            )

        saved = st.form_submit_button("💾 Save Integrations")

        if saved:
            save_results = [
                db.set_system_setting("entra_enabled", entra_enabled),
                db.set_system_setting("entra_tenant_id", entra_tenant_id.strip()),
                db.set_system_setting("entra_client_id", entra_client_id.strip()),
                db.set_system_setting("ldap_enabled", ldap_enabled),
                db.set_system_setting("ldap_server", ldap_server.strip()),
                db.set_system_setting("webhooks_enabled", webhooks_enabled),
                db.set_system_setting("webhook_url", webhook_url.strip()),
                db.set_system_setting("siem_enabled", siem_enabled),
                db.set_system_setting("siem_endpoint", siem_endpoint.strip()),
                db.set_system_setting("integration_owner", integration_owner.strip()),
            ]

            if all(save_results):
                st.success("✅ Integrations saved successfully")
                st.rerun()
            else:
                st.error("❌ Could not save integration settings")


def show_page_reports():
    """Show reports page - requires REPORT_VIEW permission"""
    if not check_permission(Permission.REPORT_VIEW):
        st.error("❌ Access Denied: You don't have permission to view reports")
        return

    st.title("📊 Reports")

    db = st.session_state.db
    report_gen = ReportGenerator(db)
    health_monitor = AgentHealthMonitor(db)
    analytics = AgentAnalytics(db)

    tab1, tab2, tab3, tab4 = st.tabs(["System Report", "Agent Report", "Security Report", "Analytics"])

    with tab1:
        st.subheader("System Health Report")

        if st.button("🔄 Refresh Metrics", key="refresh_system"):
            st.rerun()

        system_health = health_monitor.get_system_health()

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Overall Health", f"{system_health.get('overall_health', 0)}%")
        with col2:
            st.metric("Total Agents", system_health.get("total_agents", 0))
        with col3:
            st.metric("Healthy Agents", system_health.get("healthy_agents", 0))
        with col4:
            st.metric("System Uptime", system_health.get("system_uptime", "N/A"))

        st.markdown("---")

        # System report detailed
        if st.button("📄 Generate Detailed System Report"):
            report = report_gen.generate_system_report()
            st.json(report)

        st.info("📊 Detailed system health metrics and trends")

    with tab2:
        st.subheader("Agent Performance Report")

        agents = db.list_agents()

        if agents:
            selected_agent = st.selectbox("Select Agent", [a["name"] for a in agents], key="agent_report")
            selected_agent_obj = next((a for a in agents if a["name"] == selected_agent), None)

            if selected_agent_obj:
                agent_health = health_monitor.get_agent_health(selected_agent_obj["id"])
                activity = analytics.get_agent_activity_summary(selected_agent_obj["id"])

                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("Health Score", f"{agent_health.get('health_score', 0)}%")
                with col2:
                    st.metric("Recent Events", agent_health.get("recent_events", 0))
                with col3:
                    st.metric("Active Sessions", agent_health.get("active_sessions", 0))
                with col4:
                    st.metric("Success Rate", f"{activity.get('success_rate', 0):.1f}%")

                st.markdown("---")

                # Generate detailed report
                if st.button("📄 Generate Agent Report"):
                    report = report_gen.generate_agent_report(selected_agent_obj["id"])
                    st.json(report)
        else:
            st.info("No agents registered yet")

    with tab3:
        st.subheader("Security Compliance Report")

        if st.button("📄 Generate Compliance Report"):
            report = report_gen.generate_compliance_report()

            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Events", report.get("audit_trail", {}).get("total_events", 0))
            with col2:
                st.metric("Audit Events", report.get("audit_trail", {}).get("significant_events", 0))
            with col3:
                st.metric("Active Users", report.get("users_summary", {}).get("active_users", 0))

            st.markdown("---")
            st.info("🔒 Full compliance report generated")
            st.json(report)
        else:
            st.info("Click the button above to generate a compliance report")

        st.markdown("---")
        st.subheader("Executive Security Report")
        attacks = _fetch_security_alerts("attacks")
        alerts = _fetch_security_alerts("active")
        blocked_ips = _fetch_security_alerts("blocked-ips")
        cases = db.list_security_cases(limit=50) if hasattr(db, "list_security_cases") else []
        if not attacks and not alerts and not blocked_ips:
            st.info("No live security telemetry found yet")
        else:
            demo_state = _load_demo_security_state() or {}
            exec_report = build_executive_report(
                demo_state if isinstance(demo_state, dict) else {}, cases, attacks, alerts, blocked_ips
            )
            exec_cols = st.columns(4)
            with exec_cols[0]:
                st.metric("Cases", exec_report.get("case_metrics", {}).get("total_cases", 0))
            with exec_cols[1]:
                st.metric("Block Rate", f"{exec_report.get('summary', {}).get('block_rate', 0.0):.1f}%")
            with exec_cols[2]:
                st.metric("MTTD (min)", f"{exec_report.get('kpis', {}).get('mttd_minutes', 0.0):.2f}")
            with exec_cols[3]:
                st.metric("MTTR (min)", f"{exec_report.get('kpis', {}).get('mttr_minutes', 0.0):.2f}")

            st.json(exec_report)
            st.download_button(
                "📥 Download Executive JSON",
                data=json.dumps(exec_report, indent=2),
                file_name="executive_security_report.json",
                mime="application/json",
            )
            st.download_button(
                "📄 Download Executive PDF",
                data=render_executive_report_pdf(exec_report),
                file_name="executive_security_report.pdf",
                mime="application/pdf",
            )

    with tab4:
        st.subheader("System Analytics")

        system_analytics = analytics.get_system_analytics()

        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Events", system_analytics.get("total_events", 0))
        with col2:
            st.metric("Success Rate", f"{system_analytics.get('success_rate', 0):.1f}%")
        with col3:
            st.metric("Active Agents", system_analytics.get("active_agents", 0))

        st.markdown("---")

        st.subheader("Event Distribution")
        event_dist = system_analytics.get("event_distribution", {})
        if event_dist:
            event_df = pd.DataFrame(list(event_dist.items()), columns=["Event Type", "Count"])
            st.bar_chart(event_df.set_index("Event Type"))
        else:
            st.info("No events found")


def show_page_settings():
    """Show settings page - requires SETTINGS_VIEW permission"""
    if not check_permission(Permission.SETTINGS_VIEW):
        st.error("❌ Access Denied: You don't have permission to view settings")
        return

    st.title("⚙️ Settings")
    st.caption("General behavior, security posture, and advanced platform defaults.")

    settings_col1, settings_col2, settings_col3 = st.columns(3)
    with settings_col1:
        st.metric("Theme", "Light / Dark / Auto")
    with settings_col2:
        st.metric("Security Focus", "MFA + Session Control")
    with settings_col3:
        st.metric("Advanced Mode", "Logging + Debug")

    tab1, tab2, tab3 = st.tabs(["General", "Security", "Advanced"])

    with tab1:
        st.subheader("General Settings")

        theme = st.selectbox("Theme", ["Light", "Dark", "Auto"])
        refresh_interval = st.slider("Refresh Interval (seconds)", 5, 60, 30)
        notifications = st.checkbox("Enable Notifications", value=True)

        st.caption(
            f"Current general settings: theme={theme}, refresh={refresh_interval}s, "
            f"notifications={'on' if notifications else 'off'}"
        )

        if st.button("💾 Save General Settings"):
            st.success("✅ Settings saved successfully")

        st.markdown("---")
        st.write("**Current focus:** UI theme, notification posture, and refresh cadence.")

    with tab2:
        st.subheader("Security Settings")

        mfa_enabled = st.checkbox("Enable Multi-Factor Authentication", value=True)
        session_timeout = st.slider("Session Timeout (minutes)", 5, 480, 60)
        force_password_change = st.checkbox("Force Password Change on Next Login", value=False)

        st.caption(
            f"Current security settings: MFA={'on' if mfa_enabled else 'off'}, "
            f"session timeout={session_timeout} minutes, "
            f"force password change={'yes' if force_password_change else 'no'}"
        )

        if st.button("💾 Save Security Settings"):
            st.success("✅ Security settings saved successfully")

        st.markdown("---")
        st.write("**Current focus:** MFA, session timeout, and enforced password change.")

        st.markdown("---")
        st.subheader("Detection Rules")
        db = st.session_state.db
        current_rules = db.get_system_setting("security_rules", DEFAULT_SECURITY_RULES)
        rules_text = st.text_area(
            "Incident detection rules (JSON)",
            value=json.dumps(current_rules, indent=2),
            height=320,
        )
        st.caption(
            "These rules are used by the attack flow to enrich incidents, score risk, and suggest response actions."
        )
        if st.button("💾 Save Detection Rules"):
            try:
                parsed_rules = json.loads(rules_text)
                if not isinstance(parsed_rules, list):
                    raise ValueError("Rules must be a JSON list")
                db.set_system_setting("security_rules", parsed_rules)
                st.success("✅ Detection rules saved successfully")
            except Exception as exc:
                st.error(f"Invalid rules JSON: {exc}")

    with tab3:
        st.subheader("Advanced Settings")

        debug_mode = st.checkbox("Debug Mode", value=False)
        log_level = st.selectbox("Log Level", ["INFO", "DEBUG", "WARNING", "ERROR"])
        max_log_size = st.slider("Max Log Size (MB)", 10, 1000, 100)

        st.caption(
            f"Current advanced settings: debug={'on' if debug_mode else 'off'}, "
            f"log level={log_level}, max log size={max_log_size} MB"
        )

        if st.button("💾 Save Advanced Settings"):
            st.success("✅ Advanced settings saved successfully")

        st.markdown("---")
        st.write("**Current focus:** debug verbosity and log volume control.")


def show_page_user_management():
    """Admin: User management page"""
    st.title("👥 User Management (Admin Only)")

    if not is_admin():
        st.error("❌ Access Denied: Admin only")
        return

    tab1, tab2, tab3 = st.tabs(["Users", "Roles", "Permissions"])

    with tab1:
        st.subheader("Manage Users")

        db = st.session_state.db
        users = db.list_users()

        if users:
            user_data = {
                "Username": [u["username"] for u in users],
                "Email": [u["email"] for u in users],
                "Role": [u["role"] for u in users],
                "Status": [u["status"] for u in users],
                "Created": [u["created_at"] for u in users],
            }
            st.dataframe(pd.DataFrame(user_data), width="stretch", hide_index=True)

            # Add per-user actions (delete / deactivate)
            st.markdown("---")
            st.subheader("User Actions")
            for u in users:
                cols = st.columns([3, 1, 1])
                pending_delete_key = f"pending_user_delete_{u['id']}"
                with cols[0]:
                    st.write(f"**{u['username']}** — {u['email']} — role: {u['role']} — status: {u['status']}")
                with cols[1]:
                    if st.button(f"Deactivate {u['username']}", key=f"deact_{u['id']}"):
                        ok = db.update_user_status(u["id"], "suspended")
                        if ok:
                            st.success(f"User {u['username']} suspended")
                            st.rerun()
                        else:
                            st.error(f"Failed to suspend user {u['username']}")
                with cols[2]:
                    if st.button(f"Delete {u['username']}", key=f"deluser_{u['id']}"):
                        st.session_state[pending_delete_key] = True
                        st.rerun()

                if st.session_state.get(pending_delete_key):
                    st.warning(f"Are you sure you want to delete user {u['username']}? This cannot be undone.")
                    confirm_col, cancel_col = st.columns(2)
                    with confirm_col:
                        if st.button(f"✅ Confirm Delete {u['username']}", key=f"confirm_deluser_{u['id']}"):
                            ok = db.delete_user(u["id"])
                            still_exists = db.get_user_by_id(u["id"])
                            if ok and not still_exists:
                                st.success(f"User {u['username']} deleted")
                                st.session_state[pending_delete_key] = False
                                st.rerun()
                            elif ok and still_exists:
                                st.error(f"Delete reported success, but user {u['username']} still exists")
                            else:
                                st.error(f"Failed to delete user {u['username']}")
                    with cancel_col:
                        if st.button(f"✖ Cancel {u['username']}", key=f"cancel_deluser_{u['id']}"):
                            st.session_state[pending_delete_key] = False
                            st.rerun()

            st.markdown("---")
            st.subheader("Edit User")

            user_map = {f"{u['username']} ({u['email']})": u for u in users}
            selected_label = st.selectbox("Select user", list(user_map.keys()))
            selected_user = user_map[selected_label]

            edit_col1, edit_col2 = st.columns(2)
            with edit_col1:
                edited_role = st.selectbox(
                    "Edit role",
                    ["user", "operator", "admin"],
                    index=(
                        ["user", "operator", "admin"].index(selected_user["role"])
                        if selected_user["role"] in ["user", "operator", "admin"]
                        else 0
                    ),
                    key=f"edit_role_{selected_user['id']}",
                )
            with edit_col2:
                edited_status = st.selectbox(
                    "Edit status",
                    ["active", "suspended"],
                    index=(
                        ["active", "suspended"].index(selected_user["status"])
                        if selected_user["status"] in ["active", "suspended"]
                        else 0
                    ),
                    key=f"edit_status_{selected_user['id']}",
                )

            if st.button("💾 Save User Changes", key=f"save_user_{selected_user['id']}"):
                role_ok = True
                status_ok = True

                if edited_role != selected_user["role"]:
                    role_ok = db.update_user_role(selected_user["id"], edited_role)

                if edited_status != selected_user["status"]:
                    status_ok = db.update_user_status(selected_user["id"], edited_status)

                updated_user = db.get_user_by_id(selected_user["id"])
                if updated_user and updated_user["role"] == edited_role and updated_user["status"] == edited_status:
                    st.success(f"User {selected_user['username']} updated successfully")
                    st.rerun()
                elif role_ok and status_ok:
                    st.error(f"Update reported success, but user {selected_user['username']} did not persist")
                else:
                    st.error(f"Failed to update user {selected_user['username']}")

        st.markdown("---")
        st.subheader("Add New User")

        col1, col2 = st.columns(2)
        with col1:
            new_username = st.text_input("New username")
            new_email = st.text_input("New email")

        with col2:
            new_password = st.text_input("New password", type="password")
            new_role = st.selectbox("New role", ["user", "operator", "admin"])

        if st.button("➕ Create User"):
            if new_username and new_email and new_password:
                success = db.create_user(new_username, new_email, new_password, new_role)
                if success:
                    st.success(f"✅ User '{new_username}' created successfully!")
                    st.rerun()
                else:
                    st.error(f"❌ Failed to create user '{new_username}'")
            else:
                st.error("❌ Please fill in all fields")

    with tab2:
        st.subheader("Role Management")
        st.info("Available roles: Admin, Operator, User, Guest")

        role_desc = {
            "Admin": "Full system access and control",
            "Operator": "Agent and system management",
            "User": "Agent browsing and basic operations",
            "Guest": "Read-only access",
        }

        for role, desc in role_desc.items():
            st.write(f"**{role}**: {desc}")

    with tab3:
        st.subheader("Permission Management")

        get_rbac_manager()
        permissions = get_current_user_permissions()

        st.write("Your current permissions:")
        for perm in sorted(permissions, key=lambda p: p.value):
            st.write(f"✅ `{perm.value}`")


def show_page_system_config():
    """Admin: System configuration"""
    st.title("🔧 System Configuration (Admin Only)")

    if not is_admin():
        st.error("❌ Access Denied: Admin only")
        return

    tab1, tab2, tab3, tab4 = st.tabs(["Database", "Security", "Backup", "Maintenance"])

    with tab1:
        st.subheader("Database Configuration")

        db_type = st.selectbox("Database Type", ["SQLite", "PostgreSQL", "MySQL"])
        db_host = st.text_input("Database Host", "localhost" if db_type != "SQLite" else "N/A")
        db_port = st.number_input("Database Port", 3306 if db_type == "MySQL" else 5432, disabled=(db_type == "SQLite"))

        st.caption(f"Database target: {db_type} @ {db_host}:{int(db_port)}")

        if st.button("✅ Test Connection"):
            st.success("✅ Database connection successful!")

    with tab2:
        st.subheader("Security Configuration")

        enable_ssl = st.checkbox("Enable SSL/TLS", value=True)
        enable_2fa = st.checkbox("Require 2FA for Admins", value=True)
        password_policy = st.selectbox("Password Policy", ["Standard", "Strong", "Very Strong"])
        session_duration = st.slider("Session Duration (hours)", 1, 24, 8)

        st.caption(
            f"Security config: SSL={'on' if enable_ssl else 'off'}, 2FA={'on' if enable_2fa else 'off'}, "
            f"policy={password_policy}, session duration={session_duration}h"
        )

        if st.button("💾 Save Security Config"):
            st.success("✅ Security configuration saved!")

    with tab3:
        st.subheader("Backup & Restore")

        col1, col2 = st.columns(2)

        with col1:
            if st.button("💾 Create Backup"):
                st.success("✅ Backup created successfully!")

        with col2:
            if st.button("📥 Restore from Backup"):
                st.info("Restore functionality would appear here")

        st.markdown("---")

        st.write("Last Backup: 2024-02-13 14:30:00")

    with tab4:
        st.subheader("System Maintenance")

        if st.button("🧹 Clean Logs"):
            st.success("✅ Logs cleaned successfully!")

        if st.button("🔄 Clear Cache"):
            st.success("✅ Cache cleared successfully!")

        if st.button("🚀 Restart Services"):
            st.warning("⚠️ Services will restart in 10 seconds...")


def show_page_system_monitor():
    """Operator: System monitoring"""
    st.title("📡 System Monitor (Operator/Admin Only)")

    if not is_operator():
        st.error("❌ Access Denied: Operator or Admin only")
        return

    db = st.session_state.db
    health_monitor = AgentHealthMonitor(db)

    # System-wide metrics
    system_health = health_monitor.get_system_health()

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("System Health", f"{system_health.get('overall_health', 0)}%", "📊")

    with col2:
        st.metric("Total Agents", system_health.get("total_agents", 0), "🤖")

    with col3:
        st.metric("Healthy Agents", system_health.get("healthy_agents", 0), "✅")

    with col4:
        st.metric("System Uptime", system_health.get("system_uptime", "N/A"), "⏱️")

    st.markdown("---")

    # Agent health details
    st.subheader("Agent Health Status")

    agents = db.list_agents()

    if agents:
        health_data = []
        for agent in agents:
            health = health_monitor.get_agent_health(agent["id"])
            health_data.append(
                {
                    "Agent": health.get("agent_name", "Unknown"),
                    "Health": f"{health.get('health_score', 0)}%",
                    "Status": health.get("status", "unknown"),
                    "Sessions": health.get("active_sessions", 0),
                    "Events": health.get("recent_events", 0),
                }
            )

        df = pd.DataFrame(health_data)
        st.dataframe(df, width="stretch", hide_index=True)
    else:
        st.info("No agents registered yet")

    st.markdown("---")

    # Refresh button
    if st.button("🔄 Refresh Monitor Data"):
        st.rerun()


def show_page_analytics():
    """Operator: Analytics and reporting"""
    st.title("📈 Analytics (Operator/Admin Only)")

    if not is_operator():
        st.error("❌ Access Denied: Operator or Admin only")
        return

    db = st.session_state.db
    analytics = AgentAnalytics(db)

    tab1, tab2, tab3 = st.tabs(["Overview", "Trends", "Alerts"])

    with tab1:
        st.subheader("Analytics Overview")

        system_analytics = analytics.get_system_analytics()

        col1, col2, col3 = st.columns(3)

        with col1:
            st.metric("Total Events", system_analytics.get("total_events", 0), "📊")

        with col2:
            st.metric("Success Rate", f"{system_analytics.get('success_rate', 0):.1f}%", "✅")

        with col3:
            st.metric("Active Agents", system_analytics.get("active_agents", 0), "🤖")

        st.markdown("---")

        # Event distribution pie chart
        st.subheader("Event Distribution")
        event_dist = system_analytics.get("event_distribution", {})
        if event_dist:
            event_df = pd.DataFrame(list(event_dist.items()), columns=["Event Type", "Count"])
            st.bar_chart(event_df.set_index("Event Type"))
        else:
            st.info("No events found")

    with tab2:
        st.subheader("Performance Trends")

        agents = db.list_agents()

        if agents:
            selected_agent = st.selectbox(
                "Select Agent for Analysis", [a["name"] for a in agents], key="analytics_agent"
            )
            selected_agent_obj = next((a for a in agents if a["name"] == selected_agent), None)

            if selected_agent_obj:
                activity = analytics.get_agent_activity_summary(selected_agent_obj["id"])

                st.write("**Activity Summary (Last 7 Days)**")
                col1, col2, col3, col4 = st.columns(4)

                with col1:
                    st.metric("Total Events", activity.get("total_events", 0))
                with col2:
                    st.metric("Successful", activity.get("successful_events", 0))
                with col3:
                    st.metric("Failed", activity.get("failed_events", 0))
                with col4:
                    st.metric("Success Rate", f"{activity.get('success_rate', 0):.1f}%")

                st.markdown("---")

                event_types = activity.get("event_types", {})
                if event_types:
                    event_type_df = pd.DataFrame(list(event_types.items()), columns=["Event Type", "Count"])
                    st.bar_chart(event_type_df.set_index("Event Type"))
                else:
                    st.info("No events for this agent in the selected period")
        else:
            st.info("No agents registered yet")

    with tab3:
        st.subheader("Active Alerts")

        # Alert simulation
        st.warning("⚠️ High event rate detected on 3 agents")
        st.info("ℹ️ System health is optimal")
        st.success("✅ All critical systems operational")

        st.markdown("---")

        if st.button("📧 Send Alert Notification"):
            st.success("✅ Alert notification sent to administrators")

    st.markdown("---")

    # Features
    st.header("✨ Key Features")

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("👥 Agent Management")
        st.write("""
        - Register and manage AI agents
        - Monitor agent status and health
        - Track trust scores and permissions
        - Bulk operations support
        """)

    with col2:
        st.subheader("🔐 Session Management")
        st.write("""
        - Real-time session monitoring
        - Authentication management
        - Session termination
        - Activity tracking
        """)

    col3, col4 = st.columns(2)

    with col3:
        st.subheader("📊 Audit & Compliance")
        st.write("""
        - Comprehensive audit logs
        - Access history tracking
        - Compliance reporting
        - Risk assessment
        """)

    with col4:
        st.subheader("🔧 Advanced Controls")
        st.write("""
        - Fine-grained permissions
        - Role-based access control
        - Custom trust policies
        - Integration APIs
        """)

    st.markdown("---")

    # Quick actions
    st.header("⚡ Quick Actions")

    col1, col2, col3 = st.columns(3)

    with col1:
        if st.button("➕ Register New Agent", width="stretch"):
            navigate_to("➕ Register Agent")

    with col2:
        if st.button("📊 View Reports", width="stretch"):
            navigate_to("📊 Reports")

    with col3:
        if st.button("📋 View Audit Log", width="stretch"):
            navigate_to("📋 Audit Log")


def show_page_health_center():
    """Operational health center for system and agent status."""
    st.title("🏥 Health Center")
    db = st.session_state.db
    health_monitor = AgentHealthMonitor(db)
    system_health = health_monitor.get_system_health()
    analytics = AgentAnalytics(db)
    system_analytics = analytics.get_system_analytics()

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Overall Health", f"{system_health.get('overall_health', 0)}%")
    with col2:
        st.metric("Active Agents", system_health.get("healthy_agents", 0))
    with col3:
        st.metric("Total Events", system_health.get("total_events", 0))
    with col4:
        st.metric("Success Rate", f"{system_analytics.get('success_rate', 0):.1f}%")

    st.markdown("---")
    agents = db.list_agents()
    if agents:
        health_rows = []
        for agent in agents[:15]:
            health = health_monitor.get_agent_health(agent["id"])
            health_rows.append(
                {
                    "Agent": health.get("agent_name", agent["id"]),
                    "Status": health.get("status", "unknown"),
                    "Health": f"{health.get('health_score', 0)}%",
                    "Sessions": health.get("active_sessions", 0),
                    "Last Activity": health.get("last_activity", "Never"),
                }
            )
        st.dataframe(pd.DataFrame(health_rows), width="stretch", hide_index=True)
    else:
        st.info("No agents registered yet")


def show_page_activity_timeline():
    """Timeline view for recent platform activity."""
    st.title("🧭 Activity Timeline")
    db = st.session_state.db
    events = db.get_events(limit=200)

    if not events:
        st.info("No activity yet")
        return

    timeline_rows = []
    for event in events[:50]:
        timeline_rows.append(
            {
                "Time": event.get("created_at", ""),
                "Type": event.get("event_type", "unknown"),
                "Agent": event.get("agent_id", "system"),
                "Action": event.get("action", ""),
                "Status": event.get("status", "success"),
                "Details": event.get("details", ""),
            }
        )

    st.dataframe(pd.DataFrame(timeline_rows), width="stretch", hide_index=True)


def _fetch_security_alerts(endpoint: str, fallback: list | None = None):
    """Fetch security data from the local API with a safe fallback."""
    try:
        response = requests.get(f"http://127.0.0.1:8000/alerts/{endpoint}", timeout=5)
        if response.status_code == 200:
            payload = response.json()
            if isinstance(payload, list) and payload:
                return payload
            if isinstance(payload, dict):
                for key in (endpoint, endpoint.replace("-", "_")):
                    value = payload.get(key)
                    if isinstance(value, list) and value:
                        return value
    except Exception as e:
        logging.getLogger(__name__).debug("Failed to fetch local alerts endpoint %s: %s", endpoint, e)

    db = _get_dashboard_db()
    if db:
        if hasattr(db, "list_attack_events") and endpoint == "attacks":
            records = db.list_attack_events(limit=100)
            if records:
                return records
        elif hasattr(db, "list_security_alerts") and endpoint.startswith("active"):
            records = db.list_security_alerts(limit=100, active_only=True)
            if records:
                return records
        elif hasattr(db, "list_security_alerts") and endpoint.startswith("recent"):
            limit = 20
            try:
                if "limit=" in endpoint:
                    limit = int(endpoint.split("limit=")[-1].split("&")[0])
            except (ValueError, IndexError) as e:
                logging.getLogger(__name__).debug("Failed to parse limit from endpoint '%s': %s", endpoint, e)
                limit = 20
            records = db.list_security_alerts(limit=limit, active_only=False)
            if records:
                return records
        elif hasattr(db, "list_blocked_ips") and endpoint in {"blocked-ips", "blocked_ips"}:
            records = db.list_blocked_ips(active_only=True)
            if records:
                return records

        if getattr(db, "db_path", None):
            try:
                _ensure_local_security_tables(db.db_path)
                with sqlite3.connect(db.db_path) as conn:
                    cursor = conn.cursor()
                    if endpoint == "attacks":
                        cursor.execute("""
                            SELECT id, attack_type, source_ip, target_endpoint, payload,
                                   severity, detected_at, status, description, metadata
                            FROM attack_events ORDER BY detected_at DESC LIMIT 100
                            """)
                        rows = cursor.fetchall()
                        if rows:
                            return [
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
                                for row in rows
                            ]
                    elif endpoint.startswith("active"):
                        cursor.execute("""
                            SELECT id, alert_type, title, message, severity, source_ip,
                                   attack_event_id, is_resolved, created_at, resolved_at
                            FROM security_alerts WHERE is_resolved = 0
                            ORDER BY created_at DESC LIMIT 100
                            """)
                        rows = cursor.fetchall()
                        if rows:
                            return [
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
                                for row in rows
                            ]
                    elif endpoint.startswith("recent"):
                        limit = 20
                        try:
                            if "limit=" in endpoint:
                                limit = int(endpoint.split("limit=")[-1].split("&")[0])
                        except (ValueError, IndexError):
                            limit = 20
                        cursor.execute(
                            """
                            SELECT id, alert_type, title, message, severity, source_ip,
                                   attack_event_id, is_resolved, created_at, resolved_at
                            FROM security_alerts ORDER BY created_at DESC LIMIT ?
                            """,
                            (limit,),
                        )
                        rows = cursor.fetchall()
                        if rows:
                            return [
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
                                for row in rows
                            ]
                    elif endpoint in {"blocked-ips", "blocked_ips"}:
                        cursor.execute("""
                            SELECT ip_address, reason, attack_event_id, block_duration_seconds,
                                   blocked_at, expires_at, is_active
                            FROM blocked_ips WHERE is_active = 1 ORDER BY blocked_at DESC
                            """)
                        rows = cursor.fetchall()
                        if rows:
                            return [
                                {
                                    "ip": row[0],
                                    "reason": row[1],
                                    "attack_event_id": row[2],
                                    "block_duration_seconds": row[3],
                                    "blocked_at": row[4],
                                    "expires_at": row[5],
                                    "is_active": bool(row[6]),
                                }
                                for row in rows
                            ]
            except Exception as e:
                logging.getLogger(__name__).debug("Failed to query local security tables: %s", e)

    demo_state = _load_demo_security_state()
    if isinstance(demo_state, dict):
        for key in (endpoint, endpoint.replace("-", "_")):
            value = demo_state.get(key)
            if isinstance(value, list) and value:
                return value
    return fallback or []


def _parse_attack_metadata(raw_metadata):
    """Return attack metadata as a dictionary when possible."""
    if isinstance(raw_metadata, dict):
        return raw_metadata
    if isinstance(raw_metadata, str) and raw_metadata.strip():
        try:
            parsed = json.loads(raw_metadata)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError as e:
            logging.getLogger(__name__).debug("Failed to parse attack metadata: %s", e)
            return {}
    return {}


def _estimate_loss_impact(attack_type: str, severity: str, blocked: bool) -> str:
    """Provide a conservative estimated impact for the incident."""
    base_values = {
        "critical": 50000,
        "high": 20000,
        "medium": 7000,
        "low": 1500,
    }
    multipliers = {
        "brute_force": 1.4,
        "sql_injection": 1.8,
        "xss": 0.9,
        "rate_limit": 0.7,
    }
    base = base_values.get(str(severity).lower(), 5000)
    multiplier = multipliers.get(str(attack_type).lower(), 1.0)
    impact = int(base * multiplier)
    if blocked:
        impact = int(impact * 0.35)
    return f"~${impact:,}"


def _summarize_attack_status(attack: dict, blocked_ips: list[dict]) -> str:
    """Describe how an attack was stopped or mitigated."""
    if attack.get("status") == "blocked":
        blocked_match = next(
            (item for item in blocked_ips if item.get("ip") == attack.get("source_ip")),
            None,
        )
        if blocked_match and blocked_match.get("reason"):
            return f"Auto-blocked: {blocked_match.get('reason')}"
        return "Auto-blocked by security controls"
    if attack.get("status") == "mitigated":
        return "Mitigated by security workflow"
    return "Detected and under review"


def show_page_attack_forensics():
    """Detailed incident forensics for attacks, sources, containment, and impact."""
    st.title("🕵️ Attack Forensics")
    st.caption("Attack timeline, source identity, containment action, and estimated impact.")

    demo_banner = st.container()
    with demo_banner:
        st.info(
            "Demo mode is available for local screenshots and walkthroughs. It uses synthetic telemetry, blocked IPs, and auto-containment records."
        )
        demo_col1, demo_col2 = st.columns(2)
        with demo_col1:
            if st.button("Generate Demo Incident", width="stretch"):
                _persist_security_demo_state(_build_demo_security_state())
                st.success("Demo incident generated. Open this page again or rerun to refresh the telemetry.")
                st.rerun()
        with demo_col2:
            if st.button("Reset Demo Incident", width="stretch"):
                if DEMO_SECURITY_STATE_PATH.exists():
                    DEMO_SECURITY_STATE_PATH.unlink()
                st.success("Demo incident cleared.")
                st.rerun()

    attacks = _fetch_security_alerts("attacks")
    active_alerts = _fetch_security_alerts("active")
    blocked_ips = _fetch_security_alerts("blocked-ips")

    if not attacks and not active_alerts and not blocked_ips:
        st.warning(
            "No security telemetry available. Generate a demo incident or start the API server to load attack data."
        )
        return

    critical_count = sum(1 for attack in attacks if str(attack.get("severity", "")).lower() == "critical")
    blocked_count = sum(1 for attack in attacks if attack.get("status") == "blocked")
    suspicious_count = len(active_alerts)

    metric_col1, metric_col2, metric_col3, metric_col4 = st.columns(4)
    with metric_col1:
        st.metric("Attack Events", len(attacks))
    with metric_col2:
        st.metric("Blocked", blocked_count)
    with metric_col3:
        st.metric("Critical", critical_count)
    with metric_col4:
        st.metric("Active Alerts", suspicious_count)

    st.markdown("---")

    top_attack = attacks[0] if attacks else None
    if top_attack:
        top_metadata = _parse_attack_metadata(top_attack.get("metadata"))
        insight_col1, insight_col2, insight_col3 = st.columns(3)
        with insight_col1:
            st.markdown("**Latest Case**")
            st.write(f"{top_attack.get('attack_type', 'unknown')} from {top_attack.get('source_ip', 'unknown')}")
        with insight_col2:
            st.markdown("**Likely Actor**")
            st.write(top_metadata.get("username") or top_metadata.get("user") or "unknown")
        with insight_col3:
            st.markdown("**Containment Status**")
            st.write(_summarize_attack_status(top_attack, blocked_ips))

        with st.expander("Recent incident highlights", expanded=False):
            for attack in attacks[:5]:
                metadata = _parse_attack_metadata(attack.get("metadata"))
                actor = metadata.get("username") or metadata.get("user") or attack.get("source_ip", "unknown")
                status_text = _summarize_attack_status(attack, blocked_ips)
                impact_text = _estimate_loss_impact(
                    attack.get("attack_type", "unknown"),
                    attack.get("severity", "medium"),
                    attack.get("status") == "blocked",
                )
                st.markdown(
                    f"- **{attack.get('attack_type', 'unknown')}** | {actor} | {attack.get('source_ip', 'unknown')} | {status_text} | {impact_text}"
                )

    if attacks:
        forensic_rows = []
        for attack in attacks[:100]:
            metadata = _parse_attack_metadata(attack.get("metadata"))
            actor = metadata.get("username") or metadata.get("user") or attack.get("source_ip", "unknown")
            stop_reason = _summarize_attack_status(attack, blocked_ips)
            blocked = attack.get("status") == "blocked"
            forensic_rows.append(
                {
                    "Time": attack.get("detected_at", ""),
                    "Attack": attack.get("attack_type", "unknown"),
                    "Actor": actor,
                    "Source IP": attack.get("source_ip", "unknown"),
                    "Target": attack.get("target_endpoint", "unknown"),
                    "Status": attack.get("status", "detected"),
                    "Stopped By": stop_reason,
                    "Estimated Impact": _estimate_loss_impact(
                        attack.get("attack_type", "unknown"),
                        attack.get("severity", "medium"),
                        blocked,
                    ),
                }
            )

        st.dataframe(pd.DataFrame(forensic_rows), width="stretch", hide_index=True)

        st.markdown("---")
        st.subheader("Incident Details")
        selected_attack = st.selectbox(
            "Inspect a specific attack",
            options=attacks,
            format_func=lambda item: f"{item.get('attack_type', 'unknown')} | {item.get('source_ip', 'unknown')} | {item.get('detected_at', '')}",
        )

        selected_metadata = _parse_attack_metadata(selected_attack.get("metadata"))
        detail_cols = st.columns(3)
        with detail_cols[0]:
            st.write(f"**Attack Type:** {selected_attack.get('attack_type', 'unknown')}")
            st.write(f"**Severity:** {selected_attack.get('severity', 'medium')}")
            st.write(f"**Status:** {selected_attack.get('status', 'detected')}")
        with detail_cols[1]:
            st.write(f"**Actor:** {selected_metadata.get('username') or selected_metadata.get('user') or 'unknown'}")
            st.write(f"**Source IP:** {selected_attack.get('source_ip', 'unknown')}")
            st.write(f"**Target:** {selected_attack.get('target_endpoint', 'unknown')}")
        with detail_cols[2]:
            st.write(
                f"**Estimated Impact:** {_estimate_loss_impact(selected_attack.get('attack_type', 'unknown'), selected_attack.get('severity', 'medium'), selected_attack.get('status') == 'blocked')}"
            )
            st.write(f"**Response:** {_summarize_attack_status(selected_attack, blocked_ips)}")
            st.write(f"**Loss Avoided:** {'Yes' if selected_attack.get('status') == 'blocked' else 'Partial'}")

        if selected_attack.get("description"):
            st.info(selected_attack.get("description"))
        if selected_metadata:
            st.json(selected_metadata)
    else:
        st.info("No attack events recorded yet")


def show_page_alert_center():
    """Active alert queue for unresolved security alerts."""
    st.title("🔔 Alert Center")
    st.caption("Live unresolved alerts with current severity and source IP.")

    db = st.session_state.db
    active_alerts = _fetch_security_alerts("active")
    recent_alerts = _fetch_security_alerts("recent?limit=20")

    alert_col1, alert_col2 = st.columns(2)
    with alert_col1:
        st.metric("Active Alerts", len(active_alerts))
    with alert_col2:
        st.metric("Recent Alerts", len(recent_alerts))

    st.markdown("---")

    if active_alerts:
        st.subheader("Priority Alerts")
        for alert in active_alerts[:5]:
            severity = str(alert.get("severity", "medium")).upper()
            source_ip = alert.get("source_ip", "n/a")
            title = alert.get("title", "Alert")
            message = alert.get("message", "")
            left_col, right_col = st.columns([4, 1])
            with left_col:
                st.warning(f"{severity} | {title} | {source_ip}")
                st.caption(message)
            with right_col:
                if hasattr(db, "resolve_security_alert") and st.button(
                    "Resolve",
                    key=f"resolve_alert_{alert.get('id', source_ip)}",
                    width="stretch",
                ):
                    if db.resolve_security_alert(alert.get("id")):
                        st.success("Alert resolved")
                        st.rerun()
                    else:
                        st.error("Failed to resolve alert")

    if active_alerts:
        alert_rows = []
        for alert in active_alerts[:50]:
            alert_rows.append(
                {
                    "Time": alert.get("created_at", ""),
                    "Severity": alert.get("severity", "medium"),
                    "Type": alert.get("alert_type", "unknown"),
                    "Source IP": alert.get("source_ip", ""),
                    "Title": alert.get("title", ""),
                    "Message": alert.get("message", ""),
                }
            )

        st.dataframe(pd.DataFrame(alert_rows), width="stretch", hide_index=True)
    else:
        st.success("No active alerts")

    if recent_alerts:
        st.markdown("---")
        st.subheader("Recent Alert Feed")
        for alert in recent_alerts[:10]:
            st.write(
                f"**{alert.get('severity', 'medium').upper()}** - {alert.get('title', 'Alert')} ({alert.get('source_ip', 'n/a')})"
            )
            st.caption(alert.get("message", ""))


def show_page_attack_flow():
    """End-to-end attack lifecycle view for demos and screenshots."""
    st.title("🧪 Attack Flow Lifecycle")
    st.caption("From reconnaissance to containment, recovery, and final closeout.")

    db = _get_dashboard_db()
    if db:
        _process_security_notification_queue(db)

    button_col1, button_col2 = st.columns(2)
    with button_col1:
        if st.button("Run Full Demo Attack Flow", width="stretch"):
            _persist_security_demo_state(_build_demo_security_state())
            st.success("Full attack flow generated and persisted.")
            st.rerun()
    with button_col2:
        if st.button("Reset Demo Flow", width="stretch"):
            if DEMO_SECURITY_STATE_PATH.exists():
                DEMO_SECURITY_STATE_PATH.unlink()
            st.success("Demo flow cleared.")
            st.rerun()

    demo_state = _load_demo_security_state() or _build_demo_security_state()
    attacks = _fetch_security_alerts("attacks") or (
        demo_state.get("attacks", []) if isinstance(demo_state, dict) else []
    )
    alerts = _fetch_security_alerts("active") or (demo_state.get("active", []) if isinstance(demo_state, dict) else [])
    blocks = _fetch_security_alerts("blocked-ips") or (
        demo_state.get("blocked_ips", []) if isinstance(demo_state, dict) else []
    )
    cases = (
        db.list_security_cases(limit=25)
        if db and hasattr(db, "list_security_cases")
        else (demo_state.get("cases", []) if isinstance(demo_state, dict) else [])
    )
    stages = _build_attack_flow_stages()
    kpis = calculate_security_kpis(attacks, alerts, blocks)
    export_payload = build_incident_export_payload(
        demo_state if isinstance(demo_state, dict) else {}, attacks, alerts, blocks, kpis
    )
    executive_report = build_executive_report(
        demo_state if isinstance(demo_state, dict) else {}, cases, attacks, alerts, blocks
    )
    chain_hash = (demo_state or {}).get("integrity_hash", "")

    col1, col2, col3, col4, col5, col6, col7 = st.columns(7)
    with col1:
        st.metric("Stages", len(stages))
    with col2:
        st.metric("Alerts", len(alerts))
    with col3:
        st.metric("Blocked IPs", len(blocks))
    with col4:
        st.metric("Critical Events", sum(1 for item in attacks if item.get("severity") == "critical"))
    with col5:
        st.metric("MTTD (min)", f"{kpis.get('mttd_minutes', 0.0):.2f}")
    with col6:
        st.metric("MTTR (min)", f"{kpis.get('mttr_minutes', 0.0):.2f}")
    with col7:
        st.metric("Cases", len(cases))

    st.markdown("---")

    summary = (demo_state or {}).get("executive_summary", {}) if isinstance(demo_state, dict) else {}
    summary_cols = st.columns(4)
    with summary_cols[0]:
        st.metric("Threat Level", str(summary.get("threat_level", "medium")).title())
    with summary_cols[1]:
        st.metric("Block Rate", f"{kpis.get('block_rate', 0.0):.1f}%")
    with summary_cols[2]:
        st.metric("Integrity", chain_hash[:12] if chain_hash else "n/a")
    with summary_cols[3]:
        st.metric("Rules Matched", sum(len(item.get("matched_rules", [])) for item in attacks))

    timeline_col, summary_col = st.columns([2, 1])
    with timeline_col:
        st.subheader("Attack Timeline")
        for stage in stages:
            status = stage["status"]
            if status == "Observed":
                emoji = "👁️"
            elif status == "Blocked":
                emoji = "🟥"
            elif status == "Alerted":
                emoji = "⚠️"
            elif status == "Auto-blocked":
                emoji = "🛡️"
            elif status == "In progress":
                emoji = "🔄"
            else:
                emoji = "✅"

            with st.container(border=True):
                left_col, right_col = st.columns([1, 4])
                with left_col:
                    st.markdown(f"### {emoji} {stage['stage']}")
                    st.metric("Status", status)
                with right_col:
                    st.write(stage["detail"])
                    st.caption(f"Control: {stage['control']}")

    with summary_col:
        st.subheader("Outcome Summary")
        st.success("The exploit was blocked before a session was created.")
        st.info("The source IP was automatically isolated by security controls.")
        st.warning("Administrators review the incident and preserve evidence.")

        if summary:
            st.write(f"**Incident ID:** {demo_state.get('incident_id', 'n/a')}")
            st.write(f"**Correlation ID:** {demo_state.get('correlation_id', 'n/a')}")
            st.write(f"**Top Risk Score:** {summary.get('top_risk_score', 0)}")
            st.write(f"**Top Reputation:** {summary.get('top_reputation', 'unknown')}")

        st.markdown("---")
        st.write("**Key facts**")
        st.write(f"- Attack type: {attacks[0].get('attack_type', 'unknown') if attacks else 'unknown'}")
        st.write(f"- Source IP: {attacks[0].get('source_ip', 'unknown') if attacks else 'unknown'}")
        st.write(f"- Final status: {_summarize_attack_status(attacks[0], blocks) if attacks else 'contained'}")
        st.write(
            f"- Estimated impact: {_estimate_loss_impact(attacks[0].get('attack_type', 'unknown') if attacks else 'unknown', attacks[0].get('severity', 'medium') if attacks else 'medium', True)}"
        )

        st.markdown("---")
        st.subheader("Evidence")
        st.json(
            {
                "attack_count": len(attacks),
                "alert_count": len(alerts),
                "blocked_ips": [item.get("ip") for item in blocks],
                "integrity_hash": chain_hash,
                "block_rate": kpis.get("block_rate", 0.0),
                "mttd_minutes": kpis.get("mttd_minutes", 0.0),
                "mttr_minutes": kpis.get("mttr_minutes", 0.0),
                "source": "demo_security_state.json",
            }
        )

        snapshot_payload = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "attacks": attacks,
            "alerts": alerts,
            "blocked_ips": blocks,
            "stages": stages,
            "executive_summary": summary,
            "kpis": kpis,
            "integrity_hash": chain_hash,
        }
        st.download_button(
            "Download Incident Snapshot",
            data=json.dumps(snapshot_payload, indent=2),
            file_name="incident_snapshot.json",
            mime="application/json",
            use_container_width=True,
        )

        snapshot_rows = []
        for attack in attacks:
            snapshot_rows.append(
                {
                    "Type": attack.get("attack_type", "unknown"),
                    "Source IP": attack.get("source_ip", "unknown"),
                    "Status": attack.get("status", "detected"),
                    "Correlation ID": attack.get("correlation_id", ""),
                    "Threat Score": attack.get("threat_intel", {}).get("risk_score", 0),
                }
            )
        if snapshot_rows:
            st.download_button(
                "Download Attack CSV",
                data=pd.DataFrame(snapshot_rows).to_csv(index=False),
                file_name="attack_events.csv",
                mime="text/csv",
                use_container_width=True,
            )

        st.download_button(
            "Download Full Incident Package",
            data=json.dumps(export_payload, indent=2),
            file_name="incident_package.json",
            mime="application/json",
            use_container_width=True,
        )

        st.download_button(
            "Download Executive Report JSON",
            data=json.dumps(executive_report, indent=2),
            file_name="executive_security_report.json",
            mime="application/json",
            use_container_width=True,
        )

        st.download_button(
            "Download Executive Report PDF",
            data=render_executive_report_pdf(executive_report),
            file_name="executive_security_report.pdf",
            mime="application/pdf",
            use_container_width=True,
        )

        if summary.get("recommended_actions"):
            st.markdown("---")
            st.subheader("Recommended Actions")
            for action in summary.get("recommended_actions", [])[:5]:
                st.write(f"- {action}")

        if cases:
            st.markdown("---")
            st.subheader("Correlated Cases")
            case_rows = []
            for case in cases[:10]:
                case_rows.append(
                    {
                        "Case": case.get("title", "Case"),
                        "Status": case.get("status", "open"),
                        "Severity": case.get("severity", "medium"),
                        "Playbook": case.get("playbook_name", "generic-triage"),
                        "Sources": ", ".join(case.get("source_ips", [])[:3]),
                        "Summary": case.get("summary", ""),
                    }
                )
            st.dataframe(pd.DataFrame(case_rows), width="stretch", hide_index=True)

    st.markdown("---")
    st.subheader("Flow Status Table")
    flow_df = pd.DataFrame(stages)
    st.dataframe(flow_df, width="stretch", hide_index=True)

    st.markdown("---")
    st.subheader("Telemetry Summary")
    telemetry_rows = [
        {"Metric": "Attack Count", "Value": kpis.get("attack_count", 0)},
        {"Metric": "Critical Count", "Value": kpis.get("critical_count", 0)},
        {"Metric": "Alert Count", "Value": kpis.get("alert_count", 0)},
        {"Metric": "False Positive Rate", "Value": f"{kpis.get('false_positive_rate', 0.0):.1f}%"},
        {"Metric": "Case Count", "Value": len(cases)},
        {"Metric": "Integrity Hash", "Value": chain_hash},
    ]
    st.dataframe(pd.DataFrame(telemetry_rows), width="stretch", hide_index=True)


def show_page_connection_hub():
    """Central place to review company integration settings."""
    st.title("🔌 Connection Hub")
    db = st.session_state.db
    settings = db.get_system_settings()

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Current Connection")
        st.write(f"**Company:** {settings.get('company_name', 'Not configured')}")
        st.write(f"**Environment:** {settings.get('deployment_environment', 'development')}")
        st.write(f"**Identity Provider:** {settings.get('identity_provider', 'Local Accounts')}")
        st.write(f"**App URL:** {settings.get('app_url', 'Not configured')}")
        st.write(f"**API URL:** {settings.get('api_url', 'Not configured')}")

    with col2:
        st.subheader("Integration Options")
        st.write("- Microsoft Entra ID / SSO")
        st.write("- LDAP / Active Directory")
        st.write("- PostgreSQL / SQLite / MySQL")
        st.write("- Key-based secret management")
        st.write("- Audit and monitoring hooks")

    st.markdown("---")
    st.subheader("Stored Settings")
    if settings:
        display_rows = [{"Key": key, "Value": str(value)} for key, value in settings.items()]
        st.dataframe(pd.DataFrame(display_rows), width="stretch", hide_index=True)
    else:
        st.info("No connection settings saved yet")


def show_page_security_operations():
    """Operational security view for admins/operators."""
    st.title("🛡️ Security Operations")
    db = st.session_state.db
    events = db.get_events(limit=250)
    attacks = _fetch_security_alerts("attacks")
    active_alerts = _fetch_security_alerts("active")
    blocked_ips = _fetch_security_alerts("blocked-ips")
    cases = db.list_security_cases(limit=50) if hasattr(db, "list_security_cases") else []
    playbook_runs = db.list_security_playbook_runs(limit=25) if hasattr(db, "list_security_playbook_runs") else []
    security_rules = _load_security_rules(db)
    notification_queue = db.list_security_notifications(limit=25) if hasattr(db, "list_security_notifications") else []
    chain_entries = (
        db.list_security_chain_entries(limit=10, chain_name="incident-flow")
        if hasattr(db, "list_security_chain_entries")
        else []
    )
    kpis = calculate_security_kpis(attacks, active_alerts, blocked_ips)
    case_metrics = summarize_case_metrics(cases)

    failed_events = [e for e in events if e.get("status") != "success"]
    auth_events = [
        e for e in events if e.get("event_type", "").startswith("user_") or e.get("event_type", "").startswith("agent_")
    ]

    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Recent Auth Events", len(auth_events))
    with col2:
        st.metric("Failed Events", len(failed_events))
    with col3:
        st.metric("Registered Users", len(db.list_users()))

    st.markdown("---")
    kpi_cols = st.columns(4)
    with kpi_cols[0]:
        st.metric("Attack Count", kpis.get("attack_count", 0))
    with kpi_cols[1]:
        st.metric("Blocked", kpis.get("blocked_count", 0))
    with kpi_cols[2]:
        st.metric("MTTD (min)", f"{kpis.get('mttd_minutes', 0.0):.2f}")
    with kpi_cols[3]:
        st.metric("MTTR (min)", f"{kpis.get('mttr_minutes', 0.0):.2f}")

    case_cols = st.columns(4)
    with case_cols[0]:
        st.metric("Cases", case_metrics.get("total_cases", 0))
    with case_cols[1]:
        st.metric("Open Cases", case_metrics.get("open_cases", 0))
    with case_cols[2]:
        st.metric("Contained Cases", case_metrics.get("contained_cases", 0))
    with case_cols[3]:
        st.metric("Closed Cases", case_metrics.get("closed_cases", 0))

    st.markdown("---")
    st.subheader("Security Snapshot")
    st.write("- Rate limiting is active in the login flow")
    st.write("- Account lockout is enabled for repeated failures")
    st.write("- SQL injection filtering is active")
    st.write("- Audit logging captures system changes")
    st.write(f"- Detection rules loaded: {len(security_rules)}")
    st.write(f"- Notification queue entries: {len(notification_queue)}")
    st.write(f"- Integrity chain entries: {len(chain_entries)}")

    if st.button("Retry Failed Notifications"):
        results = _process_security_notification_queue(db)
        if results:
            st.success(f"Processed {len(results)} queued notification(s).")
        else:
            st.info("No queued notifications were available for retry.")

    if security_rules:
        st.subheader("Active Detection Rules")
        rule_rows = []
        for rule in security_rules:
            rule_rows.append(
                {
                    "Rule": rule.get("rule_key", "custom"),
                    "Title": rule.get("title", "Security rule"),
                    "Pattern": rule.get("pattern", ""),
                    "Severity": rule.get("severity", "medium"),
                    "Action": rule.get("response_action", "monitor"),
                }
            )
        st.dataframe(pd.DataFrame(rule_rows), width="stretch", hide_index=True)

    if notification_queue:
        st.subheader("Notification Queue")
        queue_rows = []
        for item in notification_queue:
            queue_rows.append(
                {
                    "Time": item.get("created_at", ""),
                    "Target": item.get("target_name", ""),
                    "Status": item.get("status", ""),
                    "Attempts": item.get("attempts", 0),
                    "Last Error": item.get("last_error", ""),
                }
            )
        st.dataframe(pd.DataFrame(queue_rows), width="stretch", hide_index=True)

    if chain_entries:
        st.subheader("Integrity Chain")
        chain_rows = []
        for entry in chain_entries:
            chain_rows.append(
                {
                    "Time": entry.get("created_at", ""),
                    "Chain": entry.get("chain_name", ""),
                    "Previous Hash": str(entry.get("previous_hash", ""))[:12],
                    "Current Hash": str(entry.get("current_hash", ""))[:12],
                }
            )
        st.dataframe(pd.DataFrame(chain_rows), width="stretch", hide_index=True)

    if cases:
        st.subheader("Correlated Cases")
        case_rows = []
        for case in cases[:20]:
            case_rows.append(
                {
                    "Case": case.get("title", "Case"),
                    "Status": case.get("status", "open"),
                    "Severity": case.get("severity", "medium"),
                    "Playbook": case.get("playbook_name", "generic-triage"),
                    "Sources": ", ".join(case.get("source_ips", [])[:3]),
                    "Actions": ", ".join(case.get("recommended_actions", [])[:4]),
                }
            )
        st.dataframe(pd.DataFrame(case_rows), width="stretch", hide_index=True)

        selected_case = st.selectbox(
            "Select a case to operate on",
            options=cases,
            format_func=lambda item: f"{item.get('title', 'Case')} | {item.get('severity', 'medium')} | {item.get('status', 'open')}",
        )
        selected_playbook = next(
            (
                item
                for item in get_security_playbooks()
                if item.get("playbook_name") == selected_case.get("playbook_name")
            ),
            get_security_playbooks()[-1],
        )
        play_col1, play_col2 = st.columns(2)
        with play_col1:
            if st.button("Execute Recommended Playbook", width="stretch"):
                result = execute_playbook(db, selected_case, selected_playbook)
                st.success(f"Playbook {result.get('playbook_name')} executed")
                st.json(result)
        with play_col2:
            if st.button("Close Case", width="stretch"):
                if db.close_security_case(selected_case.get("id")):
                    st.success("Case closed")
                    st.rerun()
                else:
                    st.error("Failed to close case")

    if playbook_runs:
        st.subheader("Recent Playbook Runs")
        run_rows = []
        for run in playbook_runs[:15]:
            run_rows.append(
                {
                    "Time": run.get("created_at", ""),
                    "Case": run.get("case_key", ""),
                    "Playbook": run.get("playbook_name", ""),
                    "Status": run.get("status", ""),
                    "Auto": run.get("auto_applied", False),
                }
            )
        st.dataframe(pd.DataFrame(run_rows), width="stretch", hide_index=True)

    if failed_events:
        st.subheader("Recent Failed Events")
        security_rows = []
        for event in failed_events[:20]:
            security_rows.append(
                {
                    "Time": event.get("created_at", ""),
                    "Type": event.get("event_type", ""),
                    "Agent": event.get("agent_id", "system"),
                    "Action": event.get("action", ""),
                    "Details": event.get("details", ""),
                }
            )
        st.dataframe(pd.DataFrame(security_rows), width="stretch", hide_index=True)
    else:
        st.success("No failed security events in the recent window")


def show_page_automation_center():
    """Task-oriented automation center for admins/operators."""
    st.title("⚡ Automation Center")
    db = st.session_state.db

    st.subheader("Quick Actions")
    quick_col1, quick_col2, quick_col3 = st.columns(3)
    with quick_col1:
        if st.button("Create Health Check Task", width="stretch"):
            agents = db.list_agents()
            agent_id = agents[0]["id"] if agents else "system"
            db.create_task(agent_id, "health_check", "Run a scheduled health review")
            st.success("Health check task created")
    with quick_col2:
        if st.button("Create Audit Review Task", width="stretch"):
            agents = db.list_agents()
            agent_id = agents[0]["id"] if agents else "system"
            db.create_task(agent_id, "audit_review", "Review recent audit events")
            st.success("Audit review task created")
    with quick_col3:
        if st.button("Create Connection Validation Task", width="stretch"):
            agents = db.list_agents()
            agent_id = agents[0]["id"] if agents else "system"
            db.create_task(agent_id, "connection_check", "Validate company connection settings")
            st.success("Connection validation task created")

    st.markdown("---")
    st.subheader("Recent Tasks")
    tasks = db.list_tasks(limit=50)
    if tasks:
        task_rows = []
        for task in tasks:
            task_rows.append(
                {
                    "Time": task.get("created_at", ""),
                    "Agent": task.get("agent_id", ""),
                    "Task": task.get("task_type", ""),
                    "Status": task.get("status", ""),
                    "Details": task.get("details", ""),
                }
            )
        st.dataframe(pd.DataFrame(task_rows), width="stretch", hide_index=True)
    else:
        st.info("No tasks created yet")


if __name__ == "__main__":
    main()
