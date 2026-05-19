import json

from database import Database
from security_telemetry import (
    calculate_security_kpis,
    enrich_security_state,
)


def test_enrich_security_state_adds_trace_data():
    state = {
        "generated_at": "2026-05-19 19:00:00 UTC",
        "attacks": [
            {
                "attack_type": "sql_injection",
                "severity": "critical",
                "status": "blocked",
                "detected_at": "2026-05-19 19:00:00 UTC",
                "source_ip": "203.0.113.77",
                "target_endpoint": "/api/v1/auth/login",
                "metadata": {"vector": "login_form", "username": "demo_operator"},
            }
        ],
        "active": [],
        "blocked_ips": [],
    }

    enriched = enrich_security_state(state)

    assert enriched["incident_id"]
    assert enriched["correlation_id"]
    assert enriched["integrity_hash"]
    assert enriched["attacks"][0]["correlation_id"].startswith(enriched["incident_id"])
    assert enriched["attacks"][0]["matched_rules"]
    assert enriched["attacks"][0]["threat_intel"]["risk_score"] >= 0
    assert "recommended_actions" in enriched["executive_summary"]


def test_calculate_security_kpis_reports_block_rate():
    attacks = [
        {
            "attack_type": "sql_injection",
            "severity": "critical",
            "status": "blocked",
            "detected_at": "2026-05-19 19:00:00 UTC",
        },
        {
            "attack_type": "brute_force",
            "severity": "high",
            "status": "mitigated",
            "detected_at": "2026-05-19 19:01:00 UTC",
        },
    ]
    alerts = [{"created_at": "2026-05-19 19:00:30 UTC", "is_resolved": False}]
    blocked_ips = [{"blocked_at": "2026-05-19 19:00:10 UTC"}]

    kpis = calculate_security_kpis(attacks, alerts, blocked_ips)

    assert kpis["attack_count"] == 2
    assert kpis["blocked_count"] == 1
    assert kpis["block_rate"] == 50.0
    assert kpis["alert_count"] == 1


def test_database_security_queue_and_chain_persistence(tmp_path):
    db = Database(db_path=str(tmp_path / "security.db"))

    notification_id = db.enqueue_security_notification(
        target_name="webhook",
        target_url="https://example.invalid/webhook",
        payload={"event": "incident"},
    )
    assert notification_id is not None

    queue_items = db.list_security_notifications()
    assert queue_items
    assert queue_items[0]["target_name"] == "webhook"

    assert db.update_security_notification(
        notification_id,
        status="delivered",
        attempts=1,
        last_error=None,
    ) is True

    chain_id = db.record_security_chain_entry(
        chain_name="incident-flow",
        current_hash="abc123",
        payload={"incident_id": "incident-test"},
    )
    assert chain_id is not None

    chain_entries = db.list_security_chain_entries(chain_name="incident-flow")
    assert chain_entries
    assert chain_entries[0]["current_hash"] == "abc123"

    assert db.record_incident_export(
        export_type="security_demo",
        export_hash="hash-123",
        summary="1 attack",
        file_name="incident.json",
    ) is True
