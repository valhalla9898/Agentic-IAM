from database import Database
from security_incident_management import (
    build_executive_report,
    correlate_security_cases,
    execute_playbook,
    render_executive_report_pdf,
    summarize_case_metrics,
)


def test_correlate_security_cases_groups_related_events():
    attacks = [
        {
            "id": 1,
            "attack_type": "sql_injection",
            "severity": "critical",
            "status": "blocked",
            "detected_at": "2026-05-19 19:00:00 UTC",
            "source_ip": "203.0.113.77",
            "correlation_id": "incident-1-attack-1",
            "recommended_actions": ["block_ip"],
        }
    ]
    alerts = [
        {
            "id": 11,
            "source_ip": "203.0.113.77",
            "severity": "critical",
            "created_at": "2026-05-19 19:00:05 UTC",
        }
    ]
    blocked_ips = [{"ip": "203.0.113.77", "blocked_at": "2026-05-19 19:00:10 UTC"}]

    cases = correlate_security_cases(attacks, alerts, blocked_ips)

    assert len(cases) == 1
    case = cases[0]
    assert case["case_key"] == "203.0.113.77:sql_injection"
    assert case["status"] in {"contained", "closed"}
    assert case["attack_count"] == 1
    assert case["alert_count"] == 1
    assert case["blocked_count"] == 1


def test_playbook_execution_records_queue_and_blocks(tmp_path):
    db = Database(db_path=str(tmp_path / "incident.db"))
    attack_id = db.record_attack_event(
        attack_type="sql_injection",
        source_ip="203.0.113.77",
        target_endpoint="/api/v1/auth/login",
        severity="critical",
        status="blocked",
        description="SQL injection demo",
        metadata={"vector": "login_form"},
    )
    alert_id = db.record_security_alert(
        alert_type="web_attack",
        title="SQLi blocked",
        message="Blocked payload",
        severity="critical",
        source_ip="203.0.113.77",
        attack_event_id=attack_id,
        is_resolved=False,
    )

    case = {
        "case_id": 1,
        "case_key": "203.0.113.77:sql_injection",
        "title": "SQL Injection from 203.0.113.77",
        "status": "open",
        "severity": "critical",
        "summary": "1 attack event(s), 1 alert(s), 1 blocked source(s).",
        "source_ips": ["203.0.113.77"],
        "attack_types": ["sql_injection"],
        "attack_ids": [attack_id],
        "alert_ids": [alert_id],
        "blocked_ips": ["203.0.113.77"],
        "playbook_name": "sqli-containment",
        "recommended_actions": ["block_ip"],
    }

    playbook = {
        "playbook_name": "sqli-containment",
        "title": "SQL injection containment",
        "auto_execute": True,
        "steps": ["Block source IP", "Resolve linked alerts"],
    }

    result = execute_playbook(db, case, playbook)

    assert result["playbook_name"] == "sqli-containment"
    assert any(action["status"] == "success" for action in result["actions"])
    assert db.list_security_playbook_runs(limit=10)
    assert db.list_blocked_ips(active_only=True)


def test_executive_report_and_pdf_bytes():
    state = {
        "incident_id": "incident-test",
        "correlation_id": "corr-test",
        "integrity_hash": "hash-123",
        "executive_summary": {"threat_level": "critical", "recommended_actions": ["block_ip"]},
    }
    cases = [
        {
            "case_id": 1,
            "case_key": "203.0.113.77:sql_injection",
            "title": "SQL Injection from 203.0.113.77",
            "status": "closed",
            "severity": "critical",
            "summary": "1 attack event(s), 1 alert(s), 1 blocked source(s).",
            "source_ips": ["203.0.113.77"],
            "attack_types": ["sql_injection"],
            "attack_ids": [1],
            "alert_ids": [11],
            "blocked_ips": ["203.0.113.77"],
            "playbook_name": "sqli-containment",
            "recommended_actions": ["block_ip"],
        }
    ]
    attacks = [
        {
            "attack_type": "sql_injection",
            "severity": "critical",
            "status": "blocked",
            "detected_at": "2026-05-19 19:00:00 UTC",
        }
    ]
    alerts = [{"created_at": "2026-05-19 19:00:05 UTC", "is_resolved": False}]
    blocked_ips = [{"blocked_at": "2026-05-19 19:00:10 UTC"}]

    report = build_executive_report(state, cases, attacks, alerts, blocked_ips)
    pdf_bytes = render_executive_report_pdf(report)

    assert report["report_type"] == "executive_security_summary"
    assert report["case_metrics"]["total_cases"] == 1
    assert pdf_bytes.startswith(b"%PDF-1.4")
    assert b"Executive Security Report" in pdf_bytes


def test_case_metrics_summary():
    cases = [
        {"status": "open", "severity": "critical", "blocked_count": 1},
        {"status": "contained", "severity": "high", "blocked_count": 1},
        {"status": "closed", "severity": "medium", "blocked_count": 0},
    ]
    metrics = summarize_case_metrics(cases)

    assert metrics["total_cases"] == 3
    assert metrics["open_cases"] == 1
    assert metrics["contained_cases"] == 1
    assert metrics["closed_cases"] == 1
