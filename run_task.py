import sys

sys.path.insert(0, r"C:\Users\Lenovo\Desktop\Agentic-IAM-main")
from database import Database
from security_incident_management import (
    build_executive_report,
    correlate_security_cases,
    execute_playbook,
    render_executive_report_pdf,
)

db = Database()
print("DB path:", db.db_path)
attack_id = db.record_attack_event(
    attack_type="sql_injection",
    source_ip="203.0.113.5",
    target_endpoint="/login",
    payload="id=1 OR 1=1",
    severity="high",
    status="detected",
    description="Attempted SQL injection",
    metadata={"matched_rules": [{"response_action": "Block source IP"}]},
)
print("Inserted attack_id:", attack_id)
alert_id = db.record_security_alert(
    alert_type="sqli_alert",
    title="SQLi pattern matched",
    message="Potential SQL injection detected in /login",
    severity="high",
    source_ip="203.0.113.5",
    attack_event_id=attack_id,
)
print("Inserted alert_id:", alert_id)
attacks = db.list_attack_events()
alerts = db.list_security_alerts()
blocked = db.list_blocked_ips(active_only=False)
print("attacks count", len(attacks), "alerts count", len(alerts), "blocked count", len(blocked))

cases = correlate_security_cases(attacks, alerts, blocked)
if not cases:
    print("No cases after correlation")
    sys.exit(0)
case = cases[0]
print("Correlated case key:", case.get("case_key"))
upsert_id = db.upsert_security_case(
    case_key=case.get("case_key"),
    title=case.get("title"),
    severity=case.get("severity"),
    status=case.get("status"),
    summary=case.get("summary"),
    correlation_id=None,
    attack_types=case.get("attack_types"),
    source_ips=case.get("source_ips"),
    attack_ids=case.get("attack_ids"),
    alert_ids=case.get("alert_ids"),
    blocked_ips=case.get("blocked_ips"),
    recommended_actions=case.get("recommended_actions"),
    playbook_name=case.get("playbook_name"),
    first_seen=case.get("first_seen"),
    last_seen=case.get("last_seen"),
)
print("Upserted case id:", upsert_id)
case["case_id"] = upsert_id

res = execute_playbook(db, case)
print("Execute playbook result keys:", list(res.keys()))

report_state = {
    "incident_id": "demo_incident_001",
    "correlation_id": case.get("case_key"),
    "executive_summary": {
        "threat_level": "high",
        "recommended_actions": case.get("recommended_actions", []),
    },
    "integrity_hash": case.get("integrity_hash"),
}
report = build_executive_report(report_state, [case], attacks, alerts, blocked)
print("Report generated, export_hash:", report.get("export_hash"))
pdf_bytes = render_executive_report_pdf(report)
out_path = r"C:\Users\Lenovo\Desktop\Agentic-IAM-main\executive_report_generated.pdf"
with open(out_path, "wb") as f:
    f.write(pdf_bytes)
print("Saved PDF to", out_path)
