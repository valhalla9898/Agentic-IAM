"""Security incident correlation, playbooks, and executive reporting helpers."""

from __future__ import annotations

import json
from datetime import datetime
from textwrap import wrap
from typing import Any, Dict, Iterable, List, Optional

from security_telemetry import build_event_fingerprint, calculate_security_kpis, generate_correlation_id


DEFAULT_SECURITY_PLAYBOOKS: List[Dict[str, Any]] = [
    {
        "playbook_name": "sqli-containment",
        "title": "SQL injection containment",
        "triggers": ["sql_injection"],
        "auto_execute": True,
        "steps": [
            "Block source IP",
            "Resolve linked alerts",
            "Preserve evidence",
            "Notify SOC channel",
        ],
    },
    {
        "playbook_name": "bruteforce-containment",
        "title": "Credential stuffing containment",
        "triggers": ["brute_force", "credential_stuffing"],
        "auto_execute": True,
        "steps": [
            "Rate limit source",
            "Step-up MFA",
            "Resolve linked alerts",
            "Notify SIEM",
        ],
    },
    {
        "playbook_name": "generic-triage",
        "title": "Generic security triage",
        "triggers": ["*"],
        "auto_execute": False,
        "steps": [
            "Review evidence",
            "Assign owner",
            "Validate containment",
        ],
    },
]


def _normalize_text(value: Any) -> str:
    return str(value or "").strip().lower()


def _case_severity(values: Iterable[str]) -> str:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    reverse = {v: k for k, v in order.items()}
    best = max((order.get(_normalize_text(item), 2) for item in values), default=2)
    return reverse.get(best, "medium")


def correlate_security_cases(
    attacks: Iterable[Dict[str, Any]],
    alerts: Iterable[Dict[str, Any]],
    blocked_ips: Iterable[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Group related telemetry into cases keyed by source IP and attack type."""
    attack_list = list(attacks or [])
    alert_list = list(alerts or [])
    blocked_list = list(blocked_ips or [])

    grouped: Dict[str, Dict[str, Any]] = {}
    for attack in attack_list:
        source_ip = str(attack.get("source_ip", "unknown"))
        attack_type = str(attack.get("attack_type", "unknown"))
        case_key = f"{source_ip}:{attack_type}"
        case = grouped.setdefault(
            case_key,
            {
                "case_id": generate_correlation_id("case"),
                "case_key": case_key,
                "title": f"{attack_type.replace('_', ' ').title()} from {source_ip}",
                "source_ips": set(),
                "attack_types": set(),
                "attack_ids": [],
                "alert_ids": [],
                "blocked_ips": set(),
                "correlation_ids": [],
                "severity_values": [],
                "status": "open",
                "summary": "",
                "recommended_actions": set(),
                "first_seen": attack.get("detected_at"),
                "last_seen": attack.get("detected_at"),
                "playbook_name": "generic-triage",
                "integrity_hash": "",
            },
        )

        case["source_ips"].add(source_ip)
        case["attack_types"].add(attack_type)
        case["severity_values"].append(str(attack.get("severity", "medium")))
        if attack.get("id") is not None:
            case["attack_ids"].append(attack.get("id"))
        if attack.get("correlation_id"):
            case["correlation_ids"].append(attack.get("correlation_id"))
        if attack.get("recommended_actions"):
            case["recommended_actions"].update(attack.get("recommended_actions", []))
        if attack.get("matched_rules"):
            for rule in attack.get("matched_rules", []):
                action = rule.get("response_action")
                if action:
                    case["recommended_actions"].add(action)
        last_seen = attack.get("detected_at")
        if last_seen and (not case["last_seen"] or str(last_seen) > str(case["last_seen"])):
            case["last_seen"] = last_seen

    for alert in alert_list:
        source_ip = str(alert.get("source_ip", "unknown"))
        matched_case = None
        for case in grouped.values():
            if source_ip in case["source_ips"]:
                matched_case = case
                break
        if matched_case:
            if alert.get("id") is not None:
                matched_case["alert_ids"].append(alert.get("id"))
            matched_case["severity_values"].append(str(alert.get("severity", "medium")))
            if alert.get("created_at") and (not matched_case["last_seen"] or str(alert.get("created_at")) > str(matched_case["last_seen"])):
                matched_case["last_seen"] = alert.get("created_at")

    for block in blocked_list:
        source_ip = str(block.get("ip", block.get("ip_address", "unknown")))
        for case in grouped.values():
            if source_ip in case["source_ips"]:
                case["blocked_ips"].add(source_ip)

    cases: List[Dict[str, Any]] = []
    for case in grouped.values():
        attack_count = len(case["attack_ids"])
        alert_count = len(case["alert_ids"])
        blocked_count = len(case["blocked_ips"])
        severity = _case_severity(case["severity_values"])
        status = "closed" if blocked_count and alert_count else "contained" if blocked_count else "open"
        attack_types = sorted(case["attack_types"])
        recommended_actions = sorted(case["recommended_actions"])
        if any(item == "sql_injection" for item in attack_types):
            playbook_name = "sqli-containment"
        elif any(item in {"brute_force", "credential_stuffing"} for item in attack_types):
            playbook_name = "bruteforce-containment"
        else:
            playbook_name = "generic-triage"

        summary = (
            f"{attack_count} attack event(s), {alert_count} alert(s), {blocked_count} blocked source(s)."
        )
        payload = {
            "case_key": case["case_key"],
            "source_ips": sorted(case["source_ips"]),
            "attack_types": attack_types,
            "status": status,
            "severity": severity,
            "attack_count": attack_count,
            "alert_count": alert_count,
            "blocked_count": blocked_count,
            "summary": summary,
            "recommended_actions": recommended_actions,
            "playbook_name": playbook_name,
        }

        cases.append(
            {
                "case_id": case["case_id"],
                "case_key": case["case_key"],
                "title": case["title"],
                "status": status,
                "severity": severity,
                "summary": summary,
                "source_ips": sorted(case["source_ips"]),
                "attack_types": attack_types,
                "attack_ids": case["attack_ids"],
                "alert_ids": case["alert_ids"],
                "blocked_ips": sorted(case["blocked_ips"]),
                "correlation_ids": case["correlation_ids"],
                "attack_count": attack_count,
                "alert_count": alert_count,
                "blocked_count": blocked_count,
                "first_seen": case["first_seen"],
                "last_seen": case["last_seen"],
                "playbook_name": playbook_name,
                "recommended_actions": recommended_actions,
                "integrity_hash": build_event_fingerprint(payload),
            }
        )

    cases.sort(key=lambda item: str(item.get("last_seen", "")), reverse=True)
    return cases


def get_security_playbooks() -> List[Dict[str, Any]]:
    return list(DEFAULT_SECURITY_PLAYBOOKS)


def choose_playbook(case: Dict[str, Any]) -> Dict[str, Any]:
    attack_types = {str(item).lower() for item in case.get("attack_types", [])}
    for playbook in DEFAULT_SECURITY_PLAYBOOKS:
        triggers = {str(item).lower() for item in playbook.get("triggers", [])}
        if "*" in triggers:
            fallback = playbook
        elif attack_types.intersection(triggers):
            return playbook
    return fallback if "fallback" in locals() else DEFAULT_SECURITY_PLAYBOOKS[-1]


def execute_playbook(db: Any, case: Dict[str, Any], playbook: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Apply a response playbook and record the run to the database."""
    playbook = playbook or choose_playbook(case)
    actions = []
    source_ips = case.get("source_ips", []) or []
    alert_ids = case.get("alert_ids", []) or []

    for step in playbook.get("steps", []):
        result = {"step": step, "status": "skipped", "details": "No matching executor"}
        if step == "Block source IP" and hasattr(db, "block_ip"):
            for source_ip in source_ips:
                if db.block_ip(source_ip, f"Playbook {playbook.get('playbook_name')}", attack_event_id=case.get("attack_ids", [None])[0]):
                    result = {"step": step, "status": "success", "details": f"Blocked {source_ip}"}
        elif step == "Resolve linked alerts" and hasattr(db, "resolve_security_alert"):
            resolved = 0
            for alert_id in alert_ids:
                if db.resolve_security_alert(alert_id):
                    resolved += 1
            result = {"step": step, "status": "success", "details": f"Resolved {resolved} alert(s)"}
        elif step in {"Rate limit source", "Step-up MFA", "Preserve evidence", "Notify SOC channel", "Notify SIEM", "Review evidence", "Assign owner", "Validate containment"}:
            result = {"step": step, "status": "recorded", "details": "Recorded as response action"}
        actions.append(result)

    if hasattr(db, "record_security_playbook_run"):
        db.record_security_playbook_run(
            case_id=case.get("case_id"),
            playbook_name=playbook.get("playbook_name", "unknown"),
            status="executed",
            details=json.dumps(actions),
            auto_applied=bool(playbook.get("auto_execute", False)),
            case_key=case.get("case_key"),
        )

    if hasattr(db, "log_event"):
        db.log_event(
            "security_playbook_executed",
            agent_id="system",
            action=playbook.get("playbook_name", "security_playbook"),
            details=json.dumps({"case_id": case.get("case_id"), "actions": actions}),
        )

    return {
        "case_id": case.get("case_id"),
        "case_key": case.get("case_key"),
        "playbook_name": playbook.get("playbook_name", "unknown"),
        "title": playbook.get("title", "Security playbook"),
        "auto_execute": bool(playbook.get("auto_execute", False)),
        "actions": actions,
        "executed_at": datetime.utcnow().isoformat(),
    }


def summarize_case_metrics(cases: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    case_list = list(cases or [])
    total = len(case_list)
    open_cases = sum(1 for case in case_list if str(case.get("status", "")).lower() == "open")
    contained_cases = sum(1 for case in case_list if str(case.get("status", "")).lower() == "contained")
    closed_cases = sum(1 for case in case_list if str(case.get("status", "")).lower() == "closed")
    critical_cases = sum(1 for case in case_list if str(case.get("severity", "")).lower() == "critical")
    blocked_total = sum(int(case.get("blocked_count", 0) or 0) for case in case_list)
    return {
        "total_cases": total,
        "open_cases": open_cases,
        "contained_cases": contained_cases,
        "closed_cases": closed_cases,
        "critical_cases": critical_cases,
        "blocked_total": blocked_total,
    }


def build_executive_report(
    state: Dict[str, Any],
    cases: Iterable[Dict[str, Any]],
    attacks: Iterable[Dict[str, Any]],
    alerts: Iterable[Dict[str, Any]],
    blocked_ips: Iterable[Dict[str, Any]],
) -> Dict[str, Any]:
    """Build a compact executive-ready incident report."""
    case_list = list(cases or [])
    kpis = calculate_security_kpis(attacks, alerts, blocked_ips)
    case_metrics = summarize_case_metrics(case_list)
    top_cases = sorted(case_list, key=lambda item: (item.get("severity", "medium"), item.get("attack_count", 0)), reverse=True)[:5]
    report = {
        "report_type": "executive_security_summary",
        "generated_at": datetime.utcnow().isoformat(),
        "incident_id": state.get("incident_id"),
        "correlation_id": state.get("correlation_id"),
        "summary": {
            "threat_level": state.get("executive_summary", {}).get("threat_level", "medium"),
            "attack_count": len(list(attacks or [])),
            "alert_count": len(list(alerts or [])),
            "blocked_count": len(list(blocked_ips or [])),
            "case_count": case_metrics.get("total_cases", 0),
            "block_rate": kpis.get("block_rate", 0.0),
            "mttd_minutes": kpis.get("mttd_minutes", 0.0),
            "mttr_minutes": kpis.get("mttr_minutes", 0.0),
        },
        "case_metrics": case_metrics,
        "kpis": kpis,
        "top_cases": top_cases,
        "recommended_actions": state.get("executive_summary", {}).get("recommended_actions", []),
        "integrity_hash": state.get("integrity_hash"),
    }
    report["export_hash"] = build_event_fingerprint(report)
    return report


def _escape_pdf_text(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _wrap_report_line(label: str, value: Any, width: int = 90) -> List[str]:
    text = f"{label}: {value}"
    return wrap(text, width=width) or [text]


def _build_pdf_content_lines(report: Dict[str, Any]) -> List[str]:
    lines = [
        "Agentic-IAM Executive Security Report",
        f"Generated At: {report.get('generated_at', '')}",
        f"Incident ID: {report.get('incident_id', 'n/a')}",
        f"Correlation ID: {report.get('correlation_id', 'n/a')}",
        f"Integrity Hash: {report.get('integrity_hash', 'n/a')}",
        "",
        "Summary",
    ]
    for key, value in report.get("summary", {}).items():
        lines.extend(_wrap_report_line(key.replace("_", " ").title(), value))
    lines.extend(["", "Case Metrics"])
    for key, value in report.get("case_metrics", {}).items():
        lines.extend(_wrap_report_line(key.replace("_", " ").title(), value))
    lines.extend(["", "KPI Metrics"])
    for key, value in report.get("kpis", {}).items():
        lines.extend(_wrap_report_line(key.replace("_", " ").title(), value))
    lines.extend(["", "Top Cases"])
    for case in report.get("top_cases", []):
        lines.extend(_wrap_report_line(case.get("title", "Case"), case.get("summary", "")))
        lines.extend(_wrap_report_line("Severity", case.get("severity", "medium")))
        lines.extend(_wrap_report_line("Status", case.get("status", "open")))
        lines.append("")
    if report.get("recommended_actions"):
        lines.append("Recommended Actions")
        for action in report.get("recommended_actions", []):
            lines.extend(_wrap_report_line("-", action))
    return lines


def render_executive_report_pdf(report: Dict[str, Any]) -> bytes:
    """Render a small but valid PDF document for executive report downloads."""
    lines = _build_pdf_content_lines(report)
    per_page = 40
    pages: List[List[str]] = [lines[index:index + per_page] for index in range(0, len(lines), per_page)] or [[]]

    font_obj = 3 + (len(pages) * 2)
    objects: Dict[int, bytes] = {
        1: b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n",
        2: f"2 0 obj << /Type /Pages /Kids [{' '.join(f'{3 + index * 2} 0 R' for index in range(len(pages)))}] /Count {len(pages)} >> endobj\n".encode("utf-8"),
        font_obj: f"{font_obj} 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n".encode("utf-8"),
    }

    next_page_obj = 3
    for page_lines in pages:
        page_obj = next_page_obj
        content_obj = next_page_obj + 1
        next_page_obj += 2

        content_commands = ["BT", "/F1 12 Tf", "50 760 Td"]
        first_line = True
        for line in page_lines:
            escaped = _escape_pdf_text(str(line))
            if first_line:
                content_commands.append(f"({escaped}) Tj")
                first_line = False
            else:
                content_commands.append("T*")
                content_commands.append(f"({escaped}) Tj")
        if first_line:
            content_commands.append("( ) Tj")
        content_commands.append("ET")
        content_stream = "\n".join(content_commands).encode("utf-8")
        objects[page_obj] = (
            f"{page_obj} 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Contents {content_obj} 0 R /Resources << /Font << /F1 {font_obj} 0 R >> >> >> endobj\n"
        ).encode("utf-8")
        objects[content_obj] = (
            f"{content_obj} 0 obj << /Length {len(content_stream)} >> stream\n".encode("utf-8")
            + content_stream
            + b"\nendstream\nendobj\n"
        )

    pdf = bytearray(b"%PDF-1.4\n")
    xref_offsets = {0: 0}
    for obj_number in sorted(objects):
        xref_offsets[obj_number] = len(pdf)
        pdf.extend(objects[obj_number])

    xref_start = len(pdf)
    pdf.extend(f"xref\n0 {font_obj + 1}\n".encode("utf-8"))
    pdf.extend(b"0000000000 65535 f \n")
    for obj_number in range(1, font_obj + 1):
        offset = xref_offsets.get(obj_number, 0)
        pdf.extend(f"{offset:010d} 00000 n \n".encode("utf-8"))
    pdf.extend(
        (
            "trailer << /Size {size} /Root 1 0 R >>\n"
            "startxref\n"
            "{start}\n"
            "%%EOF\n"
        ).format(size=font_obj + 1, start=xref_start).encode("utf-8")
    )
    return bytes(pdf)
