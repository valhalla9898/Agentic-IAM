"""Security telemetry helpers for the Agentic-IAM dashboard.

These helpers keep the demo incident flow deterministic enough for UI and tests
while still producing realistic incident enrichment, fingerprints, and KPI data.
"""

from __future__ import annotations

import copy
import hashlib
import json
import uuid
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

DEFAULT_SECURITY_RULES: List[Dict[str, Any]] = [
    {
        "rule_key": "sql-injection-block",
        "title": "Block SQL injection payloads",
        "pattern": "sql_injection|union select|or 1=1|login_form",
        "match_on": ["attack_type", "payload", "metadata.vector"],
        "severity": "critical",
        "response_action": "block_ip",
        "threshold": 1,
    },
    {
        "rule_key": "credential-stuffing-rate-limit",
        "title": "Rate limit credential stuffing",
        "pattern": "brute_force|credential_stuffing|attempts>=10",
        "match_on": ["attack_type", "metadata.vector", "metadata.attempts"],
        "severity": "high",
        "response_action": "rate_limit",
        "threshold": 10,
    },
    {
        "rule_key": "unknown-actor-step-up",
        "title": "Require step-up for unknown actors",
        "pattern": "unknown|suspicious|new_ip",
        "match_on": ["metadata.username", "metadata.user", "source_ip"],
        "severity": "medium",
        "response_action": "require_mfa",
        "threshold": 1,
    },
]


def generate_correlation_id(prefix: str = "sec") -> str:
    """Create a short correlation ID suitable for dashboards and exports."""
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def _safe_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))


def _parse_datetime(value: Any) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).strip()
    if not text:
        return None
    for candidate in (
        text.replace(" UTC", "+00:00"),
        text,
    ):
        try:
            return datetime.fromisoformat(candidate)
        except ValueError:
            continue
    try:
        return datetime.strptime(text, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def _match_rule_value(value: Any, rule_pattern: str, threshold: int) -> bool:
    if value is None:
        return False

    text = str(value).lower()
    tokens = [token.strip().lower() for token in rule_pattern.split("|") if token.strip()]
    if any(token in text for token in tokens if not token.startswith("attempts>=")):
        return True

    if "attempts>=" in rule_pattern:
        try:
            minimum = int(rule_pattern.split("attempts>=")[-1].split("|")[0])
            return int(value) >= minimum
        except (ValueError, TypeError):
            return False

    try:
        return int(value) >= threshold
    except (ValueError, TypeError):
        return False


def _get_nested_value(payload: Dict[str, Any], path: str) -> Any:
    current: Any = payload
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def build_threat_intel_profile(
    source_ip: str, attack_type: str, metadata: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Return a small threat-intel enrichment profile for the incident."""
    metadata = metadata or {}
    actor = metadata.get("username") or metadata.get("user") or "unknown"
    if source_ip.startswith("203.0.113."):
        reputation = "lab-simulation"
        geo = "Reserved demo network"
        risk_score = 92
    elif source_ip.startswith("198.51.100."):
        reputation = "simulated-hostile"
        geo = "Reserved demo network"
        risk_score = 88
    else:
        reputation = "unknown"
        geo = "unclassified"
        risk_score = 54

    if str(attack_type).lower() == "sql_injection":
        risk_score = min(100, risk_score + 6)
    elif str(attack_type).lower() == "brute_force":
        risk_score = min(100, risk_score + 3)

    recommended_actions = ["review source reputation", "preserve evidence"]
    if str(attack_type).lower() == "sql_injection":
        recommended_actions = ["block_ip", "rotate exposed credentials", "review WAF policy"]
    elif str(attack_type).lower() == "brute_force":
        recommended_actions = ["rate_limit", "require_mfa", "watch for credential stuffing"]

    return {
        "source_ip": source_ip,
        "actor": actor,
        "reputation": reputation,
        "geo": geo,
        "risk_score": risk_score,
        "observables": {
            "attack_type": attack_type,
            "user_agent": metadata.get("user_agent", "unknown"),
            "vector": metadata.get("vector", "unknown"),
        },
        "recommended_actions": recommended_actions,
    }


def evaluate_security_rules(
    attack: Dict[str, Any], rules: Optional[Iterable[Dict[str, Any]]] = None
) -> List[Dict[str, Any]]:
    """Return rule matches for a single attack payload."""
    rules_to_use = list(rules or DEFAULT_SECURITY_RULES)
    matches: List[Dict[str, Any]] = []
    for rule in rules_to_use:
        pattern = str(rule.get("pattern", "")).strip()
        if not pattern:
            continue

        threshold = int(rule.get("threshold", 1) or 1)
        match_fields = rule.get("match_on") or ["attack_type", "payload", "metadata.vector"]
        matched = False
        for field in match_fields:
            candidate = _get_nested_value(attack, field)
            if _match_rule_value(candidate, pattern, threshold):
                matched = True
                break

        if matched:
            matches.append(
                {
                    "rule_key": rule.get("rule_key", "custom"),
                    "title": rule.get("title", "Security rule"),
                    "severity": rule.get("severity", attack.get("severity", "medium")),
                    "response_action": rule.get("response_action", "monitor"),
                    "threshold": threshold,
                }
            )
    return matches


def build_event_fingerprint(payload: Dict[str, Any]) -> str:
    """Create a tamper-evident fingerprint for exported or stored incident state."""
    return hashlib.sha256(_safe_json(payload).encode("utf-8")).hexdigest()


def enrich_security_state(
    state: Dict[str, Any], rules: Optional[Iterable[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """Add correlation IDs, threat intel, rule matches, and integrity data."""
    enriched = copy.deepcopy(state or {})
    incident_id = enriched.get("incident_id") or generate_correlation_id("incident")
    enriched["incident_id"] = incident_id
    enriched["correlation_id"] = enriched.get("correlation_id") or generate_correlation_id("corr")

    attacks = enriched.get("attacks", []) if isinstance(enriched.get("attacks", []), list) else []
    alerts = enriched.get("active", []) if isinstance(enriched.get("active", []), list) else []
    blocked_ips = (
        enriched.get("blocked_ips", []) if isinstance(enriched.get("blocked_ips", []), list) else []
    )

    for index, attack in enumerate(attacks, start=1):
        metadata = attack.get("metadata") if isinstance(attack.get("metadata"), dict) else {}
        attack_correlation_id = attack.get("correlation_id") or f"{incident_id}-attack-{index}"
        attack["correlation_id"] = attack_correlation_id
        attack["threat_intel"] = build_threat_intel_profile(
            str(attack.get("source_ip", "unknown")),
            str(attack.get("attack_type", "unknown")),
            metadata,
        )
        attack["matched_rules"] = evaluate_security_rules(attack, rules)
        attack["recommended_actions"] = list(
            dict.fromkeys(
                [
                    action
                    for match in attack["matched_rules"]
                    for action in [match.get("response_action", "monitor")]
                ]
                + attack["threat_intel"].get("recommended_actions", [])
            )
        )
        attack["event_hash"] = build_event_fingerprint(
            {
                "incident_id": incident_id,
                "correlation_id": attack_correlation_id,
                "attack_type": attack.get("attack_type"),
                "source_ip": attack.get("source_ip"),
                "status": attack.get("status"),
                "detected_at": attack.get("detected_at"),
                "metadata": metadata,
            }
        )

    for index, alert in enumerate(alerts, start=1):
        alert["correlation_id"] = alert.get("correlation_id") or f"{incident_id}-alert-{index}"
        alert["event_hash"] = build_event_fingerprint(
            {
                "incident_id": incident_id,
                "correlation_id": alert["correlation_id"],
                "title": alert.get("title"),
                "message": alert.get("message"),
                "severity": alert.get("severity"),
                "created_at": alert.get("created_at"),
            }
        )

    for index, block in enumerate(blocked_ips, start=1):
        block["correlation_id"] = block.get("correlation_id") or f"{incident_id}-block-{index}"
        block["event_hash"] = build_event_fingerprint(
            {
                "incident_id": incident_id,
                "correlation_id": block["correlation_id"],
                "ip": block.get("ip"),
                "reason": block.get("reason"),
                "blocked_at": block.get("blocked_at"),
            }
        )

    enriched["attacks"] = attacks
    enriched["active"] = alerts
    enriched["blocked_ips"] = blocked_ips

    total_attacks = len(attacks)
    blocked_count = sum(
        1 for attack in attacks if str(attack.get("status", "")).lower() == "blocked"
    )
    critical_count = sum(
        1 for attack in attacks if str(attack.get("severity", "")).lower() == "critical"
    )
    top_intel = max(
        (attack.get("threat_intel", {}) for attack in attacks),
        key=lambda item: item.get("risk_score", 0),
        default={},
    )
    enriched["executive_summary"] = {
        "threat_level": "critical" if critical_count else "high" if blocked_count else "medium",
        "attack_count": total_attacks,
        "blocked_count": blocked_count,
        "alert_count": len(alerts),
        "block_rate": round((blocked_count / total_attacks) * 100, 1) if total_attacks else 0.0,
        "top_risk_score": top_intel.get("risk_score", 0),
        "top_reputation": top_intel.get("reputation", "unknown"),
        "recommended_actions": list(
            dict.fromkeys(
                [action for attack in attacks for action in attack.get("recommended_actions", [])][
                    :6
                ]
            )
        ),
    }

    fingerprint_source = {
        "incident_id": incident_id,
        "correlation_id": enriched["correlation_id"],
        "executive_summary": enriched["executive_summary"],
        "attacks": [
            {
                "correlation_id": item.get("correlation_id"),
                "event_hash": item.get("event_hash"),
                "status": item.get("status"),
            }
            for item in attacks
        ],
        "alerts": [
            {
                "correlation_id": item.get("correlation_id"),
                "event_hash": item.get("event_hash"),
                "severity": item.get("severity"),
            }
            for item in alerts
        ],
        "blocked_ips": [
            {
                "correlation_id": item.get("correlation_id"),
                "event_hash": item.get("event_hash"),
                "ip": item.get("ip"),
            }
            for item in blocked_ips
        ],
    }
    enriched["integrity_hash"] = build_event_fingerprint(fingerprint_source)
    return enriched


def calculate_security_kpis(
    attacks: Iterable[Dict[str, Any]],
    alerts: Iterable[Dict[str, Any]],
    blocked_ips: Iterable[Dict[str, Any]],
) -> Dict[str, Any]:
    """Calculate response metrics used in the security views."""
    attacks_list = list(attacks or [])
    alerts_list = list(alerts or [])
    blocked_list = list(blocked_ips or [])

    detected_datetimes = [_parse_datetime(item.get("detected_at")) for item in attacks_list]
    alert_datetimes = [_parse_datetime(item.get("created_at")) for item in alerts_list]
    blocked_datetimes = [_parse_datetime(item.get("blocked_at")) for item in blocked_list]

    mttd_values = []
    mttr_values = []
    for attack in attacks_list:
        detected_at = _parse_datetime(attack.get("detected_at"))
        if not detected_at:
            continue
        alert_time = next((dt for dt in alert_datetimes if dt), None)
        block_time = next((dt for dt in blocked_datetimes if dt), None)
        if alert_time:
            mttd_values.append(max(0.0, (alert_time - detected_at).total_seconds() / 60.0))
        if block_time:
            mttr_values.append(max(0.0, (block_time - detected_at).total_seconds() / 60.0))

    attack_count = len(attacks_list)
    blocked_count = sum(
        1 for attack in attacks_list if str(attack.get("status", "")).lower() == "blocked"
    )
    critical_count = sum(
        1 for attack in attacks_list if str(attack.get("severity", "")).lower() == "critical"
    )
    active_alert_count = sum(1 for alert in alerts_list if not alert.get("is_resolved"))

    return {
        "attack_count": attack_count,
        "critical_count": critical_count,
        "alert_count": len(alerts_list),
        "active_alert_count": active_alert_count,
        "blocked_count": blocked_count,
        "block_rate": round((blocked_count / attack_count) * 100, 1) if attack_count else 0.0,
        "false_positive_rate": (
            round(max(0.0, (len(alerts_list) - blocked_count) / len(alerts_list) * 100), 1)
            if alerts_list
            else 0.0
        ),
        "mttd_minutes": round(sum(mttd_values) / len(mttd_values), 2) if mttd_values else 0.0,
        "mttr_minutes": round(sum(mttr_values) / len(mttr_values), 2) if mttr_values else 0.0,
        "first_detected_at": (
            min((dt for dt in detected_datetimes if dt), default=None).isoformat()
            if any(detected_datetimes)
            else None
        ),
        "latest_alert_at": (
            max((dt for dt in alert_datetimes if dt), default=None).isoformat()
            if any(alert_datetimes)
            else None
        ),
        "latest_block_at": (
            max((dt for dt in blocked_datetimes if dt), default=None).isoformat()
            if any(blocked_datetimes)
            else None
        ),
    }


def build_incident_export_payload(
    state: Dict[str, Any],
    attacks: Iterable[Dict[str, Any]],
    alerts: Iterable[Dict[str, Any]],
    blocked_ips: Iterable[Dict[str, Any]],
    kpis: Dict[str, Any],
) -> Dict[str, Any]:
    """Create a portable incident package for downloads and audit records."""
    payload = {
        "generated_at": state.get("generated_at"),
        "incident_id": state.get("incident_id"),
        "correlation_id": state.get("correlation_id"),
        "integrity_hash": state.get("integrity_hash"),
        "executive_summary": state.get("executive_summary", {}),
        "kpis": kpis,
        "attacks": list(attacks),
        "alerts": list(alerts),
        "blocked_ips": list(blocked_ips),
        "recommended_actions": state.get("executive_summary", {}).get("recommended_actions", []),
    }
    payload["export_hash"] = build_event_fingerprint(payload)
    return payload
