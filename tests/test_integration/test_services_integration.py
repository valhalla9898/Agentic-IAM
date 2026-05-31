import pytest


@pytest.mark.integration
def test_service_registry_initialize_and_shutdown():
    from services.registry import ServiceRegistry

    registry = ServiceRegistry()
    # initialize should not raise
    registry.initialize()

    services = registry.list_services()
    assert "access" in services
    assert "investigation" in services or "trust" in services

    # shutdown should run without errors
    registry.shutdown()


@pytest.mark.integration
def test_access_and_investigation_integration():
    from services.registry import ServiceRegistry

    registry = ServiceRegistry()
    registry.initialize()

    # configure a role and permission
    registry.access.add_role("operator", ["agents:register", "agents:list"])
    allowed = registry.access.check_access("operator", "agents", "register")
    assert allowed is True

    # record an event in investigation timeline and fetch
    registry.investigation.record_event({
        "agent_id": "integration-agent-1",
        "event_type": "register",
        "details": {"by": "test"},
        "id": "evt-1",
    })

    timeline = registry.investigation.fetch_timeline(agent_id="integration-agent-1")
    assert any(e.get("event_type") == "register" for e in timeline)

    registry.shutdown()


@pytest.mark.integration
def test_agent_trust_updates_score():
    from services.registry import ServiceRegistry

    registry = ServiceRegistry()
    registry.initialize()

    # initially no score
    score = registry.trust.calculate_trust_score("agent-x")
    assert score is None or isinstance(score, float)

    registry.trust.update_from_event("agent-x", "positive_interaction", weight=0.1)
    score2 = registry.trust.calculate_trust_score("agent-x")
    assert score2 is not None
    assert 0.0 <= score2 <= 1.0

    registry.shutdown()


@pytest.mark.integration
def test_zero_trust_and_investigation_branches():
    from services.registry import ServiceRegistry

    registry = ServiceRegistry()
    registry.initialize()

    # zero trust placeholder behavior
    risk = registry.zerotrust.evaluate_risk("agent-z", {"ip": "1.2.3.4"})
    assert risk == 0.0
    assert registry.zerotrust.continuous_verify("agent-z", {}) is True

    # access policy helper branches
    registry.access.add_role("viewer", ["read"])
    registry.access.assign_permission("viewer", "agents:list")
    assert registry.access.check_access("viewer", "agents", "list") is True
    assert registry.access.check_access("viewer", "secrets", "delete") is False

    # investigation analysis helpers
    registry.investigation.record_event({
        "agent_id": "agent-z",
        "event_type": "alert",
        "details": {"severity": "high"},
        "id": "evt-z1",
    })
    registry.investigation.record_event({
        "agent_id": "agent-y",
        "event_type": "alert",
        "details": {"severity": "low"},
        "id": "evt-z2",
    })
    timeline = registry.investigation.fetch_timeline(agent_id="agent-z", limit=10)
    assert len(timeline) == 1
    summary = registry.investigation.analyze_attack(["evt-z1", "evt-z2"])
    assert summary["summary"] == "analysis placeholder"
    assert summary["event_count"] == 2

    registry.shutdown()
