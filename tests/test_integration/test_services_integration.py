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
