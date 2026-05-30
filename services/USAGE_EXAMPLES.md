# Services usage examples

This file shows minimal examples for how to use the new backend scaffolds from the application code without changing any UI.

Initialize (already performed in `initialize_session`):

- Access the registry from `st.session_state.services`.

Example: check access

```python
svc = st.session_state.services
allowed = svc.access.check_access("admin", "agents", "register")
if allowed:
    # proceed with registration
    pass
```

Example: record event to investigation timeline

```python
svc = st.session_state.services
svc.investigation.record_event({
    "agent_id": "agent-123",
    "event_type": "register",
    "details": {"source": "dashboard"},
    "timestamp": "2026-05-30T00:00:00Z",
})

recent = svc.investigation.fetch_timeline(agent_id="agent-123")
```

Example: trust score update

```python
svc.trust.update_from_event("agent-123", "positive_interaction", weight=0.05)
score = svc.trust.calculate_trust_score("agent-123")
```

Example: Zero Trust evaluation

```python
risk = svc.zerotrust.evaluate_risk("agent-123", {"ip": "203.0.113.77"})
if risk > 0.8:
    # flag for manual review
    pass
```

These snippets are safe to run in the existing app because `initialize_session()` attaches `services` to `st.session_state`.
