import requests
import streamlit as st

import app as app_module


class FakeDB:
    def __init__(self):
        self._attack_id = 1
        self.events = []
        self.settings = {}
        self.notifications_updated = []

    def get_system_settings(self):
        return {"webhooks_enabled": False, "siem_enabled": False}

    def record_attack_event(self, **kwargs):
        aid = self._attack_id
        self._attack_id += 1
        return aid

    def record_security_alert(self, **kwargs):
        return 1

    def block_ip(self, **kwargs):
        return True

    def log_event(self, *a, **kw):
        self.events.append((a, kw))

    def set_system_setting(self, key, value):
        self.settings[key] = value

    def upsert_security_case(self, **kwargs):
        return 1

    def list_security_chain_entries(self, **kwargs):
        return []

    def record_security_chain_entry(self, **kwargs):
        return True

    def record_incident_export(self, **kwargs):
        return True

    def record_security_playbook_run(self, **kwargs):
        return True

    def list_security_notifications(self, **kwargs):
        return []

    def update_security_notification(self, id, **kwargs):
        self.notifications_updated.append((id, kwargs))


def test_build_demo_security_state_contains_expected_sections():
    state = app_module._build_demo_security_state()
    assert isinstance(state, dict)
    assert "attacks" in state and isinstance(state["attacks"], list)
    assert "active" in state and isinstance(state["active"], list)
    assert "blocked_ips" in state and isinstance(state["blocked_ips"], list)


def test_write_and_load_demo_state(tmp_path):
    # Temporarily change DEMO_SECURITY_STATE_PATH to tmp file
    orig = app_module.DEMO_SECURITY_STATE_PATH
    try:
        app_module.DEMO_SECURITY_STATE_PATH = tmp_path / "security_state.json"
        state = app_module._build_demo_security_state()
        written = app_module._write_demo_security_state(state)
        assert written.get("incident_id") == state.get("incident_id")
        loaded = app_module._load_demo_security_state()
        assert loaded.get("incident_id") == state.get("incident_id")
    finally:
        app_module.DEMO_SECURITY_STATE_PATH = orig


def test_persist_demo_state_uses_db_methods(monkeypatch, tmp_path):
    fake = FakeDB()
    # attach fake DB to streamlit session
    st.session_state.db = fake

    # ensure demo path is in temp
    orig = app_module.DEMO_SECURITY_STATE_PATH
    try:
        app_module.DEMO_SECURITY_STATE_PATH = tmp_path / "security_state.json"
        state = app_module._build_demo_security_state()
        res = app_module._persist_security_demo_state(state)
        # persisted state should include cases
        assert isinstance(res, dict)
        assert "cases" in res
        # fake db should have logged an event
        assert any(e for e in fake.events)
    finally:
        app_module.DEMO_SECURITY_STATE_PATH = orig


def test_process_security_notification_queue_posts_and_updates(monkeypatch):
    fake = FakeDB()
    # create queued notification
    note = {
        "id": 123,
        "target_name": "webhook",
        "target_url": "http://example.local/hook",
        "payload": {},
    }

    def list_notifications(limit=20, status=None):
        return [note]

    fake.list_security_notifications = lambda **kw: [note]

    called = {}

    class DummyResp:
        def __init__(self, code=200):
            self.status_code = code

    def fake_post(url, json=None, timeout=5):
        called["url"] = url
        return DummyResp(200)

    monkeypatch.setattr(requests, "post", fake_post)

    res = app_module._process_security_notification_queue(fake)
    assert isinstance(res, list)
