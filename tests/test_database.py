import os
import json

from database import Database


def test_database_init_and_attack_event(tmp_path):
    db_file = tmp_path / "agentic_test.db"
    db = Database(str(db_file))

    # DB file should be created
    assert os.path.exists(db.db_path)

    # Record an attack event
    eid = db.record_attack_event(
        attack_type="sql_injection",
        source_ip="127.0.0.1",
        target_endpoint="/login",
        payload="{'attempt':'1'}",
        severity="high",
        metadata={"sample": True},
    )
    assert isinstance(eid, int)

    events = db.list_attack_events()
    assert any(e["id"] == eid for e in events) or len(events) >= 1


def test_block_ip_and_list(tmp_path):
    db_file = tmp_path / "agentic_test2.db"
    db = Database(str(db_file))

    ok = db.block_ip("10.0.0.1", reason="malicious", duration_seconds=60)
    assert ok is True

    blocked = db.list_blocked_ips()
    assert isinstance(blocked, list)
    assert any(b["ip"] == "10.0.0.1" or b.get("ip") == "10.0.0.1" for b in blocked)
from database import Database


def test_database_agent_lifecycle(tmp_path):
    db_path = tmp_path / "agentic_test.db"
    db = Database(db_path=str(db_path))

    # add agent
    assert db.add_agent("agent-1", "Test Agent") is True

    a = db.get_agent("agent-1")
    assert a is not None
    assert a["id"] == "agent-1"

    agents = db.list_agents()
    assert any(x["id"] == "agent-1" for x in agents)

    # update
    assert db.update_agent("agent-1", name="Renamed") is True

    # delete
    assert db.delete_agent("agent-1") is True
    assert db.get_agent("agent-1") is None


def test_user_create_authenticate_change_password(tmp_path):
    db_path = tmp_path / "agentic_users.db"
    db = Database(db_path=str(db_path))

    username = "tester"
    email = "tester@example.local"
    password = "s3cr3t"

    assert db.create_user(username, email, password) is True

    users = db.list_users()
    user = next((u for u in users if u["username"] == username), None)
    # If list_users returns dicts, adapt
    if user is None:
        # try matching by username in dict list
        user = next((u for u in users if u.get("username") == username), None)

    assert user is not None
    user_id = user["id"] if isinstance(user, dict) else user[0]

    auth = db.authenticate_user(username, password)
    assert auth is not None

    # change password
    assert db.change_password(user_id, "n3wpwd") is True

    # old password should fail
    assert db.authenticate_user(username, password) is None
    assert db.authenticate_user(username, "n3wpwd") is not None


def test_session_and_events(tmp_path):
    db_path = tmp_path / "agentic_events.db"
    db = Database(db_path=str(db_path))

    agent_id = "agent-sess"
    assert db.add_agent(agent_id, "Sess Agent") is True

    # create session
    assert db.create_session("sess-1", agent_id, metadata={"k": "v"}) is True

    sessions = db.get_agent_sessions(agent_id)
    assert any(s["id"] == "sess-1" for s in sessions)

    # end session
    assert db.end_session("sess-1") is True

    events = db.get_events(agent_id=agent_id, limit=50)
    # expect at least session_created or session_ended events
    types = [e["event_type"] for e in events]
    assert any(t in ("session_created", "session_ended") for t in types)
