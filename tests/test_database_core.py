import os
import sqlite3
import bcrypt
from pathlib import Path

import pytest

import database as dbmod


@pytest.fixture()
def db(tmp_path, monkeypatch):
    # Ensure fresh global instance per test
    db_file = tmp_path / "test_agentic.db"
    monkeypatch.delenv("DB_PATH", raising=False)
    dbmod._db_instance = None
    d = dbmod.get_database(str(db_file))
    yield d
    # cleanup
    try:
        dconn = sqlite3.connect(str(db_file))
        dconn.close()
    except Exception:
        pass


def test_user_crud_and_auth(db):
    # create user
    assert db.create_user('tester', 'tester@example.com', 'TestPass1!')
    assert db.has_users()

    user = db.authenticate_user('tester', 'TestPass1!')
    assert user and user['username'] == 'tester'

    uid = user['id']
    assert db.get_user_by_id(uid)['username'] == 'tester'

    # change password
    assert db.change_password(uid, 'NewPass2!')
    assert db.authenticate_user('tester', 'NewPass2!')

    # update role and status
    assert db.update_user_role(uid, 'operator')
    assert db.update_user_status(uid, 'suspended')
    u = db.get_user_by_id(uid)
    assert u['role'] == 'operator' and u['status'] == 'suspended'

    # delete
    assert db.delete_user(uid)
    assert not any(u['username'] == 'tester' for u in db.list_users())


def test_agent_crud_and_sessions(db):
    aid = 'agent_xyz'
    assert db.add_agent(aid, 'Test Agent', agent_type='bot', metadata={'k': 'v'})
    a = db.get_agent(aid)
    assert a and a['id'] == aid and a['metadata'].get('k') == 'v'

    agents = db.list_agents()
    assert any(x['id'] == aid for x in agents)

    # update
    assert db.update_agent(aid, name='Renamed', status='inactive')
    updated = db.get_agent(aid)
    assert updated['name'] == 'Renamed' and updated['status'] == 'inactive'

    # sessions
    sid = 'sess1'
    assert db.create_session(sid, aid, metadata={'ip': '1.2.3.4'})
    sessions = db.get_agent_sessions(aid)
    assert any(s['id'] == sid for s in sessions)

    assert db.end_session(sid)

    # delete agent (should remove agent and sessions)
    assert db.delete_agent(aid)
    assert db.get_agent(aid) is None


def test_events_alerts_and_blocking(db):
    # events and alerts
    eid = db.record_attack_event('sql_injection', '10.0.0.1', payload='payload', severity='high')
    assert isinstance(eid, int)

    events = db.list_attack_events()
    assert any(e['id'] == eid for e in events)

    aid = db.record_security_alert('intrusion', 'Title', 'Message', severity='high', source_ip='10.0.0.1')
    assert isinstance(aid, int)
    alerts = db.list_security_alerts()
    assert any(a['id'] == aid for a in alerts)

    # block ip
    assert db.block_ip('10.0.0.1', 'malicious', attack_event_id=eid, duration_seconds=60)
    blocked = db.list_blocked_ips()
    assert any(b['ip'] == '10.0.0.1' for b in blocked)


def test_notifications_and_settings(db):
    nid = db.enqueue_security_notification('svc', 'https://example.com/webhook', {'a': 1})
    assert isinstance(nid, int)
    notifs = db.list_security_notifications()
    assert any(n['id'] == nid for n in notifs)

    assert db.update_security_notification(nid, status='sent', attempts=1, last_error=None)
    updated = db.list_security_notifications(status='sent')
    assert any(n['id'] == nid for n in updated)

    # settings
    assert db.set_system_setting('s1', {'x': 1})
    assert db.get_system_setting('s1') == {'x': 1}
    all_settings = db.get_system_settings()
    assert 's1' in all_settings
