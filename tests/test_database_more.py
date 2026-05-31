import os
import json

from database import Database


def test_user_crud_and_auth(tmp_path):
    db_path = str(tmp_path / "test_agentic.db")
    if os.path.exists(db_path):
        os.remove(db_path)

    db = Database(db_path)

    assert db.create_user('tester', 'tester@example.local', 's3cret') is True
    assert db.has_users() is True

    user = db.authenticate_user('tester', 's3cret')
    assert user and user['username'] == 'tester'

    uid = user['id']
    assert db.get_user_by_id(uid)['username'] == 'tester'

    # change password
    assert db.change_password(uid, 'newpass') is True
    assert db.authenticate_user('tester', 's3cret') is None
    assert db.authenticate_user('tester', 'newpass') is not None

    # role/status updates
    assert db.update_user_role(uid, 'admin') is True
    assert db.update_user_status(uid, 'suspended') is True

    # delete
    assert db.delete_user(uid) is True
    assert db.get_user_by_id(uid) is None


def test_agents_sessions_events_and_tasks(tmp_path):
    db_path = str(tmp_path / "test_agentic2.db")
    if os.path.exists(db_path):
        os.remove(db_path)

    db = Database(db_path)

    # agent lifecycle
    assert db.add_agent('agent-1', 'TestAgent') is True
    agent = db.get_agent('agent-1')
    assert agent and agent['name'] == 'TestAgent'

    assert db.update_agent('agent-1', name='XAgent') is True
    assert db.update_agent_status('agent-1', 'inactive') is True

    # sessions
    assert db.create_session('sess-1', 'agent-1', {'meta': 1}) is True
    sessions = db.get_agent_sessions('agent-1')
    assert any(s['id'] == 'sess-1' for s in sessions)

    assert db.end_session('sess-1') is True

    # events and tasks
    assert db.create_task('agent-1', 'remediate', 'do something') is True
    tasks = db.list_tasks()
    assert any(t['agent_id'] == 'agent-1' for t in tasks)

    events = db.get_events('agent-1')
    assert isinstance(events, list)

    # cleanup agent
    assert db.delete_agent('agent-1') is True


def test_attack_alert_block_notifications_and_cases(tmp_path):
    db_path = str(tmp_path / "test_agentic3.db")
    if os.path.exists(db_path):
        os.remove(db_path)

    db = Database(db_path)

    atk_id = db.record_attack_event('sql_injection', '1.2.3.4', '/login', payload='x')
    assert isinstance(atk_id, int)

    alert_id = db.record_security_alert('sqli', 'Suspicious SQLi', 'payload seen', 'high', '1.2.3.4', atk_id)
    assert isinstance(alert_id, int)

    alerts = db.list_security_alerts()
    assert any(a['id'] == alert_id for a in alerts)

    assert db.block_ip('1.2.3.4', 'malicious', attack_event_id=atk_id, duration_seconds=3600) is True
    blocked = db.list_blocked_ips()
    assert any(b['ip'] == '1.2.3.4' for b in blocked)

    nid = db.enqueue_security_notification('svc', 'https://example.local/hook', {'k': 'v'})
    assert isinstance(nid, int)
    notes = db.list_security_notifications()
    assert any(n['id'] == nid for n in notes)

    assert db.update_security_notification(nid, 'sent', 1, None, None) is True

    chain_id = db.record_security_chain_entry('cases', 'hash1', {'a': 1}, None)
    assert isinstance(chain_id, int)
    chains = db.list_security_chain_entries()
    assert any(c['id'] == chain_id for c in chains)

    # security case flow
    case_id = db.upsert_security_case('CASE-1', 'Title', 'medium', 'open', 'sum')
    assert isinstance(case_id, int)
    cases = db.list_security_cases()
    assert any(c['case_key'] == 'CASE-1' for c in cases)

    assert db.close_security_case(case_id) is True

    run_id = db.record_security_playbook_run(case_id, 'playbook-x', 'completed', 'ok', auto_applied=True)
    assert isinstance(run_id, int)
    runs = db.list_security_playbook_runs(case_id=case_id)
    assert any(r['id'] == run_id for r in runs)

    assert db.resolve_security_alert(alert_id) is True

    assert db.record_incident_export('pdf', 'export-hash', 'summary', 'file.pdf') is True

    # system settings
    assert db.set_system_setting('k1', {'v': 1}) is True
    assert db.get_system_setting('k1') == {'v': 1}
    all_settings = db.get_system_settings()
    assert 'k1' in all_settings
