from dashboard.components.agent_selection import filter_visible_agents
from dashboard.components.ai_assistant import _local_helper
from dashboard.components.risk_assessment import compute_risk_score


def test_filter_visible_agents_admin_sees_all():
    agents = [
        {"id": "a1", "metadata": {"visibility": "private"}},
        {"id": "a2", "metadata": {"visibility": "shared"}},
    ]

    visible = filter_visible_agents(agents, {"role": "admin"})
    assert [a["id"] for a in visible] == ["a1", "a2"]


def test_filter_visible_agents_owner_and_shared_user():
    agents = [
        {"id": "a1", "metadata": {"visibility": "private", "created_by": "alice"}},
        {
            "id": "a2",
            "metadata": {"visibility": "private", "shared_with": ["bob"]},
        },
        {"id": "a3", "metadata": {"visibility": "public"}},
        {"id": "a4", "metadata": {"visibility": "private"}},
    ]

    visible = filter_visible_agents(agents, {"role": "user", "username": "alice"})
    assert {a["id"] for a in visible} == {"a1", "a3"}

    visible_shared = filter_visible_agents(agents, {"role": "user", "username": "bob"})
    assert {a["id"] for a in visible_shared} == {"a2", "a3"}


def test_compute_risk_score_uses_all_inputs():
    score = compute_risk_score({"failed_actions": 4, "alerts": 2, "uptime_days": 3})
    assert score == 27.0


def test_local_helper_login_branch_mentions_reset_and_lockout():
    text = _local_helper("How do I login if password is wrong?")
    assert "Authentication & Login Help" in text
    assert "setup_admin.py" in text
    assert "account is not locked" in text


def test_local_helper_agent_branch_mentions_registration():
    text = _local_helper("How do I register an agent?")
    assert "Agent Management" in text
    assert "Register New Agent" in text
    assert "Agent Types" in text


def test_local_helper_permission_and_security_branches():
    perm = _local_helper("What permissions and RBAC roles exist?")
    assert "Permissions & Authorization" in perm
    assert "Admin Role" in perm

    sec = _local_helper("Tell me about security compliance and TLS")
    assert "Security Features" in sec
    assert "mTLS" in sec


def test_local_helper_reports_and_default_branch():
    rep = _local_helper("show dashboard reports and analytics")
    assert "Reports & Analytics" in rep
    assert "PDF" in rep

    default = _local_helper("something unrelated")
    assert "AI Assistant Ready" in default
    assert "Login & Authentication" in default
