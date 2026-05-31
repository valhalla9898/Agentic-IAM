import streamlit as st

from utils.rbac import (
    RBACManager,
    Permission,
    Role,
    check_permission,
    check_role,
    get_current_user_role,
    get_current_user_permissions,
    is_admin,
    is_operator,
    is_authenticated,
)


def test_rbac_basic_permissions(monkeypatch):
    # Clear session state
    st.session_state.clear()
    r = RBACManager()
    assert r.get_user_role(None) == Role.GUEST

    user_admin = {"username": "a", "role": "admin"}
    assert r.get_user_role(user_admin) == Role.ADMIN
    perms = r.get_user_permissions(user_admin)
    assert Permission.AGENT_CREATE in perms

    user_user = {"username": "u", "role": "user"}
    assert Permission.AGENT_READ in r.get_user_permissions(user_user)
    assert Permission.AGENT_CREATE not in r.get_user_permissions(user_user)


def test_has_any_all_and_helpers(monkeypatch):
    st.session_state.clear()
    st.session_state['user'] = {"username": "op", "role": "operator"}
    assert check_permission(Permission.AGENT_UPDATE)
    assert check_role(Role.OPERATOR)
    assert get_current_user_role() == Role.OPERATOR
    perms = get_current_user_permissions()
    assert Permission.SESSION_TERMINATE in perms
    assert is_operator()
    assert not is_admin()


def test_decorators_behavior(monkeypatch):
    st.session_state.clear()

    # user without permission
    st.session_state['user'] = {"username": "g", "role": "guest"}

    r = RBACManager()

    @r.require_permission(Permission.AGENT_CREATE)
    def protected():
        return 'ok'

    assert protected() is None

    # now admin
    st.session_state['user'] = {"username": "a", "role": "admin"}
    assert protected() == 'ok'
