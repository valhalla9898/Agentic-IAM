from dashboard.components.agent_selection import filter_visible_agents


AGENTS = [
    {
        "id": "agent-public",
        "name": "Public Agent",
        "metadata": {"visibility": "public", "created_by": "admin", "shared_with": []},
    },
    {
        "id": "agent-private",
        "name": "Private Agent",
        "metadata": {"visibility": "private", "created_by": "admin", "shared_with": []},
    },
    {
        "id": "agent-shared",
        "name": "Shared Agent",
        "metadata": {"visibility": "shared", "created_by": "admin", "shared_with": ["mona"]},
    },
    {
        "id": "agent-owned",
        "name": "Owned Agent",
        "metadata": {"visibility": "private", "created_by": "mona", "shared_with": []},
    },
]


def test_filter_visible_agents_limits_regular_user_view():
    visible = filter_visible_agents(AGENTS, {"username": "mona", "role": "user"})
    assert [agent["id"] for agent in visible] == ["agent-public", "agent-shared", "agent-owned"]


def test_filter_visible_agents_allows_admin_view():
    visible = filter_visible_agents(AGENTS, {"username": "admin", "role": "admin"})
    assert [agent["id"] for agent in visible] == [agent["id"] for agent in AGENTS]
