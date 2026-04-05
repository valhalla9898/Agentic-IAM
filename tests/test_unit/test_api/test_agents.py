"""Unit tests for agent management API endpoints."""

import pytest
from unittest.mock import MagicMock


class TestAgentAPI:
    @pytest.mark.unit
    @pytest.mark.api
    def test_delete_agent_success(self, client, mock_iam):
        mock_agent_entry = MagicMock()
        mock_iam.agent_registry.get_agent.return_value = mock_agent_entry
        mock_iam.delete_agent = MagicMock(
            return_value={
                "agent_id": "agent:test-001",
                "registry_deleted": True,
                "sessions_terminated": 2,
            }
        )

        response = client.delete("/api/v1/agents/agent:test-001")

        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "deleted"
        assert data["agent_id"] == "agent:test-001"
        assert data["sessions_terminated"] == "2"
        assert data["registry_deleted"] == "True"

        mock_iam.delete_agent.assert_called_once_with("agent:test-001")

    @pytest.mark.unit
    @pytest.mark.api
    def test_delete_agent_missing(self, client, mock_iam):
        mock_iam.agent_registry.get_agent.return_value = None

        response = client.delete("/api/v1/agents/agent:missing")

        assert response.status_code == 404

    @pytest.mark.unit
    @pytest.mark.api
    def test_list_agents_uses_registry_entries(self, client, mock_iam):
        mock_agent_one = MagicMock()
        mock_agent_one.agent_id = "agent:test-001"
        mock_agent_two = MagicMock()
        mock_agent_two.agent_id = "agent:test-002"
        mock_iam.agent_registry.list_agents.return_value = [mock_agent_one, mock_agent_two]

        response = client.get("/api/v1/agents/")

        assert response.status_code == 200
        data = response.json()

        assert data["agents"] == ["agent:test-001", "agent:test-002"]
        assert data["count"] == 2