import json
from types import SimpleNamespace
from pathlib import Path

from agent_registry import AgentRegistry


def test_register_get_delete_persist(tmp_path):
    storage = tmp_path / "registry"
    registry = AgentRegistry(storage_path=str(storage), enable_persistence=True)

    # create dummy identity
    identity = SimpleNamespace(agent_id="agent-123", metadata={"foo": "bar"})

    reg_id = registry.register_agent(identity, endpoints=["http://a"], capabilities=["read"])
    assert reg_id.startswith("reg_")

    entry = registry.get_agent("agent-123")
    assert entry is not None
    assert entry.agent_id == "agent-123"
    assert "http://a" in entry.endpoints

    # ensure persistence file exists
    assert (storage / "registry.json").exists()

    # delete and confirm
    assert registry.delete_agent("agent-123") is True
    assert registry.get_agent("agent-123") is None


def test_corrupt_registry_file_is_handled(tmp_path):
    storage = tmp_path / "registry"
    storage.mkdir(parents=True)
    bad = storage / "registry.json"
    bad.write_text("this is not valid json")

    # should not raise
    registry = AgentRegistry(storage_path=str(storage), enable_persistence=True)
    assert registry.list_agents() == []

    # can still register new agents after corruption
    identity = SimpleNamespace(agent_id="agent-xyz", metadata={})
    rid = registry.register_agent(identity)
    assert rid.startswith("reg_")
