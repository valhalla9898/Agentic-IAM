"""Agent registry module

Provides a lightweight file-backed AgentRegistry implementation used by the
dashboard and core services so agent registrations persist between runs.
"""
import json
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List


class AgentEntry:
	def __init__(self, agent_id: str, agent_identity: Any, endpoints: Optional[List[str]] = None, capabilities: Optional[List[str]] = None):
		self.agent_id = agent_id
		self.agent_identity = agent_identity
		self.status = type('Status', (), {'value': 'active'})()
		self.registration_date = datetime.utcnow()
		self.last_accessed = datetime.utcnow()
		self.registration_id = f"reg_{int(self.registration_date.timestamp())}"
		self.endpoints = endpoints or []
		self.capabilities = capabilities or []

	def to_dict(self):
		return {
			'agent_id': self.agent_id,
			'status': self.status.value,
			'registration_date': self.registration_date.isoformat(),
			'last_accessed': self.last_accessed.isoformat(),
			'registration_id': self.registration_id,
			'endpoints': self.endpoints,
			'capabilities': self.capabilities,
			'metadata': getattr(self.agent_identity, 'metadata', {})
		}


class AgentRegistry:
	"""Simple file-backed agent registry

	Stores a single JSON file containing all registered agents. This is
	intentionally minimal and suitable for development/demo purposes.
	"""

	def __init__(self, storage_path: str = "./data/agent_registry", enable_persistence: bool = True):
		self.storage_dir = Path(storage_path)
		self.storage_dir.mkdir(parents=True, exist_ok=True)
		self.storage_file = self.storage_dir / "registry.json"
		self._agents: Dict[str, AgentEntry] = {}
		self._load()

	def _load(self):
		if self.storage_file.exists():
			try:
				data = json.loads(self.storage_file.read_text(encoding='utf-8'))
				for aid, info in data.items():
					entry = AgentEntry(agent_id=aid, agent_identity=type('Identity', (), {'metadata': info.get('metadata', {})})(), endpoints=info.get('endpoints', []), capabilities=info.get('capabilities', []))
					entry.status = type('Status', (), {'value': info.get('status', 'active')})()
					entry.registration_date = datetime.fromisoformat(info.get('registration_date'))
					entry.last_accessed = datetime.fromisoformat(info.get('last_accessed'))
					entry.registration_id = info.get('registration_id')
					self._agents[aid] = entry
			except Exception:
				# If registry file is corrupt, start fresh
				self._agents = {}

	def _persist(self):
		data = {aid: entry.to_dict() for aid, entry in self._agents.items()}
		try:
			self.storage_file.write_text(json.dumps(data, indent=2), encoding='utf-8')
		except OSError as e:
			# Fallback to OS temp directory if disk is full or write fails
			try:
				import tempfile
				alt = Path(tempfile.gettempdir()) / "agent_registry_fallback.json"
				alt.write_text(json.dumps(data, indent=2), encoding='utf-8')
				print(f"Warning: could not write registry to {self.storage_file}; wrote to {alt} instead: {e}")
				self.storage_file = alt
			except Exception as e2:
				# If even fallback fails, raise original error
				raise

	def register_agent(self, agent_identity, endpoints=None, capabilities=None):
		aid = agent_identity.agent_id
		if aid in self._agents:
			return self._agents[aid].registration_id

		entry = AgentEntry(agent_id=aid, agent_identity=agent_identity, endpoints=endpoints, capabilities=capabilities)
		self._agents[aid] = entry
		self._persist()
		return entry.registration_id

	def get_agent(self, agent_id: str) -> Optional[AgentEntry]:
		return self._agents.get(agent_id)

	def list_agents(self) -> List[AgentEntry]:
		return list(self._agents.values())


__all__ = ['AgentRegistry']
