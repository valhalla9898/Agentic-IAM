"""Mobile SDK support module.

This module exposes a minimal Python SDK surface for integration tests and
lightweight local development.
"""


class AgenticIAMSDK:
	"""Minimal mobile SDK placeholder."""

	async def register_agent(self, agent_data):
		return {"success": True, "agent": agent_data}
