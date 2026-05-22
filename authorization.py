"""Authorization module

Wraps a policy engine (Casbin when available) and falls back to the
lightweight `agent_identity.AuthorizationManager`.
"""

import logging

from agent_identity import AuthorizationDecision
from agent_identity import AuthorizationManager as BaseAuthz
from agent_identity import RiskLevel, Session
from authz import is_allowed


class AuthorizationManager(BaseAuthz):
    async def authorize(self, agent_id: str, resource: str, action: str, context: dict = None):
        # Context may include subject (user) or role
        subject = None
        if context:
            subject = context.get("subject") or context.get("user")
        # If policy engine available, consult it
        try:
            if is_allowed(subject or agent_id, resource, action):
                return AuthorizationDecision(True, "allowed by policy")
        except Exception as e:
            logging.getLogger(__name__).debug("Policy engine error in is_allowed: %s", e)

        # Fallback to base implementation
        base = BaseAuthz()
        return await base.authorize(agent_id, resource, action, context)


__all__ = ["AuthorizationManager", "AuthorizationDecision", "Session", "RiskLevel"]
