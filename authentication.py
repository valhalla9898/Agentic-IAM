"""Authentication module

Provides higher-level authentication helpers including OIDC token verification
and a wrapper AuthenticationManager that can delegate to OIDC or the built-in
`agent_identity.AuthenticationManager`.
"""

from typing import Dict, Optional

from agent_identity import AuthenticationManager as BaseAuthManager
from agent_identity import AuthenticationResult
from auth_oidc import verify_oidc_token


class AuthenticationManager(BaseAuthManager):
    async def authenticate(self, agent_id: str, credentials: Dict, method: str = "auto", **kwargs):
        # If a bearer token is present, try OIDC first
        token = credentials.get("token") or credentials.get("access_token")
        if token:
            issuer = kwargs.get("issuer")
            audience = kwargs.get("audience")
            claims = verify_oidc_token(token, issuer=issuer, audience=audience)
            if claims:
                return AuthenticationResult(True, claims.get("sub", agent_id), "oidc", 0.9)

        # Fallback to base implementation
        base = BaseAuthManager()
        return await base.authenticate(agent_id, credentials, method, **kwargs)


def verify_token(token: str, issuer: Optional[str] = None, audience: Optional[str] = None) -> Optional[dict]:
    """Convenience function to verify OIDC/JWT tokens."""
    return verify_oidc_token(token, issuer=issuer, audience=audience)


__all__ = ["AuthenticationManager", "AuthenticationResult", "verify_token"]
