"""OIDC helper for verifying ID/access tokens using JWKS and python-jose."""
import os
import requests
from jose import jwt
from jose.exceptions import JWTError

_jwks_cache = {}


def _fetch_jwks(issuer: str):
    if issuer in _jwks_cache:
        return _jwks_cache[issuer]
    try:
        well_known = issuer.rstrip('/') + '/.well-known/openid-configuration'
        resp = requests.get(well_known, timeout=5)
        resp.raise_for_status()
        jwks_uri = resp.json().get('jwks_uri')
        jwks = requests.get(jwks_uri, timeout=5).json()
        _jwks_cache[issuer] = jwks
        return jwks
    except Exception:
        return None


def verify_oidc_token(token: str, issuer: str = None, audience: str = None) -> dict | None:
    """Verify JWT against issuer JWKS; returns claims or None on failure."""
    try:
        if not issuer:
            issuer = os.getenv('OIDC_ISSUER')
        if not audience:
            audience = os.getenv('OIDC_AUDIENCE')
        jwks = _fetch_jwks(issuer)
        if not jwks:
            return None
        # Let jose handle key selection with jwks
        claims = jwt.decode(token, jwks, audience=audience, issuer=issuer, options={'verify_at_hash': False})
        return claims
    except JWTError:
        return None
    except Exception:
        return None
