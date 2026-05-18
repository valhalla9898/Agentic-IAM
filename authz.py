"""Authorization wrapper using Casbin policy engine (optional)."""
try:
    import casbin
    CASBIN_AVAILABLE = True
except Exception:
    CASBIN_AVAILABLE = False

import os

_enforcer = None


def get_enforcer():
    global _enforcer
    if _enforcer is not None:
        return _enforcer
    if not CASBIN_AVAILABLE:
        return None
    model = os.path.join(os.path.dirname(__file__), 'casbin_model.conf')
    policy = os.path.join(os.path.dirname(__file__), 'policies', 'policy.csv')
    _enforcer = casbin.Enforcer(model, policy)
    return _enforcer


def is_allowed(subject: str, obj: str, action: str) -> bool:
    enforcer = get_enforcer()
    if not enforcer:
        # Fallback: simple allow for wildcard
        return subject == 'admin' or '*' in (subject, obj, action)
    return enforcer.enforce(subject, obj, action)

