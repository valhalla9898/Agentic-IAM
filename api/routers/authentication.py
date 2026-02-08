from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel
from typing import Optional, Dict, Any

from core.agentic_iam import AgenticIAM
from api.dependencies import get_iam, get_settings

router = APIRouter()


class LoginRequest(BaseModel):
    agent_id: str
    method: str
    credentials: Dict[str, Any]
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None


@router.post("/login")
async def login(payload: LoginRequest, iam: AgenticIAM = Depends(get_iam)):
    try:
        auth_result = await iam.authenticate(payload.dict(), payload.method)

        if not auth_result.success:
            return {"success": False, "error_message": auth_result.error_message}

        # Generate token if available
        token = None
        method_impl = getattr(iam.authentication_manager, "methods", {}).get(auth_result.auth_method or payload.method)
        agent_entry = iam.agent_registry.get_agent(auth_result.agent_id)
        if method_impl and agent_entry:
            try:
                token = method_impl.generate_token(agent_entry.agent_identity)
            except Exception:
                token = None

        # Create session via top-level IAM helper if available
        session_id = None
        if hasattr(iam, "create_session"):
            session_id = await iam.create_session(
                agent_id=auth_result.agent_id,
                trust_level=getattr(auth_result, "trust_level", 1.0),
                auth_method=auth_result.auth_method or payload.method,
                ttl=getattr(iam, "session_ttl", None) or 3600,
                metadata={"source_ip": payload.source_ip, "user_agent": payload.user_agent}
            )

        return {
            "success": True,
            "agent_id": auth_result.agent_id,
            "token": token,
            "session_id": session_id,
            "trust_level": getattr(auth_result, "trust_level", None),
            "auth_method": auth_result.auth_method or payload.method
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))


@router.post("/logout")
async def logout(session_id: Optional[str] = Query(None), agent_id: Optional[str] = Query(None), iam: AgenticIAM = Depends(get_iam)):
    try:
        if session_id:
            success = iam.session_manager.terminate_session(session_id, reason="user_logout")
            terminated = 1 if success else 0
        elif agent_id:
            terminated = iam.session_manager.terminate_agent_sessions(agent_id, reason="user_logout")
        else:
            raise HTTPException(status_code=400, detail="Either session_id or agent_id must be provided")

        return {"message": f"Successfully terminated {terminated} session(s)", "data": {"terminated_sessions": terminated}}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/refresh")
async def refresh(request: Dict[str, Any], iam: AgenticIAM = Depends(get_iam)):
    try:
        session_id = request.get("session_id")
        refresh_token = request.get("refresh_token")
        # Attempt refresh via session manager
        success = iam.session_manager.refresh_session(session_id, refresh_token)
        if not success:
            return {"success": False, "error_message": "Invalid refresh token or session expired"}

        session = iam.session_manager.get_session(session_id)
        # Generate new token using default jwt method if available
        token = None
        method_impl = getattr(iam.authentication_manager, "methods", {}).get("jwt")
        agent_entry = iam.agent_registry.get_agent(session.agent_id) if session else None
        if method_impl and agent_entry:
            token = method_impl.generate_token(agent_entry.agent_identity)

        return {"success": True, "agent_id": session.agent_id, "token": token, "session_id": session.session_id, "auth_method": "refresh"}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))


@router.get("/challenge/{agent_id}")
async def get_challenge(agent_id: str, iam: AgenticIAM = Depends(get_iam)):
    try:
        methods = getattr(iam.authentication_manager, "methods", {})
        crypto = methods.get("crypto")
        if not crypto:
            raise HTTPException(status_code=501, detail="Cryptographic authentication not available")

        challenge = crypto.generate_challenge(agent_id)
        return {"challenge": challenge, "agent_id": agent_id, "expires_in": 300, "algorithm": "Ed25519", "timestamp": __import__("datetime").datetime.utcnow().isoformat()}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/verify-signature")
async def verify_signature(agent_id: str, challenge: str, signature: str, iam: AgenticIAM = Depends(get_iam)):
    try:
        agent_entry = iam.agent_registry.get_agent(agent_id)
        if not agent_entry:
            raise HTTPException(status_code=404, detail="Agent not found")

        public_key = agent_entry.agent_identity.get_public_key()
        valid = agent_entry.agent_identity.verify_message(challenge, signature, public_key)

        if valid:
            return {"valid": True, "agent_id": agent_id, "message": "Signature verification successful"}
        else:
            return {"valid": False, "agent_id": agent_id, "message": "Invalid signature"}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/methods")
async def get_methods(iam: AgenticIAM = Depends(get_iam), settings=Depends(get_settings)):
    methods = []
    mgr = getattr(iam.authentication_manager, "methods", {})
    default = getattr(iam.authentication_manager, "default_method", None)
    for name, impl in mgr.items():
        methods.append({
            "name": name,
            "type": impl.__class__.__name__,
            "enabled": True,
            "token_ttl": getattr(impl, "token_ttl", getattr(settings, "jwt_token_ttl", 3600))
        })

    return {"methods": methods, "default_method": default, "mfa_enabled": getattr(settings, "enable_mfa", False), "federated_auth_enabled": getattr(settings, "enable_federated_auth", False)}


@router.get("/status/{agent_id}")
async def get_status(agent_id: str, iam: AgenticIAM = Depends(get_iam)):
    try:
        agent_entry = iam.agent_registry.get_agent(agent_id)
        if not agent_entry:
            raise HTTPException(status_code=404, detail="Agent not found")

        sessions = iam.session_manager.session_store.get_agent_sessions(agent_id)
        active_count = len([s for s in sessions if getattr(s, "is_active", lambda: False)()])

        trust = None
        if hasattr(iam, "calculate_trust_score"):
            trust = await iam.calculate_trust_score(agent_id)

        audit_events = iam.audit_manager.query_events(agent_id=agent_id) if getattr(iam, "audit_manager", None) else []

        return {
            "agent_id": agent_id,
            "agent_status": getattr(agent_entry, "status", {}).value if getattr(agent_entry, "status", None) else "unknown",
            "is_active": active_count > 0,
            "sessions_count": len(sessions),
            "trust_score": getattr(trust, "overall_score", None),
            "risk_level": getattr(getattr(trust, "risk_level", None), "value", None),
            "audit_events_count": len(audit_events)
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
