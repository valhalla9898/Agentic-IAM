"""Agentic-IAM: Authorization API Router."""

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from core.agentic_iam import AgenticIAM
from api.dependencies import get_iam

router = APIRouter()


class AuthorizationRequest(BaseModel):
    agent_id: str
    resource: str
    action: str
    context: Optional[Dict[str, Any]] = None


class AuthorizationResponse(BaseModel):
    agent_id: str
    resource: str
    action: str
    allow: bool
    decision: str
    reason: Optional[str] = None


@router.post("/authorize", response_model=AuthorizationResponse)
async def authorize_action(
    request: AuthorizationRequest,
    iam: AgenticIAM = Depends(get_iam),
):
    """Make an authorization decision for an agent action."""
    try:
        allowed = await iam.authorize(
            agent_id=request.agent_id,
            resource=request.resource,
            action=request.action,
            context=request.context or {},
        )
        return AuthorizationResponse(
            agent_id=request.agent_id,
            resource=request.resource,
            action=request.action,
            allow=allowed,
            decision="allow" if allowed else "deny",
            reason="authorized" if allowed else "permission denied",
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Authorization error: {exc}")
