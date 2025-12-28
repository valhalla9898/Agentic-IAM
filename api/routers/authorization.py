"""Agentic-IAM: Authorization API Router (Simplified)"""
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional, Dict, Any

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
    reason: Optional[str] = None

@router.post("/authorize", response_model=AuthorizationResponse)
async def authorize_action(request: AuthorizationRequest):
    """Make an authorization decision for an agent action"""
    return AuthorizationResponse(
        agent_id=request.agent_id,
        resource=request.resource,
        action=request.action,
        allow=True,
        reason="authorized"
    )
