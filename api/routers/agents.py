"""Agent management endpoints"""
from fastapi import APIRouter, Depends, HTTPException
import re
from pydantic import BaseModel, field_validator
from typing import Optional, List, Dict, Any

from core.agentic_iam import AgenticIAM
from agent_identity import AgentIdentity
from api.dependencies import get_iam

router = APIRouter()


class AgentRegisterRequest(BaseModel):
    agent_id: str
    agent_type: str
    description: Optional[str] = None
    capabilities: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None
    initial_permissions: Optional[List[str]] = None

    @field_validator("agent_id")
    @classmethod
    def validate_agent_id(cls, value: str) -> str:
        if not value.startswith("agent:"):
            raise ValueError('Agent ID must start with "agent:"')
        if not re.match(r"^agent:[A-Za-z0-9._:-]+$", value):
            raise ValueError("Agent ID contains invalid characters")
        return value


class AgentResponse(BaseModel):
    agent_id: str
    status: str
    created_at: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


@router.post("/", status_code=201, tags=["Agent Management"])
async def register_agent(
    payload: AgentRegisterRequest,
    iam: AgenticIAM = Depends(get_iam)
) -> AgentResponse:
    """Register a new agent"""
    try:
        # Create identity
        metadata = payload.metadata or {}
        metadata["agent_type"] = payload.agent_type
        if payload.description:
            metadata["description"] = payload.description
        if payload.capabilities:
            metadata["capabilities"] = payload.capabilities

        identity = AgentIdentity.generate(payload.agent_id, metadata)

        # Register in IAM system
        await iam.register_agent(
            identity,
            initial_permissions=payload.initial_permissions
        )

        return AgentResponse(
            agent_id=payload.agent_id,
            status="active",
            metadata=metadata
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to register agent: {str(e)}")


@router.get("/{agent_id}", tags=["Agent Management"])
async def get_agent(
    agent_id: str,
    iam: AgenticIAM = Depends(get_iam)
) -> Dict[str, Any]:
    """Get agent details"""
    try:
        agent_entry = iam.agent_registry.get_agent(agent_id)
        if not agent_entry:
            raise HTTPException(status_code=404, detail="Agent not found")

        return {
            "agent_id": agent_id,
            "status": "active",
            "metadata": getattr(agent_entry, 'metadata', {})
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/{agent_id}", tags=["Agent Management"])
async def delete_agent(
    agent_id: str,
    iam: AgenticIAM = Depends(get_iam)
) -> Dict[str, str]:
    """Delete an agent"""
    try:
        if not iam.agent_registry.get_agent(agent_id):
            raise HTTPException(status_code=404, detail="Agent not found")

        result = iam.delete_agent(agent_id)

        return {
            "status": "deleted",
            "agent_id": agent_id,
            "sessions_terminated": str(result.get("sessions_terminated", 0)),
            "registry_deleted": str(result.get("registry_deleted", False))
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/", tags=["Agent Management"])
async def list_agents(
    iam: AgenticIAM = Depends(get_iam)
) -> Dict[str, Any]:
    """List all registered agents"""
    try:
        agents = iam.agent_registry.list_agents()
        return {
            "agents": [agent.agent_id for agent in agents],
            "count": len(agents)
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
