from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from ..main import get_iam
from typing import Optional

router = APIRouter()

class MobileRegisterRequest(BaseModel):
    agent_name: str
    platform: Optional[str] = "mobile"

class MobileHeartbeat(BaseModel):
    agent_id: str
    timestamp: Optional[str]

@router.post("/register")
async def mobile_register(req: MobileRegisterRequest, iam=Depends(get_iam)):
    # Create a lightweight agent entry for mobile client
    from agent_identity import AgentIdentity
    agent_id = f"agent_mobile_{req.agent_name}_{hash(req.agent_name) & 0xffffffff:x}"
    identity = AgentIdentity.generate(agent_id=agent_id, metadata={"platform": req.platform})
    reg_id = await iam.register_agent(identity)
    return {"agent_id": agent_id, "registration_id": reg_id}

@router.post("/heartbeat")
async def heartbeat(hb: MobileHeartbeat, iam=Depends(get_iam)):
    # Simple heartbeat that logs an audit event
    await iam.audit_manager.log_event("heartbeat", agent_id=hb.agent_id, details={"timestamp": hb.timestamp})
    return {"status": "ok", "agent_id": hb.agent_id}
