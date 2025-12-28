from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional

router = APIRouter()

class MobileRegisterRequest(BaseModel):
    agent_name: str
    platform: Optional[str] = "mobile"

class MobileHeartbeat(BaseModel):
    agent_id: str
    timestamp: Optional[str]

@router.post("/register")
async def mobile_register(req: MobileRegisterRequest):
    # Create a lightweight agent entry for mobile client
    from agent_identity import AgentIdentity
    agent_id = f"agent_mobile_{req.agent_name}_{hash(req.agent_name) & 0xffffffff:x}"
    identity = AgentIdentity.generate(agent_id=agent_id, metadata={"platform": req.platform})
    return {"agent_id": agent_id, "registration_id": f"reg_{agent_id}"}

@router.post("/heartbeat")
async def heartbeat(hb: MobileHeartbeat):
    # Simple heartbeat that acknowledges the request
    return {"status": "ok", "agent_id": hb.agent_id}
