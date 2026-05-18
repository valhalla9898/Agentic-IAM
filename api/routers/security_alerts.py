"""Security alerts and attack response router."""
from datetime import datetime
from typing import Optional, List
from fastapi import APIRouter, HTTPException, Depends, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel

router = APIRouter(prefix="/alerts", tags=["security"])

# Dependency to get DB session (will be configured in main app)
def get_db() -> Session:
    """Get database session - override in main app."""
    raise NotImplementedError("get_db must be configured in main app")


class AttackEventResponse(BaseModel):
    id: int
    attack_type: str
    source_ip: str
    severity: str
    detected_at: datetime
    status: str
    description: Optional[str]

    class Config:
        from_attributes = True


class SecurityAlertResponse(BaseModel):
    id: int
    alert_type: str
    title: str
    message: str
    severity: str
    source_ip: Optional[str]
    is_resolved: bool
    created_at: datetime

    class Config:
        from_attributes = True


@router.get("/active", response_model=List[SecurityAlertResponse])
async def get_active_alerts(db: Session = Depends(get_db)):
    """Get all active (unresolved) security alerts."""
    from core.db import SecurityAlert
    alerts = db.query(SecurityAlert).filter(SecurityAlert.is_resolved == False).order_by(
        SecurityAlert.created_at.desc()
    ).all()
    return alerts


@router.get("/recent", response_model=List[SecurityAlertResponse])
async def get_recent_alerts(limit: int = 10, db: Session = Depends(get_db)):
    """Get recent security alerts."""
    from core.db import SecurityAlert
    alerts = db.query(SecurityAlert).order_by(
        SecurityAlert.created_at.desc()
    ).limit(limit).all()
    return alerts


@router.get("/attacks", response_model=List[AttackEventResponse])
async def get_attack_events(db: Session = Depends(get_db)):
    """Get all detected attack events."""
    from core.db import AttackEvent
    events = db.query(AttackEvent).order_by(
        AttackEvent.detected_at.desc()
    ).all()
    return events


@router.get("/blocked-ips")
async def get_blocked_ips(db: Session = Depends(get_db)):
    """Get list of currently blocked IPs."""
    from core.db import BlockedIP
    blocked = db.query(BlockedIP).filter(BlockedIP.is_active == True).all()
    return [{"ip": b.ip_address, "reason": b.reason, "blocked_at": b.blocked_at} for b in blocked]


@router.post("/alerts/{alert_id}/resolve")
async def resolve_alert(alert_id: int, db: Session = Depends(get_db)):
    """Mark an alert as resolved."""
    from core.db import SecurityAlert
    alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.is_resolved = True
    alert.resolved_at = datetime.utcnow()
    db.commit()
    return {"status": "resolved", "alert_id": alert_id}


@router.post("/attacks/{attack_id}/block-ip")
async def block_attacker_ip(attack_id: int, duration_seconds: Optional[int] = None, db: Session = Depends(get_db)):
    """Block the IP address of a detected attack."""
    from core.db import AttackEvent, BlockedIP
    from core.attack_detection import AttackLogger

    attack = db.query(AttackEvent).filter(AttackEvent.id == attack_id).first()
    if not attack:
        raise HTTPException(status_code=404, detail="Attack not found")

    # Block the IP
    block = AttackLogger.block_ip(
        db,
        ip=attack.source_ip,
        reason=f"Blocked due to {attack.attack_type}",
        duration_seconds=duration_seconds,
        attack_event_id=attack_id
    )

    attack.status = 'blocked'
    db.commit()

    return {
        "status": "blocked",
        "ip": attack.source_ip,
        "expires_at": block.expires_at
    }
