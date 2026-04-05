"""Health and monitoring endpoints"""
from fastapi import APIRouter, Depends
from datetime import datetime
from typing import Dict, Any

from core.agentic_iam import AgenticIAM
from api.dependencies import get_iam, get_settings

router = APIRouter()


@router.get("/", tags=["Health"])
async def health_check(iam: AgenticIAM = Depends(get_iam)) -> Dict[str, Any]:
    """Health check endpoint"""
    try:
        status = await iam.get_platform_status()
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "platform_status": status
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }


@router.get("/ready", tags=["Health"])
async def readiness_check(iam: AgenticIAM = Depends(get_iam)) -> Dict[str, Any]:
    """Readiness check endpoint"""
    try:
        is_initialized = getattr(iam, 'is_initialized', False)
        return {
            "ready": is_initialized,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        return {
            "ready": False,
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }


@router.get("/live", tags=["Health"])
async def liveness_check() -> Dict[str, Any]:
    """Liveness check endpoint"""
    return {
        "alive": True,
        "timestamp": datetime.utcnow().isoformat()
    }
