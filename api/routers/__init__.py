"""Sessions router stub"""
from fastapi import APIRouter

router = APIRouter()

@router.get("/")
async def list_sessions():
    """List sessions"""
    return []
