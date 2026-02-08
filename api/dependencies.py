from fastapi import HTTPException
from typing import Optional

from core.agentic_iam import AgenticIAM
from config.settings import Settings


async def get_iam() -> AgenticIAM:
    """Dependency to return the global IAM instance from api.main lazily."""
    from api import main

    iam = getattr(main, "iam_instance", None)
    if not iam:
        raise HTTPException(status_code=503, detail="IAM system not initialized")
    return iam


async def get_settings() -> Settings:
    """Dependency to return the global Settings instance from api.main lazily."""
    from api import main

    settings = getattr(main, "settings_instance", None)
    if not settings:
        raise HTTPException(status_code=503, detail="Settings not initialized")
    return settings
