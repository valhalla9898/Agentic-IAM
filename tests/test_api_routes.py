import asyncio

import pytest

from api import main as api_main


@pytest.mark.asyncio
async def test_root_and_api_info_direct_call():
    # Call the endpoint coroutines directly to avoid app startup side-effects
    root_resp = await api_main.root()
    assert isinstance(root_resp, dict)
    assert root_resp.get("name") == "Agentic-IAM API"

    info = await api_main.api_info()
    assert isinstance(info, dict)
    assert info.get("version") == "1.0.0"
    assert "agents" in info.get("endpoints", {})
