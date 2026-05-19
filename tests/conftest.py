"""Test fixtures for environment-driven test cases."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_VARS_JSON = PROJECT_ROOT / "env_vars.json"
ENV_EXAMPLE = PROJECT_ROOT / ".env.example"


def _load_env_example() -> dict:
    values: dict[str, str] = {}
    if not ENV_EXAMPLE.exists():
        return values

    for line in ENV_EXAMPLE.read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def _load_env_vars() -> dict:
    if ENV_VARS_JSON.exists():
        try:
            return json.loads(ENV_VARS_JSON.read_text(encoding="utf-8"))
        except Exception:
            pass

    values = _load_env_example()
    for key in list(values.keys()):
        values[key] = os.getenv(key, values[key])
    return values


@pytest.fixture(scope="session")
def env_vars() -> dict:
    """Return environment variables for tests that expect a JSON-like config payload."""
    return _load_env_vars()
