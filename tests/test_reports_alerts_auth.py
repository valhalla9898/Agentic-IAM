import os
import importlib
from fastapi.testclient import TestClient


def reload_app_with_env(env):
    # apply environment variables, reload the app module to pick them up
    for k, v in env.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    # reload config.settings first so Settings picks up env changes
    import config.settings as settingsmod
    importlib.reload(settingsmod)
    import api.app as appmod
    importlib.reload(appmod)
    return appmod.app


def test_protected_endpoints_require_api_key(monkeypatch):
    # set admin key then reload app
    app = reload_app_with_env({"ADMIN_API_KEY": "testkey"})
    client = TestClient(app)

    # without header -> unauthorized
    r = client.get("/alerts/list")
    assert r.status_code == 401

    # with wrong header -> unauthorized
    r = client.get("/alerts/list", headers={"x-api-key": "wrong"})
    assert r.status_code == 401

    # with correct header -> allowed
    r = client.get("/alerts/list", headers={"x-api-key": "testkey"})
    assert r.status_code == 200


def test_unprotected_when_no_admin_key(monkeypatch):
    # ensure ADMIN_API_KEY not set
    app = reload_app_with_env({"ADMIN_API_KEY": None})
    client = TestClient(app)

    # should be accessible without API key
    r = client.get("/alerts/list")
    assert r.status_code == 200
