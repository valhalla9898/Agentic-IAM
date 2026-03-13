import os
import importlib
import hmac
import hashlib
import time
from fastapi.testclient import TestClient


def reload_app_with_env(env):
    for k, v in env.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    import config.settings as settingsmod
    importlib.reload(settingsmod)
    import api.app as appmod
    importlib.reload(appmod)
    return appmod.app


def test_signed_static_url_allows_valid_signature():
    key = "testsignkey"
    app = reload_app_with_env({"STATIC_URL_SIGNING_KEY": key, "ADMIN_API_KEY": None})
    client = TestClient(app)

    path = "/reports/static/fake/doesnotexist.html"
    exp = int(time.time()) + 3600
    msg = f"{path}|{exp}".encode("utf-8")
    sig = hmac.new(key.encode("utf-8"), msg, hashlib.sha256).hexdigest()

    r = client.get(f"{path}?expires={exp}&sig={sig}")
    # File won't exist, but signature should pass, resulting in 404
    assert r.status_code in (200, 404)


def test_signed_static_url_rejects_invalid_signature():
    key = "testsignkey"
    app = reload_app_with_env({"STATIC_URL_SIGNING_KEY": key, "ADMIN_API_KEY": None})
    client = TestClient(app)

    path = "/reports/static/fake/doesnotexist.html"
    exp = int(time.time()) + 3600
    # wrong sig
    sig = "deadbeef"

    r = client.get(f"{path}?expires={exp}&sig={sig}")
    assert r.status_code == 401
