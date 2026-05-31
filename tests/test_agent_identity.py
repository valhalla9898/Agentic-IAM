import base64
import hmac
import hashlib

from agent_identity import AgentIdentity


def test_hmac_verification_fallback():
    identity = AgentIdentity("agent-test")
    # Use a simple symmetric key (public_key) for HMAC path
    key = "my_shared_secret_key_12345"
    message = "important-message"

    expected_sig = base64.b64encode(
        hmac.new(key.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).digest()
    ).decode("utf-8")

    assert identity.verify_message(message, expected_sig, public_key=key)


def test_generate_identity_has_keys_or_placeholders():
    identity = AgentIdentity.generate("agent-42")
    pub = identity.get_public_key()
    priv = identity.get_private_key()

    assert isinstance(pub, str) and len(pub) > 0
    assert isinstance(priv, str) and len(priv) > 0
