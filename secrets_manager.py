"""Secrets manager abstraction supporting Azure Key Vault and HashiCorp Vault (optional).
This module provides a safe wrapper used by the app to fetch secrets at runtime.
"""

import os
from typing import Optional

_impl = None

if os.getenv("USE_AZURE_KEYVAULT", "false").lower() == "true":
    try:
        from azure.identity import DefaultAzureCredential
        from azure.keyvault.secrets import SecretClient

        class AzureKeyVaultManager:
            def __init__(self):
                vault_url = os.getenv("AZURE_KEYVAULT_URL")
                self._client = SecretClient(vault_url=vault_url, credential=DefaultAzureCredential())

            def get_secret(self, name: str) -> Optional[str]:
                try:
                    return self._client.get_secret(name).value
                except Exception as e:
                    import logging

                    logging.getLogger(__name__).debug("AzureKeyVault get_secret failed: %s", e)
                    return None

        _impl = AzureKeyVaultManager()
    except ImportError:
        _impl = None

elif os.getenv("USE_HASHICORP_VAULT", "false").lower() == "true":
    try:
        import hvac

        class HashiCorpVaultManager:
            def __init__(self):
                url = os.getenv("VAULT_ADDR")
                token = os.getenv("VAULT_TOKEN")
                self._client = hvac.Client(url=url, token=token)

            def get_secret(self, name: str) -> Optional[str]:
                try:
                    resp = self._client.secrets.kv.v2.read_secret_version(path=name)
                    return resp["data"]["data"].get("value")
                except Exception as e:
                    import logging

                    logging.getLogger(__name__).debug("HashiCorp Vault get_secret failed: %s", e)
                    return None

        _impl = HashiCorpVaultManager()
    except ImportError:
        _impl = None


def get_secret(name: str) -> Optional[str]:
    if _impl:
        return _impl.get_secret(name)
    # Fallback to environment variable
    return os.getenv(name)
