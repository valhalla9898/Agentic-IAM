"""Secrets manager scaffold supporting Azure Key Vault and local fallback.

This module provides a minimal, safe scaffold for retrieving secrets from
an external vault. It will lazily import cloud SDKs so the repository does
not require cloud SDKs unless used in production.

Usage:
    from secrets.key_vault import SecretManager
    sm = SecretManager()
    secret = sm.get_secret("DB_PASSWORD")
"""
from typing import Optional
import os


class SecretManager:
    def __init__(self):
        # Detect available providers via env vars
        self.azure_vault_url = os.getenv("AZURE_KEYVAULT_URL")
        self.aws_kms_configured = bool(os.getenv("AWS_ACCESS_KEY_ID"))

    def get_secret(self, name: str) -> Optional[str]:
        """Return secret value by name.

        Priority: Azure Key Vault (if configured) -> environment variable -> local file fallback
        """
        # 1) Try Azure Key Vault
        if self.azure_vault_url:
            try:
                from azure.identity import DefaultAzureCredential
                from azure.keyvault.secrets import SecretClient

                credential = DefaultAzureCredential()
                client = SecretClient(vault_url=self.azure_vault_url, credential=credential)
                secret = client.get_secret(name)
                return secret.value
            except Exception:
                # silent fallback to other sources
                pass

        # 2) Environment variable
        env_val = os.getenv(name)
        if env_val:
            return env_val

        # 3) Local file fallback: ./secrets/{name}
        local_path = os.path.join(os.path.dirname(__file__), "..", "data", "secrets", name)
        try:
            with open(local_path, "r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception:
            return None


secret_manager = SecretManager()
