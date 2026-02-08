"""Agentic-IAM: Configuration Settings

Lightweight settings object used by tests and application startup.
"""
import os
from typing import Optional, Dict, Any, List
from pathlib import Path


class Settings:
    """Configuration for the Agentic-IAM platform.

    Accepts optional keyword overrides so tests can instantiate with custom
    values (e.g., `Settings(environment='testing', debug=True, ...)`).
    """

    def __init__(self, **overrides):
        # Environment
        self.environment: str = overrides.get("environment", os.getenv("ENVIRONMENT", "development"))
        self.debug: bool = overrides.get("debug", os.getenv("DEBUG", "false").lower() == "true")

        # API
        self.api_host: str = overrides.get("api_host", os.getenv("API_HOST", "127.0.0.1"))
        self.api_port: int = int(overrides.get("api_port", os.getenv("API_PORT", "8000")))
        self.auto_reload: bool = overrides.get("auto_reload", False)

        # CORS
        self.enable_cors: bool = overrides.get("enable_cors", True)
        self.cors_origins: List[str] = overrides.get("cors_origins", ["http://localhost:3000", "http://localhost:8501"])

        # Logging
        self.log_level: str = overrides.get("log_level", os.getenv("LOG_LEVEL", "INFO"))
        self.log_file: Optional[str] = overrides.get("log_file", "./logs/agentic_iam.log")

        # Security
        self.require_tls: bool = overrides.get("require_tls", False)
        self.secret_key: str = overrides.get("secret_key", os.getenv("SECRET_KEY", "your-secret-key-change-in-production"))
        self.encryption_key: str = overrides.get("encryption_key", os.getenv("ENCRYPTION_KEY", "your-encryption-key-32-chars-long!"))
        # TLS / mTLS
        self.enable_mtls: bool = overrides.get("enable_mtls", False)

        # Session defaults
        self.session_ttl: int = int(overrides.get("session_ttl", 3600))

        # Authentication features
        self.enable_mfa: bool = overrides.get("enable_mfa", False)
        self.mfa_required_factors: int = overrides.get("mfa_required_factors", 2)

        # Federated authentication
        self.enable_federated_auth: bool = overrides.get("enable_federated_auth", False)
        self.oidc_client_id: Optional[str] = overrides.get("oidc_client_id", None)
        self.oidc_client_secret: Optional[str] = overrides.get("oidc_client_secret", None)
        self.oidc_discovery_url: Optional[str] = overrides.get("oidc_discovery_url", None)

        # Audit & tracing
        self.enable_audit_logging: bool = overrides.get("enable_audit_logging", True)

        # File paths
        self.agent_registry_path: str = overrides.get("agent_registry_path", "./data/agent_registry")
        self.credential_storage_path: str = overrides.get("credential_storage_path", "./data/credentials")
        self.credential_encryption_key: str = overrides.get("credential_encryption_key", self.encryption_key)
        self.audit_log_path: str = overrides.get("audit_log_path", "./logs/audit.log")

        # Feature flags
        self.enable_trust_scoring: bool = overrides.get("enable_trust_scoring", True)

        # Misc defaults
        self.enable_prometheus: bool = overrides.get("enable_prometheus", False)

        # Ensure directories exist
        self._create_directories()

    def _create_directories(self):
        directories = [
            Path(self.agent_registry_path),
            Path(self.credential_storage_path),
            Path(self.audit_log_path).parent,
            Path(self.log_file).parent if self.log_file else None,
        ]
        for directory in directories:
            if directory:
                directory.mkdir(parents=True, exist_ok=True)

    @property
    def is_production(self) -> bool:
        return self.environment == "production"


# Convenience factory used in codebase
_default_settings: Optional[Settings] = None


def get_settings() -> Settings:
    global _default_settings
    if _default_settings is None:
        _default_settings = Settings()
    return _default_settings


# Module-level settings instance for quick imports
settings = get_settings()