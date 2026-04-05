"""Agentic-IAM: Configuration Settings

Lightweight settings object used by tests and application startup.
"""
import os
from typing import Optional, List
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
        # mTLS configuration
        self.mtls_cert_path: Optional[str] = overrides.get("mtls_cert_path", os.getenv("MTLS_CERT_PATH", None))
        self.mtls_key_path: Optional[str] = overrides.get("mtls_key_path", os.getenv("MTLS_KEY_PATH", None))
        # endpoints that require mTLS (path prefixes)
        self.mtls_required_endpoints: List[str] = overrides.get("mtls_required_endpoints", ["/api/admin", "/api/operator"])

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
        self.enable_anomaly_detection: bool = overrides.get("enable_anomaly_detection", True)

        # Admin / signing keys
        # Optional admin API key for protecting admin endpoints and alerts.
        self.admin_api_key: Optional[str] = overrides.get("admin_api_key", os.getenv("ADMIN_API_KEY", None))
        # Key used to sign static report URLs. Defaults to the admin key when not provided.
        self.static_url_signing_key: Optional[str] = overrides.get(
            "static_url_signing_key", os.getenv("STATIC_URL_SIGNING_KEY", self.admin_api_key)
        )

        # Misc defaults
        self.enable_prometheus: bool = overrides.get("enable_prometheus", False)

        # Ensure directories exist
        self._create_directories()
        self._validate()

    def _validate(self):
        allowed_envs = {"development", "testing", "staging", "production"}
        if self.environment not in allowed_envs:
            raise ValueError(f"Invalid environment: {self.environment}")

        allowed_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if str(self.log_level).upper() not in allowed_levels:
            raise ValueError(f"Invalid log level: {self.log_level}")

        if not isinstance(self.encryption_key, str) or len(self.encryption_key) < 16:
            raise ValueError("encryption_key must be at least 16 characters")

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

        # Attempt to load sensitive secrets from a secret manager (vault/env/local file)
        # This is a best-effort, non-fatal operation so tests/local runs are unaffected.
        try:
            from secrets.key_vault import secret_manager
            sm = secret_manager
            _sk = sm.get_secret("SECRET_KEY")
            if _sk:
                self.secret_key = _sk
            _ek = sm.get_secret("ENCRYPTION_KEY")
            if _ek:
                self.encryption_key = _ek
                self.credential_encryption_key = _ek
            # Optional OIDC secret
            _oidc = sm.get_secret("OIDC_CLIENT_SECRET")
            if _oidc:
                self.oidc_client_secret = _oidc
        except Exception:
            # Silent fallback to environment or defaults
            pass

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
