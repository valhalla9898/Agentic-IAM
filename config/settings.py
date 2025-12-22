"""
Agentic-IAM: Configuration Settings

Comprehensive configuration management
"""
import os
from typing import Optional, Dict, Any
from pathlib import Path


class Settings:
    """Configuration for the Agentic-IAM platform"""
    
    def __init__(self):
        # Environment Configuration
        self.environment = os.getenv("ENVIRONMENT", "development")
        self.debug = os.getenv("DEBUG", "false").lower() == "true"
        
        # Core Platform Settings
        self.platform_name = "Agentic-IAM"
        self.platform_version = "1.0.0"
        
        # API Server Configuration
        self.api_host = os.getenv("API_HOST", "127.0.0.1")
        self.api_port = int(os.getenv("API_PORT", "8000"))
        self.api_workers = int(os.getenv("API_WORKERS", "1"))
        self.enable_api = True
        
        # Dashboard Configuration
        self.dashboard_host = os.getenv("DASHBOARD_HOST", "127.0.0.1")
        self.dashboard_port = int(os.getenv("DASHBOARD_PORT", "8501"))
        self.enable_dashboard = True
        
        # Database Configuration
        self.database_url = os.getenv("DATABASE_URL", "sqlite:///./agentic_iam.db")
        self.database_echo = False
        
        # Redis Configuration
        self.redis_url = os.getenv("REDIS_URL")
        self.redis_password = os.getenv("REDIS_PASSWORD")
        self.redis_db = int(os.getenv("REDIS_DB", "0"))
        
        # Logging Configuration
        self.log_level = os.getenv("LOG_LEVEL", "INFO")
        self.log_file = "./logs/agentic_iam.log"
        self.enable_json_logging = False
        
        # Security Configuration
        self.secret_key = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
        self.encryption_key = os.getenv("ENCRYPTION_KEY", "your-encryption-key-32-chars-long!")
        
        # JWT Configuration
        self.jwt_secret_key = os.getenv("JWT_SECRET_KEY", "jwt-secret-key-change-in-production")
        self.jwt_algorithm = "HS256"
        self.jwt_token_ttl = 3600
        self.jwt_refresh_ttl = 604800
        
        # Session Configuration
        self.session_ttl = 3600
        self.max_sessions_per_agent = 5
        self.session_cleanup_interval = 300
        
        # Authentication Configuration
        self.enable_mfa = os.getenv("ENABLE_MFA", "false").lower() == "true"
        self.mfa_required_factors = 2
        self.enable_mtls = os.getenv("ENABLE_MTLS", "false").lower() == "true"
        self.mtls_ca_cert_path = None
        self.mtls_cert_path = None
        self.mtls_key_path = None
        
        # Federated Authentication
        self.enable_federated_auth = False
        self.oidc_client_id = None
        self.oidc_client_secret = None
        self.oidc_discovery_url = None
        
        # Authorization Configuration
        self.enable_rbac = True
        self.enable_abac = True
        self.enable_pbac = False
        self.authorization_cache_ttl = 300
        
        # Trust Scoring & Intelligence
        self.enable_trust_scoring = True
        self.enable_anomaly_detection = True
        self.enable_behavioral_analysis = True
        self.trust_score_update_interval = 3600
        self.anomaly_threshold = 0.8
        
        # Audit & Compliance
        self.enable_audit_logging = True
        self.enable_audit_integrity = True
        self.audit_retention_days = 365
        self.audit_log_path = "./logs/audit.log"
        
        # Data Storage
        self.agent_registry_path = "./data/agent_registry"
        self.credential_storage_path = "./data/credentials"
        self.credential_encryption_key = self.encryption_key
        
        # Monitoring
        self.enable_metrics = True
        self.metrics_port = 9090
        self.enable_prometheus = True
        
        # Create necessary directories
        self._create_directories()
    
    def _create_directories(self):
        """Create necessary directories"""
        directories = [
            Path(self.agent_registry_path),
            Path(self.credential_storage_path),
            Path(self.audit_log_path).parent,
            Path(self.log_file).parent if self.log_file else None
        ]
        for directory in directories:
            if directory:
                directory.mkdir(parents=True, exist_ok=True)


# Create default settings instance
_default_settings = None

def get_settings():
    global _default_settings
    if _default_settings is None:
        _default_settings = Settings()
    return _default_settings
    """
    Comprehensive settings for the Agentic-IAM platform
    
    Supports environment variables, .env files, and validation
    """
    
    # Environment Configuration
    environment: str = "development"
    debug: bool = False
    
    # Core Platform Settings
    platform_name: str = "Agentic-IAM"
    platform_version: str = "1.0.0"
    
    # API Server Configuration
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    api_workers: int = 1
    enable_api: bool = True
    
    # Dashboard Configuration
    dashboard_host: str = "127.0.0.1"
    dashboard_port: int = 8501
    enable_dashboard: bool = True
    
    # Database Configuration
    database_url: str = "sqlite:///./agentic_iam.db"
    database_echo: bool = False
    
    # Redis Configuration (for production session storage)
    redis_url: Optional[str] = None
    redis_password: Optional[str] = None
    redis_db: int = 0
    
    # Logging Configuration
    log_level: str = "INFO"
    log_file: Optional[str] = "./logs/agentic_iam.log"
    enable_json_logging: bool = False
    
    # Security Configuration
    secret_key: str = "your-secret-key-change-in-production"
    encryption_key: str = "your-encryption-key-32-chars-long!"
    
    # JWT Configuration
    jwt_secret_key: str = "jwt-secret-key-change-in-production"
    jwt_algorithm: str = "HS256"
    jwt_token_ttl: int = 3600  # 1 hour
    jwt_refresh_ttl: int = 604800  # 7 days
    
    # Session Configuration
    session_ttl: int = 3600  # 1 hour
    max_sessions_per_agent: int = 5
    session_cleanup_interval: int = 300  # 5 minutes
    
    # Authentication Configuration
    enable_mfa: bool = False
    mfa_required_factors: int = 2
    enable_mtls: bool = False
    mtls_ca_cert_path: Optional[str] = None
    mtls_cert_path: Optional[str] = None
    mtls_key_path: Optional[str] = None
    
    # Federated Authentication
    enable_federated_auth: bool = False
    oidc_client_id: Optional[str] = None
    oidc_client_secret: Optional[str] = None
    oidc_discovery_url: Optional[str] = None
    saml_entity_id: Optional[str] = None
    saml_metadata_url: Optional[str] = None
    
    # Authorization Configuration
    enable_rbac: bool = True
    enable_abac: bool = True
    enable_pbac: bool = False
    authorization_cache_ttl: int = 300  # 5 minutes
    
    # Trust Scoring & Intelligence
    enable_trust_scoring: bool = True
    enable_anomaly_detection: bool = True
    enable_behavioral_analysis: bool = True
    trust_score_update_interval: int = 3600  # 1 hour
    anomaly_threshold: float = 0.8
    
    # Audit & Compliance
    enable_audit_logging: bool = True
    enable_audit_integrity: bool = True
    audit_log_path: str = "./logs/audit.log"
    audit_retention_days: int = 365
    compliance_frameworks: List[str] = ["gdpr", "hipaa", "sox"]
    
    # Rate Limiting
    rate_limit_enabled: bool = True
    rate_limit_requests_per_minute: int = 100
    rate_limit_burst_size: int = 200
    
    # Storage Paths
    agent_registry_path: str = "./data/agents"
    credential_storage_path: str = "./data/credentials"
    audit_storage_path: str = "./data/audit"
    
    # Credential Management
    credential_encryption_key: str = "credential-encryption-key-32-chars!"
    credential_rotation_interval: int = 2592000  # 30 days
    enable_credential_backup: bool = True
    
    # Transport Security
    require_tls: bool = False
    tls_cert_path: Optional[str] = None
    tls_key_path: Optional[str] = None
    enable_transport_encryption: bool = True
    
    # Feature Flags
    enable_experimental_features: bool = False
    enable_debug_endpoints: bool = False
    enable_metrics: bool = True
    enable_health_checks: bool = True
    
    # Monitoring & Metrics
    metrics_endpoint: str = "/metrics"
    health_endpoint: str = "/health"
    prometheus_enabled: bool = False
    prometheus_port: int = 9090
    
    # Development Settings
    auto_reload: bool = False
    enable_cors: bool = True
    cors_origins: List[str] = ["http://localhost:3000", "http://localhost:8501"]
    
    # Email Configuration (for notifications)
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_use_tls: bool = True
    
    # Cloud Configuration (for deployment)
    cloud_provider: Optional[str] = None  # aws, azure, gcp
    cloud_region: Optional[str] = None
    cloud_storage_bucket: Optional[str] = None
    
    # Machine Learning Configuration
    ml_model_path: Optional[str] = "./models"
    enable_gpu: bool = False
    ml_batch_size: int = 32
    ml_update_frequency: int = 86400  # 24 hours
    
    @validator('environment')
    def validate_environment(cls, v):
        allowed = ['development', 'testing', 'staging', 'production']
        if v not in allowed:
            raise ValueError(f'Environment must be one of: {allowed}')
        return v
    
    @validator('log_level')
    def validate_log_level(cls, v):
        allowed = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if v.upper() not in allowed:
            raise ValueError(f'Log level must be one of: {allowed}')
        return v.upper()
    
    @validator('encryption_key')
    def validate_encryption_key(cls, v):
        if len(v) != 32:
            raise ValueError('Encryption key must be exactly 32 characters long')
        return v
    
    @validator('credential_encryption_key')
    def validate_credential_encryption_key(cls, v):
        if len(v) != 32:
            raise ValueError('Credential encryption key must be exactly 32 characters long')
        return v
    
    @validator('mfa_required_factors')
    def validate_mfa_factors(cls, v):
        if v < 2 or v > 5:
            raise ValueError('MFA required factors must be between 2 and 5')
        return v
    
    @validator('anomaly_threshold')
    def validate_anomaly_threshold(cls, v):
        if v < 0.0 or v > 1.0:
            raise ValueError('Anomaly threshold must be between 0.0 and 1.0')
        return v
    
    @property
    def is_production(self) -> bool:
        return self.environment == "production"
    
    @property
    def is_development(self) -> bool:
        return self.environment == "development"
    
    @property
    def database_async_url(self) -> str:
        """Get async database URL for SQLAlchemy"""
        if self.database_url.startswith("sqlite"):
            return self.database_url.replace("sqlite://", "sqlite+aiosqlite://")
        elif self.database_url.startswith("postgresql"):
            return self.database_url.replace("postgresql://", "postgresql+asyncpg://")
        elif self.database_url.startswith("mysql"):
            return self.database_url.replace("mysql://", "mysql+aiomysql://")
        return self.database_url
    
    def get_redis_config(self) -> Dict[str, Any]:
        """Get Redis configuration dictionary"""
        if not self.redis_url:
            return {}
        
        return {
            "url": self.redis_url,
            "password": self.redis_password,
            "db": self.redis_db,
            "decode_responses": True
        }
    
    def get_smtp_config(self) -> Dict[str, Any]:
        """Get SMTP configuration dictionary"""
        return {
            "host": self.smtp_host,
            "port": self.smtp_port,
            "username": self.smtp_username,
            "password": self.smtp_password,
            "use_tls": self.smtp_use_tls
        }
    
    def create_directories(self):
        """Create necessary directories"""
        directories = [
            Path(self.log_file).parent if self.log_file else None,
            Path(self.agent_registry_path),
            Path(self.credential_storage_path),
            Path(self.audit_storage_path),
            Path(self.ml_model_path) if self.ml_model_path else None
        ]
        
        for directory in directories:
            if directory:
                directory.mkdir(parents=True, exist_ok=True)
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
        
        # Environment variable prefix
        env_prefix = "AGENTIC_IAM_"
        
        # Example environment variables:
        # AGENTIC_IAM_ENVIRONMENT=production
        # AGENTIC_IAM_API_HOST=0.0.0.0
        # AGENTIC_IAM_DATABASE_URL=postgresql://user:pass@localhost/db
        # AGENTIC_IAM_ENABLE_MFA=true


# Global settings instance
settings = Settings()

# Create necessary directories on import
settings._create_directories()