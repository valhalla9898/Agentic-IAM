"""
Pytest configuration and shared fixtures for Agentic-IAM tests
"""
import asyncio
import pytest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime, timedelta
import sys

# Add project modules to path
sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi.testclient import TestClient
from core.agentic_iam import AgenticIAM
from config.settings import Settings
from api.main import app
try:
    from secrets.key_vault import secret_manager
except Exception:
    class _Shim:
        def get_secret(self, name):
            return None

    secret_manager = _Shim()


    def pytest_collection_modifyitems(config, items):
        """Deselect end-to-end Playwright tests by default.

        Set the environment variable `RUN_E2E=1` to include `tests/e2e/*` tests.
        This avoids requiring heavy browser deps during quick local runs.
        """
        import os
        run_e2e = os.getenv("RUN_E2E")
        if run_e2e:
            return
        remove = []
        for item in list(items):
            p = str(item.fspath).replace("\\", "/")
            if "/tests/e2e/" in p or p.endswith("/tests/e2e"):
                items.remove(item)


    def pytest_ignore_collect(collection_path, config):
        """Prevent pytest from importing files under tests/e2e unless RUN_E2E is set.

        Uses the newer `collection_path` parameter name to avoid pytest deprecation warnings.
        """
        import os
        p = str(collection_path).replace("\\", "/")
        if "/tests/e2e/" in p or p.endswith("/tests/e2e"):
            return not bool(os.getenv("RUN_E2E"))
        return False


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests"""
    temp_dir = tempfile.mkdtemp()
    yield Path(temp_dir)
    shutil.rmtree(temp_dir)


@pytest.fixture
def test_settings(temp_dir):
    """Create test settings with temporary directories"""
    return Settings(
        environment="testing",
        debug=True,
        log_level="DEBUG",
        database_url=f"sqlite:///{temp_dir}/test.db",
        agent_registry_path=str(temp_dir / "agents"),
        credential_storage_path=str(temp_dir / "credentials"),
        audit_storage_path=str(temp_dir / "audit"),
        log_file=str(temp_dir / "test.log"),
        enable_audit_logging=True,
        enable_trust_scoring=True,
        enable_federated_auth=False,  # Disable for tests
        enable_mfa=False,  # Disable for tests
        secret_key=secret_manager.get_secret("SECRET_KEY") or "test-secret-key-32-characters-long",
        encryption_key=secret_manager.get_secret("ENCRYPTION_KEY") or "test-encryption-key-32-chars!!",
        credential_encryption_key=secret_manager.get_secret("CREDENTIAL_ENCRYPTION_KEY") or "test-credential-key-32-chars!!"
    )


@pytest.fixture
def mock_iam(test_settings):
    """Create a mock IAM instance for testing (synchronous fixture)."""
    iam = MagicMock(spec=AgenticIAM)
    iam.settings = test_settings
    iam.is_initialized = True
    iam.start_time = datetime.utcnow()

    # Mock managers
    iam.identity_manager = MagicMock()
    iam.authentication_manager = MagicMock()
    iam.authorization_manager = MagicMock()
    iam.session_manager = MagicMock()
    iam.federated_manager = MagicMock()
    iam.transport_manager = MagicMock()
    iam.agent_registry = MagicMock()
    iam.credential_manager = MagicMock()
    iam.audit_manager = MagicMock()
    iam.compliance_manager = MagicMock()
    iam.intelligence_engine = MagicMock()
    iam.logger = MagicMock()

    # Mock async methods where tests expect them
    iam.initialize = AsyncMock()
    # Bind the real shutdown implementation so tests that call
    # `await mock_iam.shutdown()` execute the shutdown sequence on the
    # mocked subcomponents (their `shutdown` AsyncMocks will be awaited).
    from core.agentic_iam import AgenticIAM as _AgenticIAM
    iam.shutdown = _AgenticIAM.shutdown.__get__(iam, _AgenticIAM)

    # Provide default async manager behaviors used by real bound methods.
    from authentication import AuthenticationResult

    async def _auth_side_effect(agent_id=None, credentials=None, method="auto", **kwargs):
        return AuthenticationResult(True, agent_id or "agent:test-001", method or "jwt", 0.8)

    iam.authentication_manager.authenticate = AsyncMock(side_effect=_auth_side_effect)
    iam.authorization_manager.authorize = AsyncMock(return_value=MagicMock(allow=True, reason="authorized"))
    iam.authorization_manager.assign_permissions = AsyncMock(return_value=True)
    iam.session_manager.create_session = AsyncMock(return_value="session_001")
    iam.session_manager.get_active_session_count = MagicMock(return_value=0)
    iam.session_manager.get_total_session_count = MagicMock(return_value=0)
    iam.session_manager.terminate_session = MagicMock(return_value=True)
    iam.session_manager.terminate_agent_sessions = MagicMock(return_value=0)
    iam.session_manager.refresh_session = MagicMock(return_value=True)
    iam.session_manager.get_session = MagicMock(return_value=None)
    iam.agent_registry.list_agents = MagicMock(return_value=[])
    iam.agent_registry.get_agent = MagicMock(return_value=None)
    iam.agent_registry.register_agent = MagicMock(return_value=MagicMock(registration_id="reg_default"))
    iam.credential_manager.store_agent_credentials = AsyncMock(return_value=True)
    iam.audit_manager.log_event = AsyncMock(return_value=True)
    iam.intelligence_engine.initialize_agent_score = AsyncMock(return_value=True)
    iam.intelligence_engine.update_trust_score = AsyncMock(return_value=True)
    iam.intelligence_engine.calculate_trust_score = AsyncMock(
        return_value=MagicMock(overall_score=0.8, risk_level=MagicMock(value="low"), confidence=0.9)
    )

    # Bind real AgenticIAM methods so core tests exercise implementation.
    iam.authenticate = _AgenticIAM.authenticate.__get__(iam, _AgenticIAM)
    iam.authorize = _AgenticIAM.authorize.__get__(iam, _AgenticIAM)
    iam.register_agent = _AgenticIAM.register_agent.__get__(iam, _AgenticIAM)
    iam.create_session = _AgenticIAM.create_session.__get__(iam, _AgenticIAM)
    iam.calculate_trust_score = _AgenticIAM.calculate_trust_score.__get__(iam, _AgenticIAM)
    iam.get_platform_status = _AgenticIAM.get_platform_status.__get__(iam, _AgenticIAM)
    iam._get_avg_trust_score = _AgenticIAM._get_avg_trust_score.__get__(iam, _AgenticIAM)
    iam._get_total_trust_scores = _AgenticIAM._get_total_trust_scores.__get__(iam, _AgenticIAM)
    iam._get_anomaly_count = _AgenticIAM._get_anomaly_count.__get__(iam, _AgenticIAM)

    return iam


@pytest.fixture
async def iam_instance(mock_iam):
    """Use the same IAM instance used by API client dependency overrides."""
    yield mock_iam


@pytest.fixture
def client(mock_iam):
    """Create test client for API testing"""
    # Override dependencies
    app.dependency_overrides = {}

    def get_test_iam():
        return mock_iam

    def get_test_settings():
        return mock_iam.settings

    from api.dependencies import get_iam, get_settings
    app.dependency_overrides[get_iam] = get_test_iam
    app.dependency_overrides[get_settings] = get_test_settings

    with TestClient(app) as test_client:
        yield test_client

    # Clear overrides
    app.dependency_overrides = {}


@pytest.fixture
def sample_agent_data():
    """Sample agent data for testing"""
    return {
        "agent_id": "agent:test-001",
        "agent_type": "service",
        "description": "Test agent for unit tests",
        "capabilities": ["read", "write"],
        "metadata": {
            "environment": "test",
            "version": "1.0.0"
        },
        "initial_permissions": ["agent:read", "system:status"]
    }


@pytest.fixture
def sample_auth_request():
    """Sample authentication request for testing"""
    return {
        "agent_id": "agent:test-001",
        "method": "jwt",
        "credentials": {
            "username": "test-agent",
            "password": "test-password"
        },
        "source_ip": "127.0.0.1",
        "user_agent": "test-client/1.0"
    }


@pytest.fixture
def sample_agent_identity():
    """Create a sample agent identity for testing"""
    from agent_identity import AgentIdentity

    return AgentIdentity.generate(
        agent_id="agent:test-001",
        metadata={
            "type": "service",
            "description": "Test agent",
            "capabilities": ["read", "write"]
        }
    )


@pytest.fixture
def sample_trust_score():
    """Sample trust score for testing"""
    from agent_intelligence import TrustScore, RiskLevel

    trust_score = TrustScore(
        overall_score=0.85,
        risk_level="low",
        confidence=0.92
    )
    # Add additional attributes for extended testing
    trust_score.agent_id = "agent:test-001"
    trust_score.component_scores = {
        "authentication": 0.9,
        "authorization": 0.8,
        "behavior": 0.85,
        "network": 0.88
    }
    trust_score.last_updated = datetime.utcnow()
    trust_score.factors = [
        {"type": "successful_auth", "weight": 0.3, "value": 0.95},
        {"type": "session_duration", "weight": 0.2, "value": 0.8}
    ]
    return trust_score


@pytest.fixture
def sample_session():
    """Sample session for testing"""
    from agent_identity import Session, SessionStatus

    session = Session(
        session_id="session_test_001",
        agent_id="agent:test-001",
        trust_level=0.85,
        auth_method="jwt",
        ttl=3600,
        metadata={
            "source_ip": "127.0.0.1",
            "user_agent": "test-client/1.0"
        }
    )
    # Add additional attributes for extended testing
    session.status = SessionStatus("active")
    session.last_accessed = datetime.utcnow()
    return session


@pytest.fixture
def sample_audit_event():
    """Sample audit event for testing"""
    from audit_compliance import AuditEvent, AuditEventType, EventSeverity

    return AuditEvent(
        event_id="audit_test_001",
        event_type=AuditEventType.AUTH_SUCCESS,
        agent_id="agent:test-001",
        timestamp=datetime.utcnow(),
        severity=EventSeverity.LOW,
        component="authentication",
        outcome="success",
        source_ip="127.0.0.1",
        user_agent="test-client/1.0",
        details={
            "method": "jwt",
            "duration": 150
        }
    )


@pytest.fixture
def mock_redis():
    """Mock Redis for testing"""
    import fakeredis
    return fakeredis.FakeRedis()


@pytest.fixture
def mock_database():
    """Mock database for testing"""
    from unittest.mock import MagicMock

    db = MagicMock()
    db.execute = AsyncMock()
    db.fetch = AsyncMock()
    db.fetchrow = AsyncMock()
    db.close = AsyncMock()

    return db


# Test utilities
class TestHelpers:
    """Helper methods for tests"""

    @staticmethod
    def assert_api_response(response, expected_status=200):
        """Assert API response format and status"""
        assert response.status_code == expected_status
        data = response.json()

        if expected_status == 200:
            assert "timestamp" in data
        else:
            assert "error" in data

        return data

    @staticmethod
    def create_auth_header(token: str) -> dict:
        """Create authorization header for API tests"""
        return {"Authorization": f"Bearer {token}"}

    @staticmethod
    async def wait_for_condition(condition, timeout=5.0, interval=0.1):
        """Wait for a condition to become true"""
        import asyncio

        end_time = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < end_time:
            if await condition() if asyncio.iscoroutinefunction(condition) else condition():
                return True
            await asyncio.sleep(interval)
        return False


@pytest.fixture
def test_helpers():
    """Provide test helpers"""
    return TestHelpers


# Pytest configuration
def pytest_configure(config):
    """Configure pytest"""
    # Add custom markers
    config.addinivalue_line("markers", "unit: mark test as unit test")
    config.addinivalue_line("markers", "integration: mark test as integration test")
    config.addinivalue_line("markers", "api: mark test as API test")
    config.addinivalue_line("markers", "slow: mark test as slow running")
    config.addinivalue_line("markers", "security: mark test as security test")


def pytest_collection_modifyitems(config, items):
    """Modify test collection"""
    # Add markers based on file location
    for item in items:
        # Mark tests in specific directories
        if "test_unit" in str(item.fspath):
            item.add_marker(pytest.mark.unit)
        elif "test_integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
        elif "test_api" in str(item.fspath):
            item.add_marker(pytest.mark.api)
        elif "test_security" in str(item.fspath):
            item.add_marker(pytest.mark.security)


# Asyncio compatibility
@pytest.fixture(scope="session", autouse=True)
def setup_asyncio():
    """Setup asyncio for testing"""
    import nest_asyncio
    nest_asyncio.apply()


# Cleanup fixtures
@pytest.fixture(autouse=True)
def cleanup_after_test():
    """Cleanup after each test"""
    yield
    # Cleanup any global state
    import logging
    logging.getLogger().handlers.clear()
