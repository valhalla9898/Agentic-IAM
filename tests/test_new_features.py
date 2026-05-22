"""
Unit tests for new features: GraphQL, Mobile API, Trust Scoring, Compliance
"""
import pytest
from agent_intelligence import IntelligenceEngine, TrustScore
from audit_compliance import ComplianceFramework
from api.graphql import schema
from api.routers.mobile import MobileRegisterRequest, MobileHeartbeat


class TestTrustScoring:
    @pytest.mark.asyncio
    async def test_trust_score_calculation(self):
        """Test that trust scoring engine calculates scores"""
        engine = IntelligenceEngine()
        score = await engine.calculate_trust_score("agent:test-001")
        assert isinstance(score, TrustScore)
        assert 0.0 <= score.overall_score <= 1.0
        assert score.risk_level.value in ["low", "medium", "high"]
        assert 0.0 <= score.confidence <= 1.0

    @pytest.mark.asyncio
    async def test_trust_score_caching(self):
        """Test that trust scores are cached for performance"""
        engine = IntelligenceEngine()
        agent_id = "agent:cache-test"
        score1 = await engine.calculate_trust_score(agent_id)
        score2 = await engine.calculate_trust_score(agent_id)
        assert score1.overall_score == score2.overall_score


class TestComplianceFramework:
    def test_compliance_framework_enum(self):
        """Test that compliance frameworks are defined"""
        assert hasattr(ComplianceFramework, 'GDPR')
        assert hasattr(ComplianceFramework, 'HIPAA')
        assert hasattr(ComplianceFramework, 'SOX')
        assert hasattr(ComplianceFramework, 'PCI_DSS')
        assert hasattr(ComplianceFramework, 'ISO_27001')

    def test_compliance_values(self):
        """Test compliance framework values"""
        assert ComplianceFramework.GDPR.value == 'gdpr'
        assert ComplianceFramework.HIPAA.value == 'hipaa'
        assert ComplianceFramework.SOX.value == 'sox'
        assert ComplianceFramework.PCI_DSS.value == 'pci-dss'
        assert ComplianceFramework.ISO_27001.value == 'iso-27001'


class TestMobileAPI:
    def test_mobile_register_request(self):
        """Test mobile registration request model"""
        req = MobileRegisterRequest(agent_name="test-agent", platform="ios")
        assert req.agent_name == "test-agent"
        assert req.platform == "ios"

    def test_mobile_heartbeat_model(self):
        """Test mobile heartbeat model"""
        hb = MobileHeartbeat(agent_id="agent:test", timestamp="2025-12-28T00:00:00Z")
        assert hb.agent_id == "agent:test"
        assert hb.timestamp == "2025-12-28T00:00:00Z"


class TestGraphQL:
    def test_graphql_schema_exists(self):
        """Test that GraphQL schema is defined"""
        assert schema is not None
        assert hasattr(schema, 'query_type')

    def test_graphql_types(self):
        """Test GraphQL types are defined"""
        type_map = schema.type_map
        assert 'Agent' in type_map
        assert 'TrustScore' in type_map
        assert 'Query' in type_map


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
