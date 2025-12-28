"""
Performance and Load Testing for Agentic-IAM

Run various performance tests to measure throughput, latency, and scalability.
"""
import asyncio
import time
import statistics
from typing import List, Dict, Any
import sys
from pathlib import Path

# Add project to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.agentic_iam import AgenticIAM
from config.settings import Settings
from session_manager import SessionManager
from agent_registry import AgentRegistry
from authentication import AuthenticationManager


class PerformanceTester:
    """Performance testing suite for IAM system"""
    
    def __init__(self):
        """Initialize tester"""
        self.settings = Settings()
        self.results: Dict[str, List[float]] = {}
    
    async def test_agent_creation_throughput(self, num_agents: int = 1000) -> None:
        """Test agent creation throughput"""
        print(f"\n📊 Testing Agent Creation Throughput ({num_agents} agents)...")
        
        iam = AgenticIAM(self.settings)
        timings: List[float] = []
        
        start_time = time.time()
        
        for i in range(num_agents):
            agent_id = f"agent:perf_test_{i}"
            start = time.time()
            
            agent = iam.agent_registry.register_agent(
                agent_id=agent_id,
                agent_type="test_agent",
                description=f"Performance test agent {i}",
                metadata={"iteration": i}
            )
            
            elapsed = time.time() - start
            timings.append(elapsed)
            
            if (i + 1) % 100 == 0:
                print(f"  ✓ Created {i + 1}/{num_agents} agents")
        
        total_time = time.time() - start_time
        self.results["agent_creation"] = timings
        
        self._print_stats("Agent Creation", timings, total_time, num_agents)
    
    async def test_authentication_throughput(self, num_requests: int = 5000) -> None:
        """Test authentication request throughput"""
        print(f"\n📊 Testing Authentication Throughput ({num_requests} requests)...")
        
        iam = AgenticIAM(self.settings)
        timings: List[float] = []
        
        # Create test agent
        agent = iam.agent_registry.register_agent(
            agent_id="agent:perf_test_auth",
            agent_type="test_agent",
            description="Performance test agent"
        )
        
        start_time = time.time()
        
        for i in range(num_requests):
            start = time.time()
            
            session_id = iam.session_manager.create_session(
                agent_id=agent.agent_id,
                trust_level=0.9,
                auth_method="jwt"
            )
            
            elapsed = time.time() - start
            timings.append(elapsed)
            
            if (i + 1) % 500 == 0:
                print(f"  ✓ Processed {i + 1}/{num_requests} requests")
        
        total_time = time.time() - start_time
        self.results["authentication"] = timings
        
        self._print_stats("Authentication", timings, total_time, num_requests)
    
    async def test_session_management_throughput(self, num_sessions: int = 2000) -> None:
        """Test session management throughput"""
        print(f"\n📊 Testing Session Management Throughput ({num_sessions} sessions)...")
        
        iam = AgenticIAM(self.settings)
        timings: List[float] = []
        session_ids: List[str] = []
        
        # Create test agent
        agent = iam.agent_registry.register_agent(
            agent_id="agent:perf_test_sessions",
            agent_type="test_agent",
            description="Performance test agent"
        )
        
        start_time = time.time()
        
        # Create sessions
        for i in range(num_sessions):
            start = time.time()
            
            session_id = iam.session_manager.create_session(
                agent_id=agent.agent_id,
                trust_level=0.8,
                auth_method="jwt"
            )
            session_ids.append(session_id)
            
            elapsed = time.time() - start
            timings.append(elapsed)
            
            if (i + 1) % 200 == 0:
                print(f"  ✓ Created {i + 1}/{num_sessions} sessions")
        
        total_time = time.time() - start_time
        self.results["session_creation"] = timings
        
        self._print_stats("Session Creation", timings, total_time, num_sessions)
        
        # Test session refresh
        print(f"\n📊 Testing Session Refresh Throughput ({len(session_ids)} sessions)...")
        timings = []
        start_time = time.time()
        
        for session_id in session_ids:
            start = time.time()
            iam.session_manager.refresh_session(session_id)
            elapsed = time.time() - start
            timings.append(elapsed)
        
        total_time = time.time() - start_time
        self.results["session_refresh"] = timings
        
        self._print_stats("Session Refresh", timings, total_time, len(session_ids))
    
    async def test_trust_scoring_throughput(self, num_agents: int = 500) -> None:
        """Test trust scoring calculation throughput"""
        print(f"\n📊 Testing Trust Scoring Throughput ({num_agents} agents)...")
        
        iam = AgenticIAM(self.settings)
        timings: List[float] = []
        
        # Create test agents
        agent_ids = []
        for i in range(num_agents):
            agent = iam.agent_registry.register_agent(
                agent_id=f"agent:perf_trust_{i}",
                agent_type="test_agent",
                description=f"Trust scoring test agent {i}"
            )
            agent_ids.append(agent.agent_id)
        
        start_time = time.time()
        
        for agent_id in agent_ids:
            start = time.time()
            
            # Calculate trust score (placeholder - actual implementation may vary)
            events = iam.audit_manager.query_events(
                agent_id=agent_id
            ) if iam.audit_manager else []
            
            elapsed = time.time() - start
            timings.append(elapsed)
        
        total_time = time.time() - start_time
        self.results["trust_scoring"] = timings
        
        self._print_stats("Trust Scoring", timings, total_time, num_agents)
    
    def _print_stats(self, operation: str, timings: List[float], total_time: float, count: int) -> None:
        """Print performance statistics"""
        if not timings:
            print(f"  ⚠️  No data collected")
            return
        
        min_time = min(timings)
        max_time = max(timings)
        avg_time = statistics.mean(timings)
        med_time = statistics.median(timings)
        
        try:
            std_dev = statistics.stdev(timings) if len(timings) > 1 else 0
        except:
            std_dev = 0
        
        throughput = count / total_time if total_time > 0 else 0
        
        print(f"\n  {operation} Statistics:")
        print(f"    Total Time:     {total_time:.2f}s")
        print(f"    Throughput:     {throughput:.0f} ops/sec")
        print(f"    Min Latency:    {min_time*1000:.2f}ms")
        print(f"    Avg Latency:    {avg_time*1000:.2f}ms")
        print(f"    Median Latency: {med_time*1000:.2f}ms")
        print(f"    Max Latency:    {max_time*1000:.2f}ms")
        print(f"    Std Deviation:  {std_dev*1000:.2f}ms")
    
    async def run_all_tests(self) -> None:
        """Run all performance tests"""
        print("=" * 60)
        print("🚀 Agentic-IAM Performance Testing Suite")
        print("=" * 60)
        
        try:
            await self.test_agent_creation_throughput(100)  # Reduced for testing
            await self.test_authentication_throughput(500)
            await self.test_session_management_throughput(200)
            await self.test_trust_scoring_throughput(100)
            
            print("\n" + "=" * 60)
            print("✅ All tests completed successfully!")
            print("=" * 60)
        
        except Exception as e:
            print(f"\n❌ Error during testing: {str(e)}")
            import traceback
            traceback.print_exc()


async def main():
    """Run performance tests"""
    tester = PerformanceTester()
    await tester.run_all_tests()


if __name__ == "__main__":
    asyncio.run(main())
