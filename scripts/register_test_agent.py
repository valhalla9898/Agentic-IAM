import sys
from pathlib import Path

# Ensure project root is on sys.path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config.settings import get_settings
from core.agentic_iam import AgenticIAM
from agent_identity import AgentIdentity
from agent_registry import AgentRegistry


def main():
    settings = get_settings()

    # Create a lightweight IAM instance using only the registry
    iam = AgenticIAM(settings)
    iam.agent_registry = AgentRegistry(storage_path=settings.agent_registry_path, enable_persistence=True)
    iam.is_initialized = True

    # Test agent data (from your sample)
    agent_id = "agent:payment-bot-001"
    metadata = {
        "type": "service",
        "description": "Payment processing bot for invoices (v1.0)",
        "capabilities": ["read", "write", "execute"],
        "trust_level": 0.8,
        "environment": "production",
    }

    # Generate identity and register
    agent_identity = AgentIdentity.generate(agent_id, metadata)
    reg_id = iam.agent_registry.register_agent(agent_identity, endpoints=["https://payment.example.com"], capabilities=metadata["capabilities"]) 

    print("Registered agent:", agent_id)
    print("Registration ID:", reg_id)
    agents = iam.agent_registry.list_agents()
    print(f"Total agents in registry: {len(agents)}")


if __name__ == '__main__':
    main()
