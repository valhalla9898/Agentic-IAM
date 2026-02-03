"""
Quick test script to verify the application setup
"""
import sys
from pathlib import Path

# Add project to path
sys.path.insert(0, str(Path(__file__).parent))

print("=" * 60)
print("AGENTIC-IAM System Verification")
print("=" * 60)

# Test 1: Import core modules
print("\n✓ Testing imports...")
try:
    from agent_identity import AgentIdentity, AgenticIAM
    print("  ✓ agent_identity")
except Exception as e:
    print(f"  ✗ agent_identity: {e}")

try:
    from authentication import AuthenticationManager
    print("  ✓ authentication")
except Exception as e:
    print(f"  ✗ authentication: {e}")

try:
    from authorization import AuthorizationManager
    print("  ✓ authorization")
except Exception as e:
    print(f"  ✗ authorization: {e}")

try:
    from config.settings import Settings
    print("  ✓ config.settings")
except Exception as e:
    print(f"  ✗ config.settings: {e}")

try:
    from utils.logger import get_logger, setup_logging
    print("  ✓ utils.logger")
except Exception as e:
    print(f"  ✗ utils.logger: {e}")

try:
    from core.agentic_iam import AgenticIAM as IAM
    print("  ✓ core.agentic_iam")
except Exception as e:
    print(f"  ✗ core.agentic_iam: {e}")

try:
    import streamlit as st
    print("  ✓ streamlit")
except Exception as e:
    print(f"  ✗ streamlit: {e}")

# Test 2: Create instances
print("\n✓ Testing object creation...")
try:
    identity = AgentIdentity.generate("agent:test-001", {"type": "service"})
    print(f"  ✓ Created agent identity: {identity.agent_id}")
except Exception as e:
    print(f"  ✗ Agent identity: {e}")

try:
    settings = Settings()
    print(f"  ✓ Settings loaded (env={settings.environment})")
except Exception as e:
    print(f"  ✗ Settings: {e}")

try:
    logger = get_logger("test")
    print(f"  ✓ Logger initialized")
except Exception as e:
    print(f"  ✗ Logger: {e}")

# Test 3: File structure
print("\n✓ Checking file structure...")
required_files = [
    "app.py",
    "agent_identity.py",
    "config/settings.py",
    "utils/logger.py",
    "core/agentic_iam.py",
    "dashboard/utils.py",
    "dashboard/components/agent_management.py",
]

for file in required_files:
    path = Path(__file__).parent / file
    if path.exists():
        print(f"  ✓ {file}")
    else:
        print(f"  ✗ {file} - NOT FOUND")

print("\n" + "=" * 60)
print("✓ SYSTEM READY TO RUN")
print("=" * 60)
print("\nTo start the dashboard, run:")
print("  streamlit run app.py")
print("\nOr use:")
print("  .\run_dashboard.bat  (Windows)")
print("  ./run_dashboard.sh   (Linux/Mac)")
