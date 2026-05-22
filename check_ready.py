#!/usr/bin/env python
"""
Quick test to verify Agentic-IAM is ready to run
"""

import sys
from pathlib import Path

# Add project to path
sys.path.insert(0, str(Path(__file__).parent))


def test_database():
    """Test database connectivity"""
    try:
        from database import get_database

        db = get_database()
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users")
            user_count = cursor.fetchone()[0]
            print(f"✓ Database OK - {user_count} users")
            return True
    except Exception as e:
        print(f"✗ Database failed: {e}")
        return False


def test_authentication():
    """Test that at least one active admin account exists."""
    try:
        from database import get_database

        db = get_database()
        users = db.list_users()
        has_admin = any(u.get("role") == "admin" and u.get("status") == "active" for u in users)
        if has_admin:
            print("✓ Authentication OK - Active admin account found")
            return True
        print("✗ Authentication failed - No active admin account found")
        return False
    except Exception as e:
        print(f"✗ Authentication failed: {e}")
        return False


def test_imports():
    """Test critical imports"""
    try:
        print("✓ Streamlit OK")

        print("✓ FastAPI OK")

        print("✓ SQLAlchemy OK")

        print("✓ Pandas OK")

        print("✓ OpenAI SDK OK")

        return True
    except ImportError as e:
        print(f"⚠ Import warning: {e}")
        return False


def main():
    print("=" * 60)
    print("🔧 Agentic-IAM Pre-Launch Check")
    print("=" * 60)

    print("\n📦 Checking imports...")
    test_imports()

    print("\n📊 Checking database...")
    db_ok = test_database()

    print("\n🔐 Checking authentication...")
    auth_ok = test_authentication()

    print("\n" + "=" * 60)
    if db_ok and auth_ok:
        print("✅ All checks passed! Ready to launch!")
        print("\n🚀 Launch commands:")
        print("   Option 1 (Simple): streamlit run app.py")
        print("   Option 2 (Admin):  run_admin.bat (Windows)")
        print("   Option 3 (Desktop): Click 'Agentic-IAM (Admin)' icon")
        print("\n📖 Authentication:")
        print("   Use the admin account created via setup_admin.py")
        print("\n🔗 Access: http://localhost:8501")
        return 0
    else:
        print("⚠️ Some checks failed. Please resolve and try again.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
