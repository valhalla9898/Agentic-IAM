"""Setup script to bootstrap users securely."""

import os
import secrets
import string
import sys
from pathlib import Path

from database import get_database

# Add project to path
sys.path.insert(0, str(Path(__file__).parent))


def _generate_password(length: int = 20) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def setup_admin_user():
    """Add admin user to database with a generated or env-provided password."""
    db = get_database()
    admin_password = os.getenv("AGENTIC_IAM_ADMIN_PASSWORD") or _generate_password()

    try:
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE username = ?", ("admin",))
            existing = cursor.fetchone()
            if existing:
                admin_id = existing[0]
                if db.change_password(admin_id, admin_password):
                    print("✓ Admin user already exists; password reset")
                    print("   Username: admin")
                    print(f"   Password: {admin_password}")
                    print("   Role: admin")
                    return True
                print("⚠ Admin user exists but password reset failed")
                return False
    except Exception as exc:
        print(f"Error checking admin: {exc}")

    success = db.create_user(
        username="admin",
        email="admin@agentic-iam.local",
        password=admin_password,
        role="admin",
    )

    if success:
        print("✅ Admin user created successfully!")
        print("   Username: admin")
        print(f"   Password: {admin_password}")
        print("   Role: admin")
        return True

    print("❌ Failed to create admin user")
    return False


def setup_test_users():
    """Add optional test users with generated passwords.

    This is disabled by default and can be enabled via AGENTIC_IAM_CREATE_TEST_USERS=true.
    """
    if os.getenv("AGENTIC_IAM_CREATE_TEST_USERS", "false").lower() != "true":
        print("\nℹ Skipping test user creation (set AGENTIC_IAM_CREATE_TEST_USERS=true to enable)")
        return

    db = get_database()
    test_users = [
        {"username": "operator", "email": "operator@agentic-iam.local", "role": "operator"},
        {"username": "viewer", "email": "viewer@agentic-iam.local", "role": "viewer"},
        {"username": "agent_user", "email": "agent@agentic-iam.local", "role": "user"},
    ]

    print("\n📝 Creating test users...")
    for user in test_users:
        try:
            with db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id FROM users WHERE username = ?", (user["username"],))
                if cursor.fetchone():
                    print(f"   ℹ {user['username']}: already exists")
                    continue

            generated_password = _generate_password()
            success = db.create_user(password=generated_password, **user)
            if success:
                print(f"   ✓ {user['username']}: {user['role']}")
                print(f"     password: {generated_password}")
        except Exception as exc:
            print(f"   ✗ {user['username']}: {exc}")


def verify_database():
    """Verify database is working."""
    print("\n🔍 Verifying database...")
    db = get_database()

    try:
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users")
            user_count = cursor.fetchone()[0]
            print(f"   ✓ Users in database: {user_count}")

            cursor.execute("SELECT COUNT(*) FROM agents")
            agent_count = cursor.fetchone()[0]
            print(f"   ✓ Agents in database: {agent_count}")

            cursor.execute("SELECT username, role FROM users")
            users = cursor.fetchall()
            if users:
                print("\n   Users:")
                for username, role in users:
                    print(f"      - {username} ({role})")
            return True
    except Exception as exc:
        print(f"   ✗ Database error: {exc}")
        return False


if __name__ == "__main__":
    print("=" * 60)
    print("🔧 Agentic-IAM Setup - Initialize Database")
    print("=" * 60)

    print("\n👤 Setting up admin user...")
    setup_admin_user()
    setup_test_users()
    verify_database()

    print("\n" + "=" * 60)
    print("✅ Setup complete!")
    print("=" * 60)
    print("\n📊 Launch the dashboard: streamlit run app.py")
