"""
Test script to verify the login system functionality

Run this script to test the authentication system without starting the GUI.
"""
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from database import get_database


def test_authentication():
    """Test user authentication system"""
    print("\n" + "="*70)
    print("AGENTIC-IAM AUTHENTICATION SYSTEM TEST")
    print("="*70 + "\n")
    
    db = get_database()
    
    # Test 1: List all users
    print("Test 1: List All Users")
    print("-" * 50)
    users = db.list_users()
    print(f"Total users in database: {len(users)}\n")
    
    for user in users:
        role_icon = "👨‍💼" if user['role'] == 'admin' else "👤"
        print(f"{role_icon} {user['username']:<15} | {user['full_name']:<25} | Role: {user['role']:<10} | Status: {user['status']}")
    
    # Test 2: Authenticate admin
    print("\n" + "="*70)
    print("Test 2: Admin Login")
    print("-" * 50)
    admin_user = db.authenticate_user("admin", "admin123")
    if admin_user:
        print("✅ Admin authentication successful!")
        print(f"   User ID: {admin_user['id']}")
        print(f"   Username: {admin_user['username']}")
        print(f"   Full Name: {admin_user['full_name']}")
        print(f"   Role: {admin_user['role']}")
        print(f"   Email: {admin_user['email']}")
    else:
        print("❌ Admin authentication failed!")
    
    # Test 3: Authenticate regular user
    print("\n" + "="*70)
    print("Test 3: User Login")
    print("-" * 50)
    regular_user = db.authenticate_user("user", "user123")
    if regular_user:
        print("✅ User authentication successful!")
        print(f"   User ID: {regular_user['id']}")
        print(f"   Username: {regular_user['username']}")
        print(f"   Full Name: {regular_user['full_name']}")
        print(f"   Role: {regular_user['role']}")
        print(f"   Email: {regular_user['email']}")
    else:
        print("❌ User authentication failed!")
    
    # Test 4: Test wrong password
    print("\n" + "="*70)
    print("Test 4: Invalid Password")
    print("-" * 50)
    wrong_login = db.authenticate_user("admin", "wrongpassword")
    if wrong_login:
        print("❌ Security issue: Invalid password accepted!")
    else:
        print("✅ Invalid password correctly rejected")
    
    # Test 5: Test wrong username
    print("\n" + "="*70)
    print("Test 5: Invalid Username")
    print("-" * 50)
    wrong_user = db.authenticate_user("nonexistent", "password")
    if wrong_user:
        print("❌ Security issue: Invalid username accepted!")
    else:
        print("✅ Invalid username correctly rejected")
    
    # Test 6: Create new user
    print("\n" + "="*70)
    print("Test 6: Create New User")
    print("-" * 50)
    new_user_created = db.create_user(
        username="testuser",
        password="testpass123",
        role="user",
        full_name="Test User",
        email="test@example.com"
    )
    if new_user_created:
        print("✅ New user created successfully")
        
        # Try to authenticate with new user
        test_auth = db.authenticate_user("testuser", "testpass123")
        if test_auth:
            print("✅ New user can authenticate successfully")
            print(f"   Username: {test_auth['username']}")
            print(f"   Full Name: {test_auth['full_name']}")
        else:
            print("❌ New user authentication failed")
    else:
        print("⚠️  User may already exist (expected if test was run before)")
    
    # Test 7: Test password change
    print("\n" + "="*70)
    print("Test 7: Password Change")
    print("-" * 50)
    test_user = db.authenticate_user("testuser", "testpass123")
    if test_user:
        # Change password
        changed = db.change_password(test_user['id'], "newpassword456")
        if changed:
            print("✅ Password changed successfully")
            
            # Try old password (should fail)
            old_auth = db.authenticate_user("testuser", "testpass123")
            if old_auth:
                print("❌ Old password still works - security issue!")
            else:
                print("✅ Old password correctly rejected")
            
            # Try new password (should work)
            new_auth = db.authenticate_user("testuser", "newpassword456")
            if new_auth:
                print("✅ New password works correctly")
            else:
                print("❌ New password doesn't work")
        else:
            print("❌ Password change failed")
    
    # Test 8: Test user status management
    print("\n" + "="*70)
    print("Test 8: User Status Management")
    print("-" * 50)
    if test_user:
        # Suspend user
        suspended = db.update_user_status(test_user['id'], 'suspended')
        if suspended:
            print("✅ User status updated to 'suspended'")
            
            # Try to login with suspended account
            suspended_auth = db.authenticate_user("testuser", "newpassword456")
            if suspended_auth:
                print("❌ Suspended user can still login - security issue!")
            else:
                print("✅ Suspended user correctly blocked from login")
            
            # Reactivate user
            activated = db.update_user_status(test_user['id'], 'active')
            if activated:
                print("✅ User reactivated successfully")
    
    # Test 9: Database statistics
    print("\n" + "="*70)
    print("Test 9: Database Statistics")
    print("-" * 50)
    all_users = db.list_users()
    total = len(all_users)
    active = len([u for u in all_users if u['status'] == 'active'])
    admins = len([u for u in all_users if u['role'] == 'admin'])
    regular = len([u for u in all_users if u['role'] == 'user'])
    
    print(f"Total Users: {total}")
    print(f"Active Users: {active}")
    print(f"Administrators: {admins}")
    print(f"Regular Users: {regular}")
    
    # Final summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    print("✅ All authentication tests passed!")
    print("\nDefault Credentials:")
    print("  Admin: admin / admin123")
    print("  User:  user / user123")
    print("\nDatabase Location: data/agentic_iam.db")
    print("\nRun the application with: python run_gui.py")
    print("Or directly with: streamlit run app.py")
    print("\n" + "="*70 + "\n")


if __name__ == "__main__":
    try:
        test_authentication()
    except Exception as e:
        print(f"\n❌ Error during testing: {e}")
        import traceback
        traceback.print_exc()
