# 🔐 Agentic-IAM Login System

A comprehensive authentication and authorization system for the Agentic-IAM platform with role-based access control.

## 🎯 Features

### ✅ Authentication
- Secure login with SHA-256 password hashing
- Role-based access (Admin & User)
- Session management
- Default credentials for quick start
- Password change functionality

### ✅ Authorization
- **Admin Role**: Full system access
  - User management (create, view, edit, delete users)
  - Agent management (full CRUD operations)
  - System settings
  - Complete audit logs
  
- **User Role**: Limited access
  - View agents (read-only)
  - Personal audit logs
  - Account settings
  - Password management

### ✅ Security
- SHA-256 password hashing
- No plain-text password storage
- Session-based authentication
- Role-based page protection
- Automatic login requirement

## 🚀 Quick Start

### 1. Run the Application
```bash
# Option 1: Using the launcher
python run_gui.py

# Option 2: Direct launch
streamlit run app.py
```

### 2. Access the Login Page
Open your browser to: **http://localhost:8501**

### 3. Login with Default Credentials

**Administrator:**
- Username: `admin`
- Password: `admin123`

**Regular User:**
- Username: `user`
- Password: `user123`

⚠️ **Important:** Change these passwords after first login!

## 📊 Dashboard Overview

### Admin Dashboard
```
┌─────────────────────────────────────────┐
│         🏠 Admin Dashboard              │
├─────────────────────────────────────────┤
│  Navigation:                            │
│  • Home                                 │
│  • 👥 Users (Manage all users)         │
│  • 🤖 Agents (Manage all agents)       │
│  • Register Agent                       │
│  • Select Agent                         │
│  • Audit Log (Complete access)          │
│  • Settings                             │
└─────────────────────────────────────────┘
```

### User Dashboard
```
┌─────────────────────────────────────────┐
│         🏠 User Dashboard               │
├─────────────────────────────────────────┤
│  Navigation:                            │
│  • Home                                 │
│  • Select Agent (Read-only)             │
│  • Audit Log (Personal only)            │
│  • Settings                             │
└─────────────────────────────────────────┘
```

## 🔧 User Management (Admin Only)

### Create New User
1. Login as admin
2. Navigate to **👥 Users** → **➕ Create User**
3. Fill in the form:
   - Username (required, must be unique)
   - Password (required, min 6 characters)
   - Full Name (required)
   - Email (optional)
   - Role (user or admin)
4. Click **Create User**

### Manage Existing Users
1. Navigate to **👥 Users** → **🔧 Manage Users**
2. Select a user from the dropdown
3. Available actions:
   - **Change Status**: Active, Inactive, Suspended
   - **Reset Password**: Set new password
   - **View Details**: See user information

### User List View
View all users with:
- User ID
- Username
- Full Name
- Email
- Role (Admin/User)
- Status (Active/Inactive)
- Creation date
- Last login timestamp

## 🔑 Password Management

### Change Your Own Password
1. Login to your account
2. Navigate to **Settings** → **Security**
3. Fill in the password change form:
   - Current Password
   - New Password
   - Confirm New Password
4. Click **Change Password**

### Reset Another User's Password (Admin Only)
1. Login as admin
2. Navigate to **👥 Users** → **🔧 Manage Users**
3. Select the user
4. In the **Reset Password** section:
   - Enter new password
   - Confirm new password
5. Click **Reset Password**

## 🗄️ Database Structure

### Users Table
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,           -- SHA-256 hashed
    role TEXT DEFAULT 'user',        -- 'admin' or 'user'
    full_name TEXT,
    email TEXT,
    created_at TIMESTAMP,
    last_login TIMESTAMP,
    status TEXT DEFAULT 'active'     -- 'active', 'inactive', 'suspended'
)
```

## 🧪 Testing the System

### Run Authentication Tests
```bash
python test_login.py
```

This will test:
- User authentication
- Password hashing
- Role-based access
- User creation
- Password changes
- Status management

### Manual Testing Checklist
- [ ] Login as admin with default credentials
- [ ] Login as user with default credentials
- [ ] Create a new user (admin only)
- [ ] Change your password
- [ ] Reset another user's password (admin only)
- [ ] Suspend a user account (admin only)
- [ ] View user list (admin only)
- [ ] View agents (both roles)
- [ ] Check audit logs
- [ ] Logout and login again

## 📁 File Structure

```
Agentic-IAM-main/
├── app.py                          ← Main application with auth
├── database.py                     ← Database with user management
├── test_login.py                   ← Authentication tests
├── LOGIN_GUIDE.md                  ← Comprehensive guide
├── ARCHITECTURE_DIAGRAM.md         ← System diagrams
└── dashboard/
    └── components/
        ├── login.py                ← Login page component
        ├── user_management.py      ← User management (admin)
        └── agent_management.py     ← Agent management
```

## 🔒 Security Best Practices

1. **Change Default Passwords**
   - Immediately change admin and user passwords
   - Use strong passwords (8+ characters, mixed case, numbers, symbols)

2. **User Management**
   - Create individual accounts for each user
   - Use principle of least privilege
   - Regularly review user access
   - Disable unused accounts

3. **Password Policy**
   - Minimum 6 characters (recommended 8+)
   - Mix uppercase, lowercase, numbers, symbols
   - Don't reuse passwords
   - Change passwords periodically

4. **Monitoring**
   - Check audit logs regularly
   - Monitor failed login attempts
   - Review user activity
   - Track agent access patterns

## 🐛 Troubleshooting

### Cannot Login
**Problem:** Login fails with correct credentials

**Solutions:**
- Verify username and password
- Check you selected correct role (Admin vs User)
- Ensure account status is 'active'
- Check database file exists: `data/agentic_iam.db`

### Permission Denied
**Problem:** Cannot access certain features

**Solution:**
- Regular users cannot access admin features
- Login with admin account for full access
- Contact administrator to change your role

### Database Errors
**Problem:** Database-related errors

**Solutions:**
- Check `data/agentic_iam.db` exists
- Verify database permissions
- Run `test_login.py` to verify database
- Delete database and restart to recreate

### Session Issues
**Problem:** Logged out unexpectedly

**Solution:**
- Refresh the page
- Clear browser cache
- Restart the application

## 📝 API Reference

### Database Methods

```python
from database import get_database

db = get_database()

# Authenticate user
user = db.authenticate_user(username, password)

# Create user
success = db.create_user(
    username="newuser",
    password="password",
    role="user",
    full_name="New User",
    email="user@example.com"
)

# List all users
users = db.list_users()

# Update user status
db.update_user_status(user_id, "suspended")

# Change password
db.change_password(user_id, new_password)
```

### Login Component Methods

```python
from dashboard.components.login import (
    is_authenticated,
    is_admin,
    get_current_user,
    logout
)

# Check if user is logged in
if is_authenticated():
    print("User is logged in")

# Check if user is admin
if is_admin():
    print("User has admin privileges")

# Get current user info
user = get_current_user()
print(f"Username: {user['username']}")

# Logout
logout()
```

## 🎨 Customization

### Adding New Roles
1. Modify `database.py` to support additional roles
2. Update `login.py` to include new role options
3. Add role-specific pages in `app.py`
4. Update authorization checks

### Changing Password Requirements
Edit in `dashboard/components/user_management.py`:
```python
# Change minimum length
elif len(password) < 8:  # Changed from 6 to 8
    st.error("⚠️ Password must be at least 8 characters long")
```

### Custom Login Styling
Modify CSS in `dashboard/components/login.py`:
```python
st.markdown("""
    <style>
    .login-container {
        /* Your custom styles */
    }
    </style>
""", unsafe_allow_html=True)
```

## 📞 Support

For issues or questions:
1. Check [LOGIN_GUIDE.md](LOGIN_GUIDE.md) for detailed instructions
2. Review [ARCHITECTURE_DIAGRAM.md](ARCHITECTURE_DIAGRAM.md) for system design
3. Run `test_login.py` to diagnose issues
4. Check application logs in the terminal

## 📄 License

Part of the Agentic-IAM project. See main project README for license information.

## 🙏 Acknowledgments

Built with:
- [Streamlit](https://streamlit.io/) - Web framework
- [SQLite](https://www.sqlite.org/) - Database
- Python 3.x - Programming language

---

**Version:** 1.0  
**Last Updated:** December 2025  
**Author:** Agentic-IAM Team
