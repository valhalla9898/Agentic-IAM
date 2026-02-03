# Agentic-IAM Login System Guide

## Overview
The Agentic-IAM application now features a complete authentication system with role-based access control (RBAC) supporting two user types: **Administrators** and **Regular Users**.

## Default Credentials

### Administrator Account
- **Username:** `admin`
- **Password:** `admin123`
- **Access:** Full system access including user management, agent management, and all system features

### Regular User Account
- **Username:** `user`
- **Password:** `user123`
- **Access:** Limited access to view agents, audit logs, and personal settings

## How to Run

1. **Start the Application:**
   ```bash
   python run_gui.py
   ```
   Or directly:
   ```bash
   streamlit run app.py
   ```

2. **Access the Dashboard:**
   - Open your browser to: `http://localhost:8501`
   - You'll be greeted with the login page

3. **Login:**
   - Select your role (User or Administrator)
   - Enter your credentials
   - Click "Login"

## Features by Role

### Administrator Features (admin/admin123)
- ✅ **User Management**
  - Create new users
  - View all system users
  - Change user passwords
  - Update user status (active/inactive/suspended)
  - Assign roles

- ✅ **Full Agent Access**
  - Register new agents
  - View all agents
  - Manage agent lifecycle
  - View detailed agent information

- ✅ **Complete Audit Trail**
  - View all system events
  - Filter by agent
  - Export audit logs

- ✅ **System Configuration**
  - Manage system settings
  - Configure security policies
  - View system health

### Regular User Features (user/user123)
- ✅ **Agent Viewing**
  - View available agents
  - Select agents for interaction
  - View agent details (read-only)

- ✅ **Personal Audit Logs**
  - View personal activity
  - Track agent interactions

- ✅ **Account Settings**
  - Change password
  - Update preferences
  - View profile information

## Security Features

### Password Security
- SHA-256 password hashing
- Minimum 6 character password requirement
- Secure password change process
- No plain-text password storage

### Session Management
- Persistent session state
- Automatic session cleanup on logout
- Role-based route protection

### Access Control
- Role-based access control (RBAC)
- Page-level authorization checks
- Function-level permission validation

## User Management (Admin Only)

### Creating New Users
1. Login as administrator
2. Navigate to **Users** in the sidebar
3. Go to the **Create User** tab
4. Fill in the form:
   - Username (required, unique)
   - Password (required, min 6 chars)
   - Full Name (required)
   - Email (optional)
   - Role (user or admin)
5. Click "Create User"

### Managing Existing Users
1. Login as administrator
2. Navigate to **Users** → **Manage Users** tab
3. Select a user from the dropdown
4. Available actions:
   - Change user status (active/inactive/suspended)
   - Reset password
   - View user details

## Database Structure

The system uses SQLite database with the following tables:

### Users Table
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,  -- SHA-256 hashed
    role TEXT DEFAULT 'user',
    full_name TEXT,
    email TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    status TEXT DEFAULT 'active'
)
```

## First-Time Setup

1. **Initialize Database:**
   - The database is automatically created on first run
   - Default admin and user accounts are created automatically

2. **Change Default Passwords:**
   - Login with default credentials
   - Go to Settings → Security
   - Change your password immediately

3. **Create Additional Users (Admin):**
   - Login as admin
   - Navigate to Users
   - Create new user accounts as needed

## Troubleshooting

### Cannot Login
- Verify you're using the correct credentials
- Check that you selected the correct role (Admin vs User)
- Ensure the database file exists: `data/agentic_iam.db`

### Permission Denied
- Regular users cannot access admin features
- Login with administrator account for full access

### Password Reset
- Administrators can reset any user's password from the User Management page
- Users can change their own password from Settings → Security

## API Endpoints (Future)

The system is designed to support future API integration:
- `/api/auth/login` - User authentication
- `/api/auth/logout` - Session termination
- `/api/users` - User management (admin only)
- `/api/agents` - Agent management

## Best Practices

1. **Security:**
   - Change default passwords immediately
   - Use strong passwords (8+ characters, mixed case, numbers, symbols)
   - Regularly review user access logs
   - Disable inactive accounts

2. **User Management:**
   - Create separate accounts for each user
   - Use the principle of least privilege
   - Regularly audit user permissions
   - Remove or suspend terminated users

3. **Monitoring:**
   - Regularly check audit logs
   - Monitor failed login attempts
   - Track user activity
   - Review agent access patterns

## Development Notes

### File Structure
```
dashboard/
  components/
    login.py           # Login page and authentication
    user_management.py # User management interface (admin)
    agent_management.py # Agent management (existing)
    
database.py           # Database operations with user auth
app.py               # Main application with role-based routing
```

### Adding New Features
1. Use `is_authenticated()` to check if user is logged in
2. Use `is_admin()` to check admin privileges
3. Use `require_auth(admin_only=True)` decorator for admin-only pages
4. Use `get_current_user()` to access user information

## Support

For issues or questions:
1. Check the audit logs for error messages
2. Verify database integrity: `data/agentic_iam.db`
3. Review application logs
4. Contact system administrator

## Version History

- **v1.0** - Initial release with authentication system
  - Role-based access control
  - User management
  - Password security
  - Session management
