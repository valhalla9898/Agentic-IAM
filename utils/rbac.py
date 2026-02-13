"""
Role-Based Access Control (RBAC) Module

Provides comprehensive permission management and access control for the Agentic-IAM system.
Supports role-based access control with fine-grained permissions.
"""

from enum import Enum
from typing import Set, Dict, List, Optional, Callable
import functools
import streamlit as st
import logging

logger = logging.getLogger(__name__)


class Permission(Enum):
    """System permissions"""
    # Agent management permissions
    AGENT_CREATE = "agent:create"
    AGENT_READ = "agent:read"
    AGENT_UPDATE = "agent:update"
    AGENT_DELETE = "agent:delete"
    AGENT_LIST = "agent:list"
    
    # User management permissions (admin only)
    USER_CREATE = "user:create"
    USER_READ = "user:read"
    USER_UPDATE = "user:update"
    USER_DELETE = "user:delete"
    USER_LIST = "user:list"
    USER_ROLE = "user:role"
    
    # Session permissions
    SESSION_CREATE = "session:create"
    SESSION_READ = "session:read"
    SESSION_TERMINATE = "session:terminate"
    
    # Audit/Compliance permissions
    AUDIT_READ = "audit:read"
    AUDIT_EXPORT = "audit:export"
    
    # System permissions (admin only)
    SYSTEM_CONFIG = "system:config"
    SYSTEM_BACKUP = "system:backup"
    SYSTEM_RESTORE = "system:restore"
    
    # Reporting permissions
    REPORT_VIEW = "report:view"
    REPORT_GENERATE = "report:generate"
    
    # Settings permissions
    SETTINGS_VIEW = "settings:view"
    SETTINGS_MODIFY = "settings:modify"


class Role(Enum):
    """System roles"""
    ADMIN = "admin"
    USER = "user"
    GUEST = "guest"
    OPERATOR = "operator"


# Role-permission mapping
ROLE_PERMISSIONS: Dict[Role, Set[Permission]] = {
    Role.ADMIN: {
        # All permissions for admin
        Permission.AGENT_CREATE,
        Permission.AGENT_READ,
        Permission.AGENT_UPDATE,
        Permission.AGENT_DELETE,
        Permission.AGENT_LIST,
        Permission.USER_CREATE,
        Permission.USER_READ,
        Permission.USER_UPDATE,
        Permission.USER_DELETE,
        Permission.USER_LIST,
        Permission.USER_ROLE,
        Permission.SESSION_CREATE,
        Permission.SESSION_READ,
        Permission.SESSION_TERMINATE,
        Permission.AUDIT_READ,
        Permission.AUDIT_EXPORT,
        Permission.SYSTEM_CONFIG,
        Permission.SYSTEM_BACKUP,
        Permission.SYSTEM_RESTORE,
        Permission.REPORT_VIEW,
        Permission.REPORT_GENERATE,
        Permission.SETTINGS_VIEW,
        Permission.SETTINGS_MODIFY,
    },
    Role.USER: {
        # Limited permissions for regular users
        Permission.AGENT_READ,
        Permission.AGENT_LIST,
        Permission.SESSION_CREATE,
        Permission.SESSION_READ,
        Permission.REPORT_VIEW,
        Permission.SETTINGS_VIEW,
    },
    Role.OPERATOR: {
        # Operator can manage agents but not users
        Permission.AGENT_CREATE,
        Permission.AGENT_READ,
        Permission.AGENT_UPDATE,
        Permission.AGENT_LIST,
        Permission.SESSION_CREATE,
        Permission.SESSION_READ,
        Permission.SESSION_TERMINATE,
        Permission.AUDIT_READ,
        Permission.REPORT_VIEW,
        Permission.REPORT_GENERATE,
    },
    Role.GUEST: {
        # Minimal permissions for guests
        Permission.AGENT_READ,
        Permission.AGENT_LIST,
        Permission.REPORT_VIEW,
    },
}


class RBACManager:
    """Manages role-based access control"""
    
    def __init__(self):
        """Initialize RBAC manager"""
        self.role_permissions = ROLE_PERMISSIONS
    
    def get_user_role(self, user: Optional[Dict]) -> Role:
        """Get user role from session"""
        if not user:
            return Role.GUEST
        
        role_str = user.get('role', 'user').lower()
        try:
            return Role[role_str.upper()]
        except KeyError:
            return Role.USER
    
    def get_user_permissions(self, user: Optional[Dict]) -> Set[Permission]:
        """Get all permissions for a user"""
        role = self.get_user_role(user)
        return self.role_permissions.get(role, set())
    
    def has_permission(self, user: Optional[Dict], permission: Permission) -> bool:
        """Check if user has specific permission"""
        permissions = self.get_user_permissions(user)
        return permission in permissions
    
    def has_any_permission(self, user: Optional[Dict], permissions: List[Permission]) -> bool:
        """Check if user has any of the given permissions"""
        user_permissions = self.get_user_permissions(user)
        return any(p in user_permissions for p in permissions)
    
    def has_all_permissions(self, user: Optional[Dict], permissions: List[Permission]) -> bool:
        """Check if user has all of the given permissions"""
        user_permissions = self.get_user_permissions(user)
        return all(p in user_permissions for p in permissions)
    
    def require_permission(self, permission: Permission):
        """Decorator to require specific permission for a function"""
        def decorator(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                user = st.session_state.get('user')
                if not self.has_permission(user, permission):
                    st.error(f"❌ Access Denied: You don't have permission to {permission.value}")
                    logger.warning(f"Access denied for {user.get('username', 'unknown') if user else 'guest'} to {permission.value}")
                    return None
                return func(*args, **kwargs)
            return wrapper
        return decorator
    
    def require_any_permission(self, *permissions: Permission):
        """Decorator to require any of the given permissions"""
        def decorator(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                user = st.session_state.get('user')
                if not self.has_any_permission(user, list(permissions)):
                    st.error(f"❌ Access Denied: Insufficient permissions")
                    logger.warning(f"Access denied for {user.get('username', 'unknown') if user else 'guest'}")
                    return None
                return func(*args, **kwargs)
            return wrapper
        return decorator
    
    def require_all_permissions(self, *permissions: Permission):
        """Decorator to require all of the given permissions"""
        def decorator(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                user = st.session_state.get('user')
                if not self.has_all_permissions(user, list(permissions)):
                    st.error(f"❌ Access Denied: Insufficient permissions")
                    logger.warning(f"Access denied for {user.get('username', 'unknown') if user else 'guest'}")
                    return None
                return func(*args, **kwargs)
            return wrapper
        return decorator
    
    def require_role(self, *roles: Role):
        """Decorator to require specific role(s)"""
        def decorator(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                user = st.session_state.get('user')
                user_role = self.get_user_role(user)
                if user_role not in roles:
                    st.error(f"❌ Access Denied: This action requires one of {[r.value for r in roles]}")
                    logger.warning(f"Access denied for {user.get('username', 'unknown') if user else 'guest'} role {user_role.value}")
                    return None
                return func(*args, **kwargs)
            return wrapper
        return decorator


def check_permission(permission: Permission) -> bool:
    """Check if current user has permission"""
    rbac = RBACManager()
    user = st.session_state.get('user')
    return rbac.has_permission(user, permission)


def check_role(*roles: Role) -> bool:
    """Check if current user has required role"""
    rbac = RBACManager()
    user = st.session_state.get('user')
    user_role = rbac.get_user_role(user)
    return user_role in roles


def get_current_user_role() -> Role:
    """Get current user's role"""
    rbac = RBACManager()
    user = st.session_state.get('user')
    return rbac.get_user_role(user)


def get_current_user_permissions() -> Set[Permission]:
    """Get current user's permissions"""
    rbac = RBACManager()
    user = st.session_state.get('user')
    return rbac.get_user_permissions(user)


def is_admin() -> bool:
    """Check if current user is admin"""
    return check_role(Role.ADMIN)


def is_operator() -> bool:
    """Check if current user is operator"""
    return check_role(Role.OPERATOR, Role.ADMIN)


def is_authenticated() -> bool:
    """Check if user is authenticated"""
    return st.session_state.get('authenticated', False) and st.session_state.get('user') is not None


# Global RBAC manager instance
_rbac_manager = None


def get_rbac_manager() -> RBACManager:
    """Get or create global RBAC manager"""
    global _rbac_manager
    if _rbac_manager is None:
        _rbac_manager = RBACManager()
    return _rbac_manager


__all__ = [
    'Permission',
    'Role',
    'RBACManager',
    'check_permission',
    'check_role',
    'get_current_user_role',
    'get_current_user_permissions',
    'is_admin',
    'is_operator',
    'is_authenticated',
    'get_rbac_manager',
    'ROLE_PERMISSIONS',
]
