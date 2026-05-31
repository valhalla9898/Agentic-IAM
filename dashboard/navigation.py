from typing import Any, Callable, Dict, List


# Central navigation configuration for the Streamlit dashboard.
# Each entry is intentionally rich with properties commonly used in
# production-grade projects (permissions, roles, quick actions, badges,
# children, feature flags, help text, ordering, etc.).

NAVIGATION_CONFIG: List[Dict[str, Any]] = [
    {
        "id": "home",
        "label": "Home",
        "icon": "🏠",
        "route": "Home",
        "order": 0,
        "roles": ["admin", "operator", "user"],
        "permissions": [],
        "tooltip": "Overview and quick status",
        "badge": None,
        "children": [],
        "quick_actions": [
            {"id": "refresh", "label": "Refresh", "icon": "🔁"}
        ],
    },

    {
        "id": "health",
        "label": "Health Center",
        "icon": "🏥",
        "route": "🏥 Health Center",
        "order": 10,
        "roles": ["admin", "operator"],
        "permissions": [],
        "tooltip": "System and agent health overview",
        "children": [],
    },

    {
        "id": "activity",
        "label": "Activity Timeline",
        "icon": "🧭",
        "route": "🧭 Activity Timeline",
        "order": 20,
        "roles": ["admin", "operator", "user"],
        "permissions": [],
        "tooltip": "Recent events and changes",
        "children": [],
    },

    {
        "id": "incidents",
        "label": "Incident Response",
        "icon": "🚨",
        "route": "🚨 Incident Response",
        "order": 30,
        "roles": ["admin", "operator"],
        "permissions": ["incident:view"],
        "tooltip": "Investigate and respond to incidents",
        "children": [],
    },

    # Security forensic cluster
    {
        "id": "forensics",
        "label": "Security Forensics",
        "icon": "🕵️",
        "route": None,
        "order": 40,
        "roles": ["admin", "operator"],
        "permissions": [],
        "tooltip": "Forensics and attack analysis",
        "children": [
            {"id": "attack_forensics", "label": "Attack Forensics", "route": "🕵️ Attack Forensics"},
            {"id": "attack_flow", "label": "Attack Flow Lifecycle", "route": "🧪 Attack Flow Lifecycle"},
            {"id": "alert_center", "label": "Alert Center", "route": "🔔 Alert Center"},
        ],
    },

    # Agents cluster
    {
        "id": "agents",
        "label": "Agents",
        "icon": "🤖",
        "route": None,
        "order": 50,
        "roles": ["admin", "operator", "user"],
        "permissions": [],
        "tooltip": "Agent registry and management",
        "children": [
            {"id": "browse_agents", "label": "Browse Agents", "route": "🔍 Browse Agents", "permissions": ["agent:read"]},
            {"id": "register_agent", "label": "Register Agent", "route": "➕ Register Agent", "permissions": ["agent:create"]},
            {"id": "trust_scores", "label": "Agent Trust Scores", "route": "⭐ Agent Trust Scores", "permissions": ["agent:read"]},
        ],
    },

    # Audit & reports
    {
        "id": "audit",
        "label": "Audit & Reports",
        "icon": "📋",
        "route": None,
        "order": 60,
        "roles": ["admin", "operator"],
        "permissions": [],
        "children": [
            {"id": "audit_log", "label": "Audit Log", "route": "📋 Audit Log", "permissions": ["audit:read"]},
            {"id": "reports", "label": "Reports", "route": "📊 Reports", "permissions": ["report:view"]},
            {"id": "compliance", "label": "Compliance Reports", "route": "✅ Compliance Reports", "permissions": ["compliance:read"]},
        ],
    },

    # Admin cluster
    {
        "id": "admin",
        "label": "Administration",
        "icon": "👥",
        "route": None,
        "order": 90,
        "roles": ["admin"],
        "permissions": [],
        "children": [
            {"id": "user_mgmt", "label": "User Management", "route": "👥 User Management", "permissions": ["user:manage"]},
            {"id": "system_config", "label": "System Config", "route": "🔧 System Config", "permissions": ["system:write"]},
            {"id": "integrations", "label": "Integrations", "route": "🔗 Integrations", "permissions": ["integration:manage"]},
        ],
    },

    # Misc / utilities
    {
        "id": "misc",
        "label": "Utilities",
        "icon": "🧰",
        "route": None,
        "order": 200,
        "roles": ["admin", "operator", "user"],
        "children": [
            {"id": "settings", "label": "Settings", "route": "⚙️ Settings", "permissions": ["settings:view"]},
            {"id": "kb", "label": "Security KB", "route": "📚 Security KB"},
        ],
    },
]


def build_navigation(role: str, has_permission: Callable[[str], bool] | None = None) -> List[Dict[str, Any]]:
    """Return filtered navigation config for the given role.

    - `role` is a lowercase role string (e.g., 'admin', 'operator', 'user').
    - `has_permission` is an optional callable(permission:str)->bool used to further filter items.
    """
    role = (role or "").lower()
    has_permission = has_permission or (lambda p: True)

    def item_allowed(item: Dict[str, Any]) -> bool:
        roles = item.get("roles")
        if roles and role not in roles:
            return False
        perms = item.get("permissions") or []
        for p in perms:
            if not has_permission(p):
                return False
        return True

    result: List[Dict[str, Any]] = []
    for item in sorted(NAVIGATION_CONFIG, key=lambda x: x.get("order", 1000)):
        if not item_allowed(item):
            continue
        # shallow copy
        copy_item = {k: v for k, v in item.items() if k != "children"}
        children = []
        for c in item.get("children", []):
            # child-level permissions default to item's permissions
            child_perms = c.get("permissions", item.get("permissions", []))
            if child_perms:
                ok = all(has_permission(p) for p in child_perms)
            else:
                ok = True
            if ok:
                children.append(c)
        if children:
            copy_item["children"] = children
        result.append(copy_item)

    return result


def flatten_labels(nav_config: List[Dict[str, Any]]) -> List[str]:
    """Return a flattened list of route labels for compatibility with existing code.

    If an item has a `route` that is a string, that string is used as the page label.
    Otherwise the `label` is used.
    """
    labels: List[str] = []
    for item in nav_config:
        if item.get("route"):
            labels.append(item.get("route"))
        else:
            labels.append(item.get("label"))
        for c in item.get("children", []):
            labels.append(c.get("route") or c.get("label"))
    return labels
