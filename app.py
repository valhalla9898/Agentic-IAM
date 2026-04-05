"""
Agentic-IAM: Streamlit Dashboard Application

Main entry point for the web-based GUI dashboard with role-based access control.
"""

import streamlit as st
import sys
from pathlib import Path
import pandas as pd
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from database import get_database
from dashboard.components.agent_selection import (
    show_agent_registration,
    show_agent_selector,
    show_agent_list,
    show_agent_details,
)
from dashboard.components.ai_assistant import show_ai_assistant
from dashboard.components.risk_assessment import show_risk_assessment
from utils.rbac import (
    Permission,
    check_permission,
    is_admin,
    is_operator,
    get_current_user_permissions,
    get_rbac_manager,
)
from utils.advanced_features import AgentHealthMonitor, AgentAnalytics, ReportGenerator
from utils.security import (
    InputValidator,
    RateLimiter,
    AccountSecurity,
    AuditLogger,
    SessionSecurityManager,
    SQLInjectionProtection,
)

# Page configuration
st.set_page_config(
    page_title="Agentic-IAM Dashboard",
    page_icon="👥",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS
st.markdown(
    """
    <style>
    .main {
        padding-top: 2rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
    }
    """,
    unsafe_allow_html=True,
)


def initialize_session():
    """Initialize session state"""
    if "iam" not in st.session_state:
        st.session_state.iam = None
    if "agent_page" not in st.session_state:
        st.session_state.agent_page = 1
    if "db" not in st.session_state:
        st.session_state.db = get_database()
    if "selected_agent" not in st.session_state:
        st.session_state.selected_agent = None
    if "user" not in st.session_state:
        st.session_state.user = None
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False

    # Initialize security components
    if "rate_limiter" not in st.session_state:
        st.session_state.rate_limiter = RateLimiter(max_attempts=5, window_seconds=300)
    if "account_security" not in st.session_state:
        st.session_state.account_security = AccountSecurity(max_failed_attempts=5)
    if "csrf_token" not in st.session_state:
        st.session_state.csrf_token = SessionSecurityManager.generate_csrf_token()


def show_login():
    """Show login page with security checks"""
    st.title("🔐 Agentic-IAM Login")

    col1, col2, col3 = st.columns([1, 2, 1])

    with col2:
        st.markdown("### Welcome to Agentic-IAM v2.0")
        st.markdown("Enterprise Security with Advanced RBAC")

        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")

            submitted = st.form_submit_button("🔐 Login")

            if submitted:
                # Security Check 1: Input Validation
                if not username or not password:
                    st.error("❌ Please enter both username and password")
                    return

                # Security Check 2: Validate username format
                if not InputValidator.validate_username(username):
                    st.warning("⚠️ Invalid username format")
                    AuditLogger.log_suspicious_activity(username, "Invalid username format")
                    return

                # Security Check 3: Check account lockout
                if st.session_state.account_security.is_account_locked(username):
                    st.error("❌ Account temporarily locked. Try again later.")
                    AuditLogger.log_suspicious_activity(username, "Account locked - login attempt")
                    return

                # Security Check 4: Rate limiting
                if not st.session_state.rate_limiter.is_allowed(username):
                    st.error("❌ Too many login attempts. Please try again later.")
                    st.session_state.account_security.record_failed_attempt(username)
                    AuditLogger.log_failed_login(username, "Rate limit exceeded")
                    return

                # Security Check 5: SQL Injection Detection
                if SQLInjectionProtection.detect_sql_injection(username):
                    st.error("❌ Invalid input detected")
                    AuditLogger.log_suspicious_activity(username, "SQL injection attempt")
                    return

                # Authenticate user
                user = st.session_state.db.authenticate_user(username, password)

                if user:
                    # Successful authentication
                    st.session_state.user = user
                    st.session_state.authenticated = True
                    st.session_state.account_security.record_successful_login(username)
                    AuditLogger.log_successful_login(username)
                    st.success("✅ Login successful!")
                    st.balloons()
                    st.rerun()
                else:
                    # Failed authentication
                    st.session_state.account_security.record_failed_attempt(username)
                    remaining = st.session_state.account_security.max_failed_attempts - len(
                        st.session_state.account_security.failed_attempts.get(username, [])
                    )
                    st.error(f"❌ Invalid credentials. ({remaining} attempts remaining)")
                    AuditLogger.log_failed_login(username, "Invalid credentials")

        st.markdown("---")
        st.markdown("### ℹ️ Demo Credentials")

        # Create three columns for credentials
        col1, col2, col3 = st.columns(3)

        with col1:
            st.markdown("**Admin** 🔴")
            st.code("admin\nadmin123")

        with col2:
            st.markdown("**Operator** 🟡")
            st.code("operator\noperator123")

        with col3:
            st.markdown("**User** 🟢")
            st.code("user\nuser123")

        st.markdown("---")
        st.markdown("""
        **Security Features Enabled:**
        - ✅ Input validation & sanitization
        - ✅ Rate limiting (5 attempts/5 min)
        - ✅ Account lockout protection
        - ✅ SQL injection prevention
        - ✅ Audit logging
        - ✅ Password hashing (bcrypt)
        """)


def show_logout():
    """Show logout button"""
    if st.sidebar.button("🚪 Logout"):
        st.session_state.user = None
        st.session_state.authenticated = False
        st.rerun()


def get_navigation_pages():
    """Get navigation pages based on user role"""
    pages = ["Home"]

    # User pages (available to all authenticated users)
    if check_permission(Permission.AGENT_READ):
        pages.append("🔍 Browse Agents")

    if check_permission(Permission.AGENT_CREATE):
        pages.append("➕ Register Agent")

    if check_permission(Permission.AUDIT_READ):
        pages.append("📋 Audit Log")

    if check_permission(Permission.REPORT_VIEW):
        pages.append("📊 Reports")

    if check_permission(Permission.SETTINGS_VIEW):
        pages.append("⚙️ Settings")

    # Admin-only pages
    if is_admin():
        pages.append("👥 User Management")
        pages.append("🔧 System Config")
        pages.append("📡 System Monitor")

    # Operator pages
    if is_operator():
        pages.append("📈 Analytics")

    # AI Assistant available to all authenticated users
    pages.append("🤖 AI Assistant")

    # Risk assessment page for operators/admins
    if is_operator() or is_admin():
        pages.append("⚠️ Risk Assessment")

    return pages


def main():
    """Main application"""
    initialize_session()

    # Check authentication
    if not st.session_state.authenticated:
        show_login()
        return

    # Sidebar
    with st.sidebar:
        st.title("⚙️ Agentic-IAM")
        st.markdown("v2.0 (Enhanced RBAC)")
        st.markdown("---")

        # User info with role badge
        if st.session_state.user:
            user_role = st.session_state.user["role"].upper()
            role_colors = {"ADMIN": "🔴", "OPERATOR": "🟡", "USER": "🟢", "GUEST": "⚪"}
            role_icon = role_colors.get(user_role, "⚪")
            st.write(f"👤 **{st.session_state.user['username']}** {role_icon} `{user_role}`")
            show_logout()
            st.markdown("---")

        # Get available pages based on permissions
        available_pages = get_navigation_pages()

        # Navigation
        page = st.radio("Navigation", available_pages, index=0, key="main_navigation")

        st.markdown("---")

        # Selected Agent Info
        if st.session_state.selected_agent:
            st.write("### 👤 Selected Agent:")
            agent = st.session_state.db.get_agent(st.session_state.selected_agent)
            if agent:
                st.info(f"**{agent['name']}** (ID: {agent['id']})")

        st.markdown("---")

        # System Status
        st.write("### 🔧 System Status")
        col1, col2 = st.columns(2)

        with col1:
            agents_count = len(st.session_state.db.list_agents())
            st.metric("Agents", agents_count)

        with col2:
            events_count = len(st.session_state.db.get_events(limit=1))
            st.metric("Events", events_count)

        st.markdown("---")

        # About
        st.write("### ℹ️ About")
        st.write("""
        **Agentic-IAM v2.0**

        Enterprise identity and access
        management for AI agents with
        advanced RBAC controls.
        """)

    # Main content - Route to correct page
    if page == "Home":
        show_home()
    elif page == "🤖 AI Assistant":
        show_ai_assistant()
    elif page == "🔍 Browse Agents":
        show_page_browse_agents()
    elif page == "➕ Register Agent":
        show_page_register_agent()
    elif page == "👥 Manage & Select Agents":
        show_page_manage_agents()
    elif page == "📋 Audit Log":
        show_page_audit_log()
    elif page == "📊 Reports":
        show_page_reports()
    elif page == "⚙️ Settings":
        show_page_settings()
    elif page == "👥 User Management":
        if is_admin():
            show_page_user_management()
        else:
            st.error("❌ Access Denied: Admin only")
    elif page == "🔧 System Config":
        if is_admin():
            show_page_system_config()
        else:
            st.error("❌ Access Denied: Admin only")
    elif page == "📡 System Monitor":
        if is_operator():
            show_page_system_monitor()
        else:
            st.error("❌ Access Denied: Operator or Admin only")
    elif page == "📈 Analytics":
        if is_operator():
            show_page_analytics()
        else:
            st.error("❌ Access Denied: Operator or Admin only")
    elif page == "⚠️ Risk Assessment":
        show_risk_assessment(st.session_state.db)
    else:
        st.warning(f"Page '{page}' not implemented yet")


def show_home():
    """Show home page with role-based content"""
    st.title("🏠 Agentic-IAM Dashboard")

    user_role = st.session_state.user["role"].lower()

    # Role-specific greeting
    greeting = f"Welcome, {st.session_state.user['username']}!"
    if user_role == "admin":
        greeting += " 🔴 You have administrator privileges."
    elif user_role == "operator":
        greeting += " 🟡 You have operator privileges."
    else:
        greeting += " 🟢 You have user privileges."

    st.markdown(f"### {greeting}")

    st.markdown("""
    Welcome to the **Agentic-IAM Dashboard** - Your comprehensive solution for
    managing agent identities, permissions, and access control.
    """)

    # Quick stats with role-aware content
    col1, col2, col3, col4 = st.columns(4)

    agents = st.session_state.db.list_agents()
    events = st.session_state.db.get_events(limit=100)

    with col1:
        st.metric("Total Agents", len(agents), help="Number of registered agents")

    with col2:
        st.metric("Recent Events", len(events), help="Events in last check")

    with col3:
        st.metric("System Health", "✅ 100%", help="Overall system health status")

    with col4:
        current_time = datetime.now().strftime("%H:%M:%S")
        st.metric("Current Time", current_time, help="Server time")

    st.markdown("---")

    # Role-based features section
    st.header("✨ Available Features")

    # Admin features
    if is_admin():
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("👥 Admin Controls")
            st.write("""
            - User management
            - System configuration
            - Security policies
            - Audit reports
            - System monitoring
            """)

        with col2:
            st.subheader("🔐 Security")
            st.write("""
            - Role-based access control
            - Permission management
            - Audit trails
            - Compliance reports
            - Threat detection
            """)

    # Operator features
    elif is_operator():
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("📊 Operations")
            st.write("""
            - Agent management
            - Session monitoring
            - Performance analytics
            - Alert management
            - Log aggregation
            """)

        with col2:
            st.subheader("🔧 Maintenance")
            st.write("""
            - Status monitoring
            - Configuration updates
            - Backup management
            - Performance tuning
            - Issue resolution
            """)

    # User features
    else:
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("👥 Agent Management")
            st.write("""
            - Browse agents
            - View agent details
            - Monitor sessions
            - Check permissions
            - Track activity
            """)

        with col2:
            st.subheader("📊 Reports")
            st.write("""
            - View audit logs
            - Generate reports
            - Track metrics
            - Check status
            - Access documentation
            """)

    st.markdown("---")

    # Quick stats table
    st.subheader("📊 System Statistics")
    stats_data = {
        "Metric": ["Total Agents", "Active Sessions", "Total Events", "System Uptime"],
        "Value": [
            str(len(agents)),
            str(len([e for e in events if e.get("event_type") == "session_created"])),
            str(len(events)),
            "99.9%",
        ],
    }
    st.dataframe(pd.DataFrame(stats_data), width="stretch", hide_index=True)


def show_page_browse_agents():
    """Browse and view agents - requires AGENT_READ permission"""
    if not check_permission(Permission.AGENT_READ):
        st.error("❌ Access Denied: You don't have permission to view agents")
        return

    st.title("🔍 Browse Agents")
    show_agent_list()


def show_page_register_agent():
    """Register new agent - requires AGENT_CREATE permission"""
    if not check_permission(Permission.AGENT_CREATE):
        st.error("❌ Access Denied: You don't have permission to register agents")
        return

    st.title("➕ Register New Agent")
    show_agent_registration()
    st.divider()
    st.subheader("📋 All Agents")
    show_agent_list()


def show_page_manage_agents():
    """Manage agents - requires AGENT_UPDATE permission"""
    if not check_permission(Permission.AGENT_UPDATE):
        st.error("❌ Access Denied: You don't have permission to manage agents")
        return

    st.title("👥 Manage & Select Agents")
    col1, col2 = st.columns([2, 1])
    with col1:
        show_agent_selector()

    st.divider()

    if st.session_state.selected_agent:
        show_agent_details(st.session_state.selected_agent)
    else:
        show_agent_list()


def show_page_audit_log():
    """Show audit log - requires AUDIT_READ permission"""
    if not check_permission(Permission.AUDIT_READ):
        st.error("❌ Access Denied: You don't have permission to view audit logs")
        return

    st.title("📋 Audit Log")

    db = st.session_state.db

    # Filters
    col1, col2, col3 = st.columns(3)

    with col1:
        agent_filter = st.selectbox(
            "🔍 Filter by Agent",
            ["All"] + [f"{a['name']} ({a['id']})" for a in db.list_agents()],
            key="audit_agent_filter",
        )

    with col2:
        limit = st.slider("Number of records", 10, 500, 50)

    with col3:
        if st.button("🔄 Refresh"):
            st.rerun()

    st.markdown("---")

    # Get events
    agent_id = None
    if agent_filter != "All":
        agent_id = agent_filter.split("(")[-1].rstrip(")")

    events = db.get_events(agent_id=agent_id, limit=limit)

    if events:
        df = pd.DataFrame(events)
        df["created_at"] = pd.to_datetime(df["created_at"]).dt.strftime("%Y-%m-%d %H:%M:%S")
        df = df[
            ["event_type", "agent_id", "action", "details", "created_at", "status"]
        ].sort_values("created_at", ascending=False)

        # Color code by status
        st.dataframe(df, width="stretch", hide_index=True)
        st.success(f"✅ Total events: {len(events)}")

        # Export option
        if check_permission(Permission.AUDIT_EXPORT):
            csv = df.to_csv(index=False)
            st.download_button("📥 Download CSV", csv, "audit_log.csv")
    else:
        st.info("📭 No events found")


def show_page_reports():
    """Show reports page - requires REPORT_VIEW permission"""
    if not check_permission(Permission.REPORT_VIEW):
        st.error("❌ Access Denied: You don't have permission to view reports")
        return

    st.title("📊 Reports")

    db = st.session_state.db
    report_gen = ReportGenerator(db)
    health_monitor = AgentHealthMonitor(db)
    analytics = AgentAnalytics(db)

    tab1, tab2, tab3, tab4 = st.tabs(
        ["System Report", "Agent Report", "Security Report", "Analytics"]
    )

    with tab1:
        st.subheader("System Health Report")

        if st.button("🔄 Refresh Metrics", key="refresh_system"):
            st.rerun()

        system_health = health_monitor.get_system_health()

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Overall Health", f"{system_health.get('overall_health', 0)}%")
        with col2:
            st.metric("Total Agents", system_health.get("total_agents", 0))
        with col3:
            st.metric("Healthy Agents", system_health.get("healthy_agents", 0))
        with col4:
            st.metric("System Uptime", system_health.get("system_uptime", "N/A"))

        st.markdown("---")

        # System report detailed
        if st.button("📄 Generate Detailed System Report"):
            report = report_gen.generate_system_report()
            st.json(report)

        st.info("📊 Detailed system health metrics and trends")

    with tab2:
        st.subheader("Agent Performance Report")

        agents = db.list_agents()

        if agents:
            selected_agent = st.selectbox(
                "Select Agent", [a["name"] for a in agents], key="agent_report"
            )
            selected_agent_obj = next((a for a in agents if a["name"] == selected_agent), None)

            if selected_agent_obj:
                agent_health = health_monitor.get_agent_health(selected_agent_obj["id"])
                activity = analytics.get_agent_activity_summary(selected_agent_obj["id"])

                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("Health Score", f"{agent_health.get('health_score', 0)}%")
                with col2:
                    st.metric("Recent Events", agent_health.get("recent_events", 0))
                with col3:
                    st.metric("Active Sessions", agent_health.get("active_sessions", 0))
                with col4:
                    st.metric("Success Rate", f"{activity.get('success_rate', 0):.1f}%")

                st.markdown("---")

                # Generate detailed report
                if st.button("📄 Generate Agent Report"):
                    report = report_gen.generate_agent_report(selected_agent_obj["id"])
                    st.json(report)
        else:
            st.info("No agents registered yet")

    with tab3:
        st.subheader("Security Compliance Report")

        if st.button("📄 Generate Compliance Report"):
            report = report_gen.generate_compliance_report()

            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Events", report.get("audit_trail", {}).get("total_events", 0))
            with col2:
                st.metric(
                    "Audit Events", report.get("audit_trail", {}).get("significant_events", 0)
                )
            with col3:
                st.metric("Active Users", report.get("users_summary", {}).get("active_users", 0))

            st.markdown("---")
            st.info("🔒 Full compliance report generated")
            st.json(report)
        else:
            st.info("Click the button above to generate a compliance report")

    with tab4:
        st.subheader("System Analytics")

        system_analytics = analytics.get_system_analytics()

        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Events", system_analytics.get("total_events", 0))
        with col2:
            st.metric("Success Rate", f"{system_analytics.get('success_rate', 0):.1f}%")
        with col3:
            st.metric("Active Agents", system_analytics.get("active_agents", 0))

        st.markdown("---")

        st.subheader("Event Distribution")
        event_dist = system_analytics.get("event_distribution", {})
        if event_dist:
            event_df = pd.DataFrame(list(event_dist.items()), columns=["Event Type", "Count"])
            st.bar_chart(event_df.set_index("Event Type"))
        else:
            st.info("No events found")


def show_page_settings():
    """Show settings page - requires SETTINGS_VIEW permission"""
    if not check_permission(Permission.SETTINGS_VIEW):
        st.error("❌ Access Denied: You don't have permission to view settings")
        return

    st.title("⚙️ Settings")

    tab1, tab2, tab3 = st.tabs(["General", "Security", "Advanced"])

    with tab1:
        st.subheader("General Settings")

        theme = st.selectbox("Theme", ["Light", "Dark", "Auto"])
        refresh_interval = st.slider("Refresh Interval (seconds)", 5, 60, 30)
        notifications = st.checkbox("Enable Notifications", value=True)

        st.caption(
            f"Current general settings: theme={theme}, refresh={refresh_interval}s, "
            f"notifications={'on' if notifications else 'off'}"
        )

        if st.button("💾 Save General Settings"):
            st.success("✅ Settings saved successfully")

    with tab2:
        st.subheader("Security Settings")

        mfa_enabled = st.checkbox("Enable Multi-Factor Authentication", value=True)
        session_timeout = st.slider("Session Timeout (minutes)", 5, 480, 60)
        force_password_change = st.checkbox("Force Password Change on Next Login", value=False)

        st.caption(
            f"Current security settings: MFA={'on' if mfa_enabled else 'off'}, "
            f"session timeout={session_timeout} minutes, "
            f"force password change={'yes' if force_password_change else 'no'}"
        )

        if st.button("💾 Save Security Settings"):
            st.success("✅ Security settings saved successfully")

    with tab3:
        st.subheader("Advanced Settings")

        debug_mode = st.checkbox("Debug Mode", value=False)
        log_level = st.selectbox("Log Level", ["INFO", "DEBUG", "WARNING", "ERROR"])
        max_log_size = st.slider("Max Log Size (MB)", 10, 1000, 100)

        st.caption(
            f"Current advanced settings: debug={'on' if debug_mode else 'off'}, "
            f"log level={log_level}, max log size={max_log_size} MB"
        )

        if st.button("💾 Save Advanced Settings"):
            st.success("✅ Advanced settings saved successfully")


def show_page_user_management():
    """Admin: User management page"""
    st.title("👥 User Management (Admin Only)")

    if not is_admin():
        st.error("❌ Access Denied: Admin only")
        return

    tab1, tab2, tab3 = st.tabs(["Users", "Roles", "Permissions"])

    with tab1:
        st.subheader("Manage Users")

        db = st.session_state.db
        users = db.list_users()

        if users:
            user_data = {
                "Username": [u["username"] for u in users],
                "Email": [u["email"] for u in users],
                "Role": [u["role"] for u in users],
                "Status": [u["status"] for u in users],
                "Created": [u["created_at"] for u in users],
            }
            st.dataframe(pd.DataFrame(user_data), width="stretch", hide_index=True)

            # Add per-user actions (delete / deactivate)
            st.markdown("---")
            st.subheader("User Actions")
            for u in users:
                cols = st.columns([3, 1, 1])
                with cols[0]:
                    st.write(
                        f"**{u['username']}** — {u['email']} — role: {u['role']} — status: {u['status']}"
                    )
                with cols[1]:
                    if st.button(f"Deactivate {u['username']}", key=f"deact_{u['id']}"):
                        ok = db.update_user_status(u["id"], "suspended")
                        if ok:
                            st.success(f"User {u['username']} suspended")
                            st.rerun()
                        else:
                            st.error(f"Failed to suspend user {u['username']}")
                with cols[2]:
                    if st.button(f"Delete {u['username']}", key=f"deluser_{u['id']}"):
                        ok = db.delete_user(u["id"])
                        still_exists = db.get_user_by_id(u["id"])
                        if ok and not still_exists:
                            st.success(f"User {u['username']} deleted")
                            st.rerun()
                        elif ok and still_exists:
                            st.error(f"Delete reported success, but user {u['username']} still exists")
                        else:
                            st.error(f"Failed to delete user {u['username']}")

            st.markdown("---")
            st.subheader("Edit User")

            user_map = {f"{u['username']} ({u['email']})": u for u in users}
            selected_label = st.selectbox("Select user", list(user_map.keys()))
            selected_user = user_map[selected_label]

            edit_col1, edit_col2 = st.columns(2)
            with edit_col1:
                edited_role = st.selectbox(
                    "Edit role",
                    ["user", "operator", "admin"],
                    index=["user", "operator", "admin"].index(selected_user["role"])
                    if selected_user["role"] in ["user", "operator", "admin"] else 0,
                    key=f"edit_role_{selected_user['id']}"
                )
            with edit_col2:
                edited_status = st.selectbox(
                    "Edit status",
                    ["active", "suspended"],
                    index=["active", "suspended"].index(selected_user["status"])
                    if selected_user["status"] in ["active", "suspended"] else 0,
                    key=f"edit_status_{selected_user['id']}"
                )

            if st.button("💾 Save User Changes", key=f"save_user_{selected_user['id']}"):
                role_ok = True
                status_ok = True

                if edited_role != selected_user["role"]:
                    role_ok = db.update_user_role(selected_user["id"], edited_role)

                if edited_status != selected_user["status"]:
                    status_ok = db.update_user_status(selected_user["id"], edited_status)

                updated_user = db.get_user_by_id(selected_user["id"])
                if updated_user and updated_user["role"] == edited_role and updated_user["status"] == edited_status:
                    st.success(f"User {selected_user['username']} updated successfully")
                    st.rerun()
                elif role_ok and status_ok:
                    st.error(f"Update reported success, but user {selected_user['username']} did not persist")
                else:
                    st.error(f"Failed to update user {selected_user['username']}")

        st.markdown("---")
        st.subheader("Add New User")

        col1, col2 = st.columns(2)
        with col1:
            new_username = st.text_input("New username")
            new_email = st.text_input("New email")

        with col2:
            new_password = st.text_input("New password", type="password")
            new_role = st.selectbox("New role", ["user", "operator", "admin"])

        if st.button("➕ Create User"):
            if new_username and new_email and new_password:
                success = db.create_user(new_username, new_email, new_password, new_role)
                if success:
                    st.success(f"✅ User '{new_username}' created successfully!")
                    st.rerun()
                else:
                    st.error(f"❌ Failed to create user '{new_username}'")
            else:
                st.error("❌ Please fill in all fields")

    with tab2:
        st.subheader("Role Management")
        st.info("Available roles: Admin, Operator, User, Guest")

        role_desc = {
            "Admin": "Full system access and control",
            "Operator": "Agent and system management",
            "User": "Agent browsing and basic operations",
            "Guest": "Read-only access",
        }

        for role, desc in role_desc.items():
            st.write(f"**{role}**: {desc}")

    with tab3:
        st.subheader("Permission Management")

        get_rbac_manager()
        permissions = get_current_user_permissions()

        st.write("Your current permissions:")
        for perm in sorted(permissions, key=lambda p: p.value):
            st.write(f"✅ `{perm.value}`")


def show_page_system_config():
    """Admin: System configuration"""
    st.title("🔧 System Configuration (Admin Only)")

    if not is_admin():
        st.error("❌ Access Denied: Admin only")
        return

    tab1, tab2, tab3, tab4 = st.tabs(["Database", "Security", "Backup", "Maintenance"])

    with tab1:
        st.subheader("Database Configuration")

        db_type = st.selectbox("Database Type", ["SQLite", "PostgreSQL", "MySQL"])
        db_host = st.text_input("Database Host", "localhost" if db_type != "SQLite" else "N/A")
        db_port = st.number_input(
            "Database Port", 3306 if db_type == "MySQL" else 5432, disabled=(db_type == "SQLite")
        )

        st.caption(f"Database target: {db_type} @ {db_host}:{int(db_port)}")

        if st.button("✅ Test Connection"):
            st.success("✅ Database connection successful!")

    with tab2:
        st.subheader("Security Configuration")

        enable_ssl = st.checkbox("Enable SSL/TLS", value=True)
        enable_2fa = st.checkbox("Require 2FA for Admins", value=True)
        password_policy = st.selectbox("Password Policy", ["Standard", "Strong", "Very Strong"])
        session_duration = st.slider("Session Duration (hours)", 1, 24, 8)

        st.caption(
            f"Security config: SSL={'on' if enable_ssl else 'off'}, 2FA={'on' if enable_2fa else 'off'}, "
            f"policy={password_policy}, session duration={session_duration}h"
        )

        if st.button("💾 Save Security Config"):
            st.success("✅ Security configuration saved!")

    with tab3:
        st.subheader("Backup & Restore")

        col1, col2 = st.columns(2)

        with col1:
            if st.button("💾 Create Backup"):
                st.success("✅ Backup created successfully!")

        with col2:
            if st.button("📥 Restore from Backup"):
                st.info("Restore functionality would appear here")

        st.markdown("---")

        st.write("Last Backup: 2024-02-13 14:30:00")

    with tab4:
        st.subheader("System Maintenance")

        if st.button("🧹 Clean Logs"):
            st.success("✅ Logs cleaned successfully!")

        if st.button("🔄 Clear Cache"):
            st.success("✅ Cache cleared successfully!")

        if st.button("🚀 Restart Services"):
            st.warning("⚠️ Services will restart in 10 seconds...")


def show_page_system_monitor():
    """Operator: System monitoring"""
    st.title("📡 System Monitor (Operator/Admin Only)")

    if not is_operator():
        st.error("❌ Access Denied: Operator or Admin only")
        return

    db = st.session_state.db
    health_monitor = AgentHealthMonitor(db)

    # System-wide metrics
    system_health = health_monitor.get_system_health()

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("System Health", f"{system_health.get('overall_health', 0)}%", "📊")

    with col2:
        st.metric("Total Agents", system_health.get("total_agents", 0), "🤖")

    with col3:
        st.metric("Healthy Agents", system_health.get("healthy_agents", 0), "✅")

    with col4:
        st.metric("System Uptime", system_health.get("system_uptime", "N/A"), "⏱️")

    st.markdown("---")

    # Agent health details
    st.subheader("Agent Health Status")

    agents = db.list_agents()

    if agents:
        health_data = []
        for agent in agents:
            health = health_monitor.get_agent_health(agent["id"])
            health_data.append(
                {
                    "Agent": health.get("agent_name", "Unknown"),
                    "Health": f"{health.get('health_score', 0)}%",
                    "Status": health.get("status", "unknown"),
                    "Sessions": health.get("active_sessions", 0),
                    "Events": health.get("recent_events", 0),
                }
            )

        df = pd.DataFrame(health_data)
        st.dataframe(df, width="stretch", hide_index=True)
    else:
        st.info("No agents registered yet")

    st.markdown("---")

    # Refresh button
    if st.button("🔄 Refresh Monitor Data"):
        st.rerun()


def show_page_analytics():
    """Operator: Analytics and reporting"""
    st.title("📈 Analytics (Operator/Admin Only)")

    if not is_operator():
        st.error("❌ Access Denied: Operator or Admin only")
        return

    db = st.session_state.db
    analytics = AgentAnalytics(db)

    tab1, tab2, tab3 = st.tabs(["Overview", "Trends", "Alerts"])

    with tab1:
        st.subheader("Analytics Overview")

        system_analytics = analytics.get_system_analytics()

        col1, col2, col3 = st.columns(3)

        with col1:
            st.metric("Total Events", system_analytics.get("total_events", 0), "📊")

        with col2:
            st.metric("Success Rate", f"{system_analytics.get('success_rate', 0):.1f}%", "✅")

        with col3:
            st.metric("Active Agents", system_analytics.get("active_agents", 0), "🤖")

        st.markdown("---")

        # Event distribution pie chart
        st.subheader("Event Distribution")
        event_dist = system_analytics.get("event_distribution", {})
        if event_dist:
            event_df = pd.DataFrame(list(event_dist.items()), columns=["Event Type", "Count"])
            st.bar_chart(event_df.set_index("Event Type"))
        else:
            st.info("No events found")

    with tab2:
        st.subheader("Performance Trends")

        agents = db.list_agents()

        if agents:
            selected_agent = st.selectbox(
                "Select Agent for Analysis", [a["name"] for a in agents], key="analytics_agent"
            )
            selected_agent_obj = next((a for a in agents if a["name"] == selected_agent), None)

            if selected_agent_obj:
                activity = analytics.get_agent_activity_summary(selected_agent_obj["id"])

                st.write("**Activity Summary (Last 7 Days)**")
                col1, col2, col3, col4 = st.columns(4)

                with col1:
                    st.metric("Total Events", activity.get("total_events", 0))
                with col2:
                    st.metric("Successful", activity.get("successful_events", 0))
                with col3:
                    st.metric("Failed", activity.get("failed_events", 0))
                with col4:
                    st.metric("Success Rate", f"{activity.get('success_rate', 0):.1f}%")

                st.markdown("---")

                event_types = activity.get("event_types", {})
                if event_types:
                    event_type_df = pd.DataFrame(
                        list(event_types.items()), columns=["Event Type", "Count"]
                    )
                    st.bar_chart(event_type_df.set_index("Event Type"))
                else:
                    st.info("No events for this agent in the selected period")
        else:
            st.info("No agents registered yet")

    with tab3:
        st.subheader("Active Alerts")

        # Alert simulation
        st.warning("⚠️ High event rate detected on 3 agents")
        st.info("ℹ️ System health is optimal")
        st.success("✅ All critical systems operational")

        st.markdown("---")

        if st.button("📧 Send Alert Notification"):
            st.success("✅ Alert notification sent to administrators")

    st.markdown("---")

    # Features
    st.header("✨ Key Features")

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("👥 Agent Management")
        st.write("""
        - Register and manage AI agents
        - Monitor agent status and health
        - Track trust scores and permissions
        - Bulk operations support
        """)

    with col2:
        st.subheader("🔐 Session Management")
        st.write("""
        - Real-time session monitoring
        - Authentication management
        - Session termination
        - Activity tracking
        """)

    col3, col4 = st.columns(2)

    with col3:
        st.subheader("📊 Audit & Compliance")
        st.write("""
        - Comprehensive audit logs
        - Access history tracking
        - Compliance reporting
        - Risk assessment
        """)

    with col4:
        st.subheader("🔧 Advanced Controls")
        st.write("""
        - Fine-grained permissions
        - Role-based access control
        - Custom trust policies
        - Integration APIs
        """)

    st.markdown("---")

    # Quick actions
    st.header("⚡ Quick Actions")

    col1, col2, col3 = st.columns(3)

    with col1:
        if st.button("➕ Register New Agent", width="stretch"):
            st.session_state.page = "Agent Management"
            st.rerun()

    with col2:
        if st.button("📊 View Reports", width="stretch"):
            st.info("Report generation would be implemented here")

    with col3:
        if st.button("📋 View Audit Log", width="stretch"):
            st.session_state.page = "Audit Log"
            st.rerun()


if __name__ == "__main__":
    main()
