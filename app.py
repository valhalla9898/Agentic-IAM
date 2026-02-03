"""
Agentic-IAM: Streamlit Dashboard Application

Main entry point for the web-based GUI dashboard with authentication.
"""
import streamlit as st
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from dashboard.components.login import (
    show_login_page,
    is_authenticated,
    get_current_user,
    is_admin,
    show_user_profile,
)
from dashboard.components.user_management import show_user_management
from dashboard.components.agent_selection import (
    show_agent_registration,
    show_agent_selector,
    show_agent_list,
    show_agent_details,
)
from database import get_database


# Page configuration
st.set_page_config(
    page_title="Agentic-IAM Dashboard",
    page_icon="AI",
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
    .app-header {
        background: linear-gradient(120deg, #0f172a 0%, #1e293b 45%, #0b7285 100%);
        color: #f8fafc;
        padding: 1.25rem 1.5rem;
        border-radius: 0.75rem;
        margin-bottom: 1.25rem;
        box-shadow: 0 10px 20px rgba(15, 23, 42, 0.2);
    }
    .app-header h1 {
        margin: 0;
        font-size: 1.75rem;
        font-weight: 700;
        letter-spacing: 0.5px;
    }
    .app-header p {
        margin: 0.25rem 0 0 0;
        color: #cbd5f5;
        font-size: 0.95rem;
    }
    </style>
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
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
    if "current_user" not in st.session_state:
        st.session_state.current_user = None
    if "page" not in st.session_state:
        st.session_state.page = "Home"
    if "nav_page" not in st.session_state:
        st.session_state.nav_page = st.session_state.page
    if "requested_page" not in st.session_state:
        st.session_state.requested_page = None
    if "mode" not in st.session_state:
        st.session_state.mode = "Info"
    if "sidebar_mode" not in st.session_state:
        st.session_state.sidebar_mode = st.session_state.mode
    if "settings_mode" not in st.session_state:
        st.session_state.settings_mode = st.session_state.mode


def get_mode_descriptions():
    return {
        "Info": "Normal operations and general notifications.",
        "Debug": "Verbose details for troubleshooting and development.",
        "Monitor": "Observability-focused view with health signals.",
        "Warning/Errors": "Highlights warnings and critical error states.",
    }


def render_app_header():
    st.markdown(
        """
        <div class="app-header">
            <h1>Agentic-IAM Dashboard</h1>
            <p>Identity and access management console for AI agents</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def get_nav_options(user_is_admin: bool):
    if user_is_admin:
        return ["Home", "Users", "Agents", "Register Agent", "Select Agent", "Audit Log", "Settings"]
    return ["Home", "Select Agent", "Audit Log", "Settings"]


def main():
    """Main application"""
    initialize_session()

    # Check authentication
    if not is_authenticated():
        show_login_page()
        return

    # Get current user and role
    current_user = get_current_user()
    user_is_admin = is_admin()

    if st.session_state.requested_page:
        st.session_state.page = st.session_state.requested_page
        st.session_state.nav_page = st.session_state.requested_page
        st.session_state.requested_page = None

    nav_options = get_nav_options(user_is_admin)
    if st.session_state.page not in nav_options:
        st.session_state.page = "Home"
    if st.session_state.nav_page not in nav_options:
        st.session_state.nav_page = st.session_state.page

    # Keep sidebar selector in sync with global mode before widget creation
    if st.session_state.sidebar_mode != st.session_state.mode:
        st.session_state.sidebar_mode = st.session_state.mode

    # Sidebar
    with st.sidebar:
        st.title("Agentic-IAM")

        # Display user profile
        show_user_profile()

        st.markdown("---")

        # Navigation based on role
        st.markdown("### Admin Dashboard" if user_is_admin else "### User Dashboard")
        st.radio(
            "Navigation",
            nav_options,
            index=nav_options.index(st.session_state.nav_page),
            key="nav_page",
        )
        if st.session_state.page != st.session_state.nav_page:
            st.session_state.page = st.session_state.nav_page

        st.markdown("---")

        # Selected Agent Info
        if st.session_state.selected_agent:
            st.write("### Selected Agent")
            agent = st.session_state.db.get_agent(st.session_state.selected_agent)
            if agent:
                st.info(f"**{agent['name']}** (ID: {agent['id']})")

        st.markdown("---")

        # System Status
        st.write("### System Status")
        st.info("System Ready")

        st.markdown("---")

        # Mode selector
        st.write("### Mode")
        mode_descriptions = get_mode_descriptions()
        st.selectbox(
            "Select mode",
            list(mode_descriptions.keys()),
            key="sidebar_mode",
        )
        if st.session_state.mode != st.session_state.sidebar_mode:
            st.session_state.mode = st.session_state.sidebar_mode
        st.caption(mode_descriptions.get(st.session_state.mode, ""))

        st.markdown("---")

        # About
        st.write("### About")
        st.write(
            """
            **Agentic-IAM v1.0**

            Comprehensive identity and access management system for AI agents.
            """
        )

    render_app_header()

    # Main content based on navigation
    page = st.session_state.page
    if page == "Home":
        show_home(user_is_admin)
    elif page == "Users" and user_is_admin:
        show_user_management()
    elif page == "Agents" and user_is_admin:
        st.title("Agent Management")
        show_agent_list()
        st.divider()
        if st.session_state.selected_agent:
            show_agent_details(st.session_state.selected_agent)
    elif page == "Register Agent":
        if user_is_admin:
            st.title("Register New Agent")
            show_agent_registration()
            st.divider()
            show_agent_list()
        else:
            st.error("Administrator access required")
    elif page == "Select Agent":
        st.title("Manage and Select Agents")
        col1, col2 = st.columns([2, 1])
        with col1:
            show_agent_selector()

        st.divider()

        if st.session_state.selected_agent:
            show_agent_details(st.session_state.selected_agent)
        else:
            show_agent_list()
    elif page == "Audit Log":
        show_audit_log()
    elif page == "Settings":
        show_settings()


def show_home(is_admin_user: bool):
    """Show home page based on user role"""
    current_user = get_current_user()

    # Welcome message
    role_badge = "Administrator" if is_admin_user else "User"
    st.title(f"Welcome, {current_user['full_name']}!")
    st.markdown(f"**Role:** {role_badge}")

    st.markdown(
        """
        Welcome to the **Agentic-IAM Dashboard** - Your comprehensive solution for
        managing agent identities, permissions, and access control.
        """
    )

    st.markdown("---")

    # Quick stats
    db = st.session_state.db
    agents = db.list_agents()
    active_agents = len([a for a in agents if a["status"] == "active"])

    if is_admin_user:
        users = db.list_users()
        active_users = len([u for u in users if u["status"] == "active"])

        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric("Total Users", len(users), help="Number of system users")

        with col2:
            st.metric("Active Users", active_users, help="Currently active users")

        with col3:
            st.metric("Total Agents", len(agents), help="Number of registered agents")

        with col4:
            st.metric("Active Agents", active_agents, help="Currently active agents")
    else:
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric("Total Agents", len(agents), help="Number of registered agents")

        with col2:
            st.metric("Active Agents", active_agents, help="Currently active agents")

        with col3:
            st.metric("System Health", "100%", help="Overall system health status")

        with col4:
            st.metric("Last Update", "Just now", help="Last system update")

    st.markdown("---")

    # Features based on role
    if is_admin_user:
        show_admin_features()
    else:
        show_user_features()

    st.markdown("---")

    # Quick actions
    st.header("Quick Actions")

    if is_admin_user:
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            if st.button("Create User", use_container_width=True):
                st.session_state.requested_page = "Users"
                st.rerun()

        with col2:
            if st.button("Register Agent", use_container_width=True):
                st.session_state.requested_page = "Register Agent"
                st.rerun()

        with col3:
            if st.button("Manage Users", use_container_width=True):
                st.session_state.requested_page = "Users"
                st.rerun()

        with col4:
            if st.button("Audit Log", use_container_width=True):
                st.session_state.requested_page = "Audit Log"
                st.rerun()
    else:
        col1, col2, col3 = st.columns(3)

        with col1:
            if st.button("View Agents", use_container_width=True):
                st.session_state.requested_page = "Select Agent"
                st.rerun()

        with col2:
            if st.button("Audit Log", use_container_width=True):
                st.session_state.requested_page = "Audit Log"
                st.rerun()

        with col3:
            if st.button("Settings", use_container_width=True):
                st.session_state.requested_page = "Settings"
                st.rerun()


def show_admin_features():
    """Show features available to admins"""
    st.header("Administrator Features")

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("User Management")
        st.write(
            """
            - Create and manage users
            - Assign roles and permissions
            - Reset user passwords
            - Monitor user activity
            """
        )

        st.subheader("Agent Management")
        st.write(
            """
            - Register and manage AI agents
            - Monitor agent status and health
            - Track trust scores and permissions
            - Bulk operations support
            """
        )

    with col2:
        st.subheader("Full System Access")
        st.write(
            """
            - View all users and agents
            - Complete audit trail access
            - System configuration
            - Security management
            """
        )

        st.subheader("Analytics and Reports")
        st.write(
            """
            - Comprehensive audit logs
            - User activity reports
            - Agent performance metrics
            - Security compliance reports
            """
        )


def show_user_features():
    """Show features available to regular users"""
    st.header("Available Features")

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Agent Access")
        st.write(
            """
            - View registered agents
            - Select and interact with agents
            - Monitor agent status
            - Track assigned agents
            """
        )

    with col2:
        st.subheader("Personal Dashboard")
        st.write(
            """
            - View your activity logs
            - Monitor your sessions
            - Update your settings
            - Access personal reports
            """
        )


def show_audit_log():
    """Show audit log page"""
    st.title("Audit Log")

    db = st.session_state.db

    col1, col2, col3 = st.columns(3)

    with col1:
        agent_filter = st.selectbox(
            "Filter by Agent",
            ["All"] + [f"{a['name']} ({a['id']})" for a in db.list_agents()],
            key="audit_agent_filter",
        )

    with col2:
        limit = st.slider("Number of records", 10, 100, 50)

    with col3:
        st.write("")

    st.markdown("---")

    # Get events
    agent_id = None
    if agent_filter != "All":
        agent_id = agent_filter.split("(")[-1].rstrip(")")

    events = db.get_events(agent_id=agent_id, limit=limit)

    if events:
        import pandas as pd

        df = pd.DataFrame(events)
        df["created_at"] = pd.to_datetime(df["created_at"]).dt.strftime("%Y-%m-%d %H:%M:%S")

        st.dataframe(
            df[
                ["event_type", "agent_id", "action", "details", "created_at", "status"]
            ].sort_values("created_at", ascending=False),
            use_container_width=True,
            hide_index=True,
        )

        st.success(f"Total Events: {len(events)}")
    else:
        st.info("No events found")


def show_settings():
    """Show settings page"""
    st.title("Settings")

    current_user = get_current_user()
    mode_descriptions = get_mode_descriptions()

    tab1, tab2, tab3 = st.tabs(["General", "Security", "Profile"])

    with tab1:
        st.subheader("General Settings")

        theme = st.selectbox("Theme", ["Light", "Dark", "Auto"])
        refresh_interval = st.slider("Refresh Interval (seconds)", 5, 60, 30)
        mode_options = list(mode_descriptions.keys())
        st.selectbox(
            "Mode",
            mode_options,
            index=mode_options.index(st.session_state.mode),
            key="settings_mode",
        )
        if st.session_state.mode != st.session_state.settings_mode:
            st.session_state.mode = st.session_state.settings_mode
        st.caption(mode_descriptions.get(st.session_state.settings_mode, ""))

        if st.button("Save General Settings"):
            st.success("Settings saved successfully")

    with tab2:
        st.subheader("Security Settings")

        st.markdown(f"**Current User:** {current_user['username']}")

        with st.form("change_password_form"):
            st.markdown("#### Change Password")
            current_password = st.text_input("Current Password", type="password")
            new_password = st.text_input("New Password", type="password")
            confirm_password = st.text_input("Confirm New Password", type="password")

            if st.form_submit_button("Change Password"):
                if not current_password or not new_password:
                    st.error("Please fill in all fields")
                elif len(new_password) < 6:
                    st.error("Password must be at least 6 characters")
                elif new_password != confirm_password:
                    st.error("Passwords do not match")
                else:
                    db = st.session_state.db
                    if db.authenticate_user(current_user["username"], current_password):
                        if db.change_password(current_user["id"], new_password):
                            st.success("Password changed successfully")
                        else:
                            st.error("Failed to change password")
                    else:
                        st.error("Current password is incorrect")

    with tab3:
        st.subheader("Profile Information")

        st.markdown(
            f"""
            **User ID:** {current_user['id']}
            **Username:** {current_user['username']}
            **Full Name:** {current_user['full_name']}
            **Email:** {current_user['email']}
            **Role:** {current_user['role'].title()}
            **Status:** {current_user['status'].title()}
            """
        )


if __name__ == "__main__":
    main()
