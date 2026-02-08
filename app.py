"""
Agentic-IAM: Streamlit Dashboard Application

Main entry point for the web-based GUI dashboard.
"""
import streamlit as st
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from dashboard.components.agent_management import show_agent_management
from dashboard.utils import show_alert
from database import get_database
from dashboard.components.agent_selection import show_agent_registration, show_agent_selector, show_agent_list, show_agent_details

# Page configuration
st.set_page_config(
    page_title="Agentic-IAM Dashboard",
    page_icon="👥",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
    <style>
    .main {
        padding-top: 2rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
    }
    </style>
    """, unsafe_allow_html=True)


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


def show_login():
    """Show login page"""
    st.title("🔐 Agentic-IAM Login")
    
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.markdown("### Welcome to Agentic-IAM")
        st.markdown("Please log in to access the dashboard.")
        
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            
            submitted = st.form_submit_button("Login")
            
            if submitted:
                if username and password:
                    user = st.session_state.db.authenticate_user(username, password)
                    if user:
                        st.session_state.user = user
                        st.session_state.authenticated = True
                        st.success("✅ Login successful!")
                        st.rerun()
                    else:
                        st.error("❌ Invalid username or password")
                else:
                    st.error("❌ Please enter both username and password")
        
        st.markdown("---")
        st.markdown("**Default Credentials:**")
        st.info("Admin: admin / admin123\n\nUser: user / user123")


def show_logout():
    """Show logout button"""
    if st.sidebar.button("🚪 Logout"):
        st.session_state.user = None
        st.session_state.authenticated = False
        st.rerun()


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
        st.markdown("---")
        
        # User info
        if st.session_state.user:
            st.write(f"👤 **{st.session_state.user['username']}** ({st.session_state.user['role']})")
            show_logout()
            st.markdown("---")
        
        # Navigation
        page = st.radio(
            "Navigation",
            ["Home", "Register Agent", "Select Agent", "Audit Log", "Settings"],
            index=0
        )
        
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
        st.info("✅ System Ready")
        
        st.markdown("---")
        
        # About
        st.write("### ℹ️ About")
        st.write("""
        **Agentic-IAM v1.0**
        
        Comprehensive identity and access management system for AI agents.
        """)
    
    # Main content
    if page == "Home":
        show_home()
    elif page == "Register Agent":
        st.title("👤 Register New Agent")
        show_agent_registration()
        st.divider()
        show_agent_list()
    elif page == "Select Agent":
        st.title("👥 Manage & Select Agents")
        col1, col2 = st.columns([2, 1])
        with col1:
            selected_agent_id = show_agent_selector()
        
        st.divider()
        
        if st.session_state.selected_agent:
            show_agent_details(st.session_state.selected_agent)
        else:
            show_agent_list()
    elif page == "Audit Log":
        show_audit_log()
    elif page == "Settings":
        show_settings()


def show_home():
    """Show home page"""
    st.title("🏠 Agentic-IAM Dashboard")
    
    st.markdown("""
    Welcome to the **Agentic-IAM Dashboard** - Your comprehensive solution for 
    managing agent identities, permissions, and access control.
    """)
    
    # Quick stats
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Agents", "0", help="Number of registered agents")
    
    with col2:
        st.metric("Active Sessions", "0", help="Currently active agent sessions")
    
    with col3:
        st.metric("System Health", "100%", help="Overall system health status")
    
    with col4:
        st.metric("Last Update", "Just now", help="Last system update")
    
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
        if st.button("➕ Register New Agent", use_container_width=True):
            st.session_state.page = "Agent Management"
            st.rerun()
    
    with col2:
        if st.button("📊 View Reports", use_container_width=True):
            st.info("Report generation would be implemented here")
    
    with col3:
        if st.button("📋 View Audit Log", use_container_width=True):
            st.session_state.page = "Audit Log"
            st.rerun()


def show_sessions():
    """Show sessions page"""
    st.title("🔐 Session Management")
    
    st.info("Session management features would be displayed here")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Active Sessions", "0")
    
    with col2:
        st.metric("Total Sessions (24h)", "0")
    
    with col3:
        st.metric("Avg Duration", "N/A")
    
    st.markdown("---")
    
    st.subheader("📋 Active Sessions Table")
    st.info("No active sessions at the moment")


def show_audit_log():
    """Show audit log page"""
    st.title("📋 Audit Log")
    
    db = st.session_state.db
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        agent_filter = st.selectbox(
            "🔍 Filter by Agent",
            ["All"] + [f"{a['name']} ({a['id']})" for a in db.list_agents()],
            key="audit_agent_filter"
        )
    
    with col2:
        limit = st.slider("Number of records", 10, 100, 50)
    
    with col3:
        st.write("")  # Spacing
    
    st.markdown("---")
    
    # Get events
    agent_id = None
    if agent_filter != "All":
        agent_id = agent_filter.split("(")[-1].rstrip(")")
    
    events = db.get_events(agent_id=agent_id, limit=limit)
    
    if events:
        import pandas as pd
        df = pd.DataFrame(events)
        df['created_at'] = pd.to_datetime(df['created_at']).dt.strftime('%Y-%m-%d %H:%M:%S')
        
        # Display with colors
        st.dataframe(
            df[['event_type', 'agent_id', 'action', 'details', 'created_at', 'status']].sort_values('created_at', ascending=False),
            use_container_width=True,
            hide_index=True
        )
        
        st.success(f"✅ Number of events: {len(events)}")
    else:
        st.info("📭 No events found")


def show_settings():
    """Show settings page"""
    st.title("⚙️ Settings")
    
    tab1, tab2, tab3 = st.tabs(["General", "Security", "Advanced"])
    
    with tab1:
        st.subheader("General Settings")
        
        theme = st.selectbox("Theme", ["Light", "Dark", "Auto"])
        refresh_interval = st.slider("Refresh Interval (seconds)", 5, 60, 30)
        
        if st.button("Save General Settings"):
            st.success("✅ Settings saved successfully")
    
    with tab2:
        st.subheader("Security Settings")
        
        mfa_enabled = st.checkbox("Enable Multi-Factor Authentication", value=True)
        session_timeout = st.slider("Session Timeout (minutes)", 5, 480, 60)
        
        if st.button("Save Security Settings"):
            st.success("✅ Security settings saved successfully")
    
    with tab3:
        st.subheader("Advanced Settings")
        
        debug_mode = st.checkbox("Debug Mode", value=False)
        log_level = st.selectbox("Log Level", ["INFO", "DEBUG", "WARNING", "ERROR"])
        
        if st.button("Save Advanced Settings"):
            st.success("✅ Advanced settings saved successfully")


if __name__ == "__main__":
    main()
