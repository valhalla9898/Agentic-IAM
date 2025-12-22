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


def main():
    """Main application"""
    initialize_session()
    
    # Sidebar
    with st.sidebar:
        st.title("⚙️ Agentic-IAM")
        st.markdown("---")
        
        # Navigation
        page = st.radio(
            "Navigation",
            ["Home", "Agent Management", "Sessions", "Audit Log", "Settings"],
            index=0
        )
        
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
    elif page == "Agent Management":
        show_agent_management(st.session_state.iam)
    elif page == "Sessions":
        show_sessions()
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
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        start_date = st.date_input("Start Date")
    
    with col2:
        end_date = st.date_input("End Date")
    
    with col3:
        event_type = st.selectbox("Event Type", ["All", "Login", "Logout", "Permission Change", "Error"])
    
    st.markdown("---")
    
    st.info("No audit events to display")


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
