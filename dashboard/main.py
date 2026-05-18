"""Main Streamlit dashboard for Agentic-IAM with real-time security monitoring."""
import streamlit as st
import sys
from pathlib import Path

# Add core modules to path
sys.path.append(str(Path(__file__).parent.parent))

# Configure page
st.set_page_config(
    page_title="Agentic-IAM Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .metric-card {
        padding: 20px;
        border-radius: 8px;
        background-color: #f0f0f0;
        border-left: 4px solid #ff6600;
    }
    .alert-critical {
        border-left-color: #ff0000;
    }
    .alert-high {
        border-left-color: #ff6600;
    }
    .alert-medium {
        border-left-color: #ffaa00;
    }
    .alert-low {
        border-left-color: #00aa00;
    }
</style>
""", unsafe_allow_html=True)

# Sidebar navigation
st.sidebar.title("🛡️ Agentic-IAM")
page = st.sidebar.radio(
    "Navigation",
    [
        "Dashboard",
        "Security Monitoring",
        "Attack Simulation",
        "Audit Log",
        "Settings"
    ]
)

# Import components
from dashboard.components.real_time_alerts import show_attack_simulation_results
from dashboard.components.attack_simulation import show_attack_results

# Page routing
if page == "Dashboard":
    st.title("🛡️ Agentic-IAM Control Center")
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("🟢 System Status", "Operational")
    with col2:
        st.metric("📊 Active Sessions", "12")
    with col3:
        st.metric("🔒 Authentication", "OIDC + Casbin")
    
    st.divider()
    
    st.subheader("Quick Links")
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        if st.button("🔐 Agent Management"):
            st.info("Navigate to Agent Management page")
    with col2:
        if st.button("📋 Policies"):
            st.info("Navigate to Policy Editor")
    with col3:
        if st.button("📊 Analytics"):
            st.info("Navigate to Analytics")
    with col4:
        if st.button("⚙️ Configuration"):
            st.info("Navigate to Settings")

elif page == "Security Monitoring":
    st.title("🚨 Real-Time Security Monitoring")
    show_attack_simulation_results()

elif page == "Attack Simulation":
    st.title("⚔️ Attack Simulation & Results")
    show_attack_results()

elif page == "Audit Log":
    st.title("📋 Audit Log")
    
    st.info("Comprehensive audit trail of all system activities, security events, and policy changes.")
    
    # Sample audit entries
    import pandas as pd
    from datetime import datetime, timedelta
    
    audit_data = {
        "Timestamp": [
            datetime.now() - timedelta(hours=i) for i in range(5)
        ],
        "Event Type": [
            "Attack Detected",
            "IP Blocked",
            "Alert Resolved",
            "Policy Updated",
            "Agent Created"
        ],
        "Severity": [
            "CRITICAL",
            "HIGH",
            "HIGH",
            "LOW",
            "LOW"
        ],
        "Details": [
            "SQL Injection detected from 127.0.0.1",
            "IP 192.168.1.100 blocked for 1 hour",
            "Brute force alert resolved by admin",
            "Casbin policy updated",
            "New agent provisioned"
        ]
    }
    
    df = pd.DataFrame(audit_data)
    st.dataframe(df, use_container_width=True)

elif page == "Settings":
    st.title("⚙️ Settings & Configuration")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("System Settings")
        st.toggle("Enable Attack Detection", value=True)
        st.toggle("Auto-block suspicious IPs", value=True)
        st.slider("Brute Force Threshold", 1, 20, value=5)
        st.slider("Alert Check Interval (seconds)", 5, 60, value=10)
    
    with col2:
        st.subheader("API Configuration")
        st.text_input("API Base URL", value="http://127.0.0.1:8000")
        st.text_input("Admin API Key", value="", type="password")
        st.selectbox("Log Level", ["DEBUG", "INFO", "WARNING", "ERROR"])

# Footer
st.divider()
st.markdown("""
<div style="text-align: center; color: gray; font-size: 12px; margin-top: 20px;">
    <p>🛡️ Agentic-IAM v1.0.0 | Enterprise Agent Identity & Access Management</p>
    <p>Real-time Security Monitoring • Attack Detection & Mitigation • Comprehensive Audit Trail</p>
</div>
""", unsafe_allow_html=True)
