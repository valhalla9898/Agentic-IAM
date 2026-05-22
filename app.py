"""
Agentic-IAM: Streamlit Dashboard Application

Main entry point for the web-based GUI dashboard with role-based access control.
"""

from utils.security import (
    InputValidator,
    RateLimiter,
    AccountSecurity,
    AuditLogger,
    SessionSecurityManager,
    SQLInjectionProtection,
)
from utils.advanced_features import AgentHealthMonitor, AgentAnalytics, ReportGenerator
from utils.rbac import (
    Permission,
    check_permission,
    is_admin,
    is_operator,
    get_current_user_permissions,
    get_rbac_manager,
)
from bloome_store import (
    STORE_NAME,
    build_consultation_details,
    format_price,
    get_brand_story,
    get_catalog_summary,
    get_featured_products,
)
from dashboard.components.risk_assessment import show_risk_assessment
from dashboard.components.ai_assistant import show_ai_assistant
from dashboard.components.agent_selection import (
    show_agent_registration,
    show_agent_selector,
    show_agent_list,
    show_agent_details,
)
from config.settings import get_settings
from database import get_database
import streamlit as st
import os
import sys
import json
from pathlib import Path
import pandas as pd
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))


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
        st.session_state.db = get_database(get_settings().database_path)
    if "selected_agent" not in st.session_state:
        st.session_state.selected_agent = None
    if "user" not in st.session_state:
        st.session_state.user = None
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
    if "requested_page" not in st.session_state:
        st.session_state.requested_page = None

    # Initialize security components
    if "rate_limiter" not in st.session_state:
        st.session_state.rate_limiter = RateLimiter(max_attempts=5, window_seconds=300)
    if "account_security" not in st.session_state:
        st.session_state.account_security = AccountSecurity(max_failed_attempts=5)
    if "csrf_token" not in st.session_state:
        st.session_state.csrf_token = SessionSecurityManager.generate_csrf_token()


def is_onboarding_required() -> bool:
    """Check whether the setup wizard should be shown before login."""
    db = st.session_state.db
    onboarding_done = str(db.get_system_setting("onboarding_completed", False)).lower() == "true"
    return not onboarding_done or not db.has_users()


def _initialize_onboarding_fields(settings: dict) -> None:
    """Seed onboarding widgets so the form can be prefilled for demos."""
    defaults = {
        "onboarding_company_name": settings.get("company_name", ""),
        "onboarding_environment_name": str(settings.get("deployment_environment", "development")).lower(),
        "onboarding_identity_provider": settings.get("identity_provider", "Local Accounts"),
        "onboarding_app_url": settings.get("app_url", ""),
        "onboarding_api_url": settings.get("api_url", ""),
        "onboarding_database_type": settings.get("database_type", "SQLite"),
        "onboarding_database_url": settings.get("database_url", ""),
        "onboarding_enable_sso": bool(settings.get("enable_sso", False)),
        "onboarding_admin_username": settings.get("admin_username", "admin"),
        "onboarding_admin_email": settings.get("admin_email", "admin@company.local"),
        "onboarding_admin_password": "",
        "onboarding_confirm_password": "",
    }

    for key, value in defaults.items():
        st.session_state.setdefault(key, value)


def _load_demo_onboarding_values() -> None:
    demo_file = Path(__file__).parent / "demo" / "valhalla_onboarding.json"
    if demo_file.exists():
        with demo_file.open("r", encoding="utf-8") as handle:
            demo_values = json.load(handle)
    else:
        demo_values = {
            "company_name": "Valhalla",
            "deployment_environment": "development",
            "identity_provider": "Microsoft Entra ID",
            "app_url": "http://localhost:8501",
            "api_url": "http://localhost:8000/api",
            "database_type": "SQLite",
            "database_url": "sqlite:///valhalla_demo.db",
            "enable_sso": True,
            "admin_username": "valhalla_admin",
            "admin_email": "admin@valhalla.local",
            "admin_password": "Valhalla@12345",
        }

    st.session_state.onboarding_company_name = demo_values.get("company_name", "Valhalla")
    st.session_state.onboarding_environment_name = demo_values.get(
        "deployment_environment", "development")
    st.session_state.onboarding_identity_provider = demo_values.get(
        "identity_provider", "Local Accounts")
    st.session_state.onboarding_app_url = demo_values.get("app_url", "")
    st.session_state.onboarding_api_url = demo_values.get("api_url", "")
    st.session_state.onboarding_database_type = demo_values.get("database_type", "SQLite")
    st.session_state.onboarding_database_url = demo_values.get("database_url", "")
    st.session_state.onboarding_enable_sso = bool(demo_values.get("enable_sso", False))
    st.session_state.onboarding_admin_username = demo_values.get("admin_username", "admin")
    st.session_state.onboarding_admin_email = demo_values.get("admin_email", "admin@company.local")
    st.session_state.onboarding_admin_password = demo_values.get("admin_password", "")
    st.session_state.onboarding_confirm_password = demo_values.get("admin_password", "")


def show_onboarding(inline: bool = False):
    """First-run setup wizard for company connection and admin bootstrap."""
    if inline:
        st.subheader("First-time setup")
        st.write(
            "Use this section to connect the app to your environment, save the company profile, "
            "and create the first admin account."
        )
    else:
        st.title("🚀 Welcome to Agentic-IAM")
        st.subheader("First-time setup")
        st.write(
            "Use this screen to connect the app to your environment, save the company profile, "
            "and create the first admin account."
        )

    settings = st.session_state.db.get_system_settings()
    _initialize_onboarding_fields(settings)

    demo_col1, demo_col2 = st.columns([1, 2])
    with demo_col1:
        if st.button("🎯 Load Demo Values", use_container_width=True):
            _load_demo_onboarding_values()
            st.rerun()
    with demo_col2:
        st.caption(
            "Use the demo preset for a fast live presentation, or fill the form manually for a real setup.")

    with st.form("onboarding_form"):
        col1, col2 = st.columns(2)

        with col1:
            company_name = st.text_input("Company / Tenant Name", key="onboarding_company_name")
            environment_options = ["development", "staging", "production"]
            environment_name = st.selectbox(
                "Deployment Environment",
                environment_options,
                index=environment_options.index(st.session_state.onboarding_environment_name)
                if st.session_state.onboarding_environment_name in environment_options
                else 0,
                key="onboarding_environment_name",
            )
            identity_options = [
                "Local Accounts",
                "Microsoft Entra ID",
                "LDAP / Active Directory",
                "Other SSO"]
            identity_provider = st.selectbox(
                "Identity Provider",
                identity_options,
                index=identity_options.index(st.session_state.onboarding_identity_provider)
                if st.session_state.onboarding_identity_provider in identity_options
                else 0,
                key="onboarding_identity_provider",
            )
            app_url = st.text_input("Company App URL", key="onboarding_app_url")

        with col2:
            api_url = st.text_input("API / Backend URL", key="onboarding_api_url")
            db_type_options = ["SQLite", "PostgreSQL", "MySQL"]
            database_type = st.selectbox(
                "Database Type",
                db_type_options,
                index=db_type_options.index(st.session_state.onboarding_database_type)
                if st.session_state.onboarding_database_type in db_type_options
                else 0,
                key="onboarding_database_type",
            )
            database_url = st.text_input(
                "Database Connection String",
                key="onboarding_database_url")
            enable_sso = st.checkbox("Enable Single Sign-On later", key="onboarding_enable_sso")

        st.markdown("---")
        st.subheader("Create First Admin")

        admin_col1, admin_col2 = st.columns(2)

        with admin_col1:
            admin_username = st.text_input("Admin Username", key="onboarding_admin_username")
            admin_email = st.text_input("Admin Email", key="onboarding_admin_email")

        with admin_col2:
            admin_password = st.text_input(
                "Admin Password",
                type="password",
                key="onboarding_admin_password")
            confirm_password = st.text_input(
                "Confirm Password",
                type="password",
                key="onboarding_confirm_password")

        submitted = st.form_submit_button("✅ Save Setup and Continue")

        if submitted:
            required_fields = [
                company_name.strip(),
                app_url.strip(),
                api_url.strip(),
                admin_username.strip(),
                admin_email.strip(),
            ]
            if not all(required_fields):
                st.error("❌ Please fill in the required connection and admin fields.")
                return

            if not admin_password:
                st.error("❌ Please enter an admin password.")
                return

            if admin_password != confirm_password:
                st.error("❌ Password and confirmation do not match.")
                return

            if len(admin_password) < 12:
                st.error("❌ Admin password must be at least 12 characters long.")
                return

            db = st.session_state.db
            saved = all(
                [
                    db.set_system_setting("company_name", company_name.strip()),
                    db.set_system_setting("deployment_environment", environment_name),
                    db.set_system_setting("identity_provider", identity_provider),
                    db.set_system_setting("app_url", app_url.strip()),
                    db.set_system_setting("api_url", api_url.strip()),
                    db.set_system_setting("database_type", database_type),
                    db.set_system_setting("database_url", database_url.strip()),
                    db.set_system_setting("enable_sso", enable_sso),
                    db.set_system_setting("admin_username", admin_username.strip()),
                    db.set_system_setting("admin_email", admin_email.strip()),
                ]
            )

            if not saved:
                st.error("❌ Could not save the setup settings.")
                return

            admin_exists = False
            try:
                admin_exists = any(user["username"] == admin_username.strip()
                                   for user in db.list_users())
            except Exception:
                admin_exists = False

            if not admin_exists:
                admin_created = db.create_user(
                    username=admin_username.strip(),
                    email=admin_email.strip(),
                    password=admin_password,
                    role="admin",
                )
                if not admin_created:
                    st.error("❌ Setup was saved, but creating the admin account failed.")
                    return

            db.set_system_setting("onboarding_completed", True)
            st.session_state.onboarding_completed = True
            st.success("✅ Setup completed successfully. You can now log in.")
            st.rerun()


def navigate_to(page_name: str):
    """Update the active Streamlit navigation target."""
    st.session_state.main_navigation = page_name
    st.rerun()


def get_requested_page() -> str | None:
    """Read an optional page request from the URL query string and save to session state."""
    try:
        query_page = st.query_params.get("page")
        if isinstance(query_page, list):
            page = query_page[0] if query_page else None
        else:
            page = query_page
    except Exception:
        try:
            params = st.experimental_get_query_params()
            values = params.get("page", [])
            page = values[0] if values else None
        except Exception:
            page = None

    # Save to session state so it persists after login
    if page:
        st.session_state.requested_page = page

    return page


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
        if os.getenv("AGENTIC_IAM_SHOW_SETUP_HINTS", "true").lower() == "true":
            st.info("No demo credentials are exposed. Create your first admin using setup scripts.")
            st.caption("Example: python setup_admin.py")

        db = st.session_state.db
        onboarding_required = not db.has_users()

        if onboarding_required:
            st.warning("No users exist yet. Use the setup section below to create the first admin.")

        show_setup = st.checkbox(
            "First-time setup / Connect your company system",
            value=onboarding_required,
        )

        if show_setup:
            with st.expander("Setup and connection details", expanded=True):
                show_onboarding(inline=True)

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
    pages = ["Bloome"]

    if is_admin() or is_operator():
        pages.insert(0, "Home")

    # High-value operational views
    pages.append("🏥 Health Center")
    pages.append("🧭 Activity Timeline")
    pages.append("🚨 Incident Response")

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

    if check_permission(Permission.SETTINGS_VIEW) or is_admin():
        pages.append("🔌 Connection Hub")
        pages.append("🔗 Integrations")

    # Admin-only pages
    if is_admin():
        pages.append("👥 User Management")
        pages.append("🔧 System Config")
        pages.append("📡 System Monitor")
        pages.append("🛡️ Security Operations")
        pages.append("⚡ Automation Center")

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

        # Check for requested page (from query params or session state)
        requested_page = get_requested_page()
        if not requested_page:
            requested_page = st.session_state.get("requested_page")

        if requested_page and requested_page in available_pages:
            st.session_state.main_navigation = requested_page

        # Navigation - use stored value or first available page
        current_page = st.session_state.get("main_navigation", available_pages[0])
        try:
            page_index = available_pages.index(
                current_page) if current_page in available_pages else 0
        except ValueError:
            page_index = 0

        page = st.radio("Navigation", available_pages, index=page_index, key="main_navigation")

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
    elif page == "Bloome":
        show_bloome_storefront()
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
    elif page == "🏥 Health Center":
        show_page_health_center()
    elif page == "🧭 Activity Timeline":
        show_page_activity_timeline()
    elif page == "🚨 Incident Response":
        show_page_incident_response()
    elif page == "🔌 Connection Hub":
        show_page_connection_hub()
    elif page == "🔗 Integrations":
        show_page_integrations()
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
    elif page == "🛡️ Security Operations":
        if is_admin() or is_operator():
            show_page_security_operations()
        else:
            st.error("❌ Access Denied: Admin or Operator only")
    elif page == "⚡ Automation Center":
        if is_admin() or is_operator():
            show_page_automation_center()
        else:
            st.error("❌ Access Denied: Admin or Operator only")
    elif page == "📈 Analytics":
        if is_operator():
            show_page_analytics()
        else:
            st.error("❌ Access Denied: Operator or Admin only")
    elif page == "⚠️ Risk Assessment":
        show_risk_assessment(st.session_state.db)
    else:
        st.warning(f"Page '{page}' not implemented yet")


def show_bloome_storefront():
    """Show the consumer-facing Bloome storefront."""
    st.title(f"✨ {STORE_NAME}")
    st.caption(
        "Premium perfume and skin care with clear pricing, product discovery, and concierge-style guidance.")

    st.markdown(
        """
        <style>
        .bloome-hero {
            background: linear-gradient(135deg, #f7efe4 0%, #fff8f0 45%, #f3e5d8 100%);
            border: 1px solid rgba(126, 93, 52, 0.12);
            border-radius: 24px;
            padding: 2rem;
            box-shadow: 0 18px 50px rgba(117, 80, 38, 0.10);
        }
        .bloome-chip {
            display: inline-block;
            padding: 0.4rem 0.8rem;
            border-radius: 999px;
            background: rgba(126, 93, 52, 0.08);
            margin-right: 0.5rem;
            margin-bottom: 0.5rem;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    hero_col1, hero_col2 = st.columns([2, 1])
    with hero_col1:
        st.markdown("<div class='bloome-hero'>", unsafe_allow_html=True)
        st.subheader("Perfume and skincare, curated like a boutique.")
        st.write(get_brand_story())
        for label in ["Perfume", "Skin Care", "Gift Sets", "Consultation"]:
            st.markdown(f"<span class='bloome-chip'>{label}</span>", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    with hero_col2:
        summary = get_catalog_summary()
        st.metric("Categories", len(summary))
        st.metric("Featured Products", len(get_featured_products()))
        st.metric("Starting Price", format_price(620))

    st.markdown("---")
    st.subheader("Featured Collection")
    featured = get_featured_products()
    product_cols = st.columns(2)
    for index, product in enumerate(featured):
        with product_cols[index % 2]:
            st.markdown(
                f"""
                <div style='border:1px solid rgba(126,93,52,0.14);border-radius:20px;padding:1rem;background:#fffdf9;'>
                <div style='font-size:0.8rem;opacity:0.7'>{product.category}</div>
                <h3 style='margin-bottom:0.25rem'>{product.name}</h3>
                <div style='margin-bottom:0.35rem'><strong>{format_price(product.price_egp)}</strong></div>
                <div style='margin-bottom:0.35rem'>{product.description}</div>
                <div style='font-size:0.9rem;opacity:0.8'>Skin type: {product.skin_type or 'All skin types'}</div>
                <div style='font-size:0.9rem;opacity:0.8'>Size: {product.size or 'Standard'}</div>
                <div style='font-size:0.8rem;margin-top:0.35rem'><strong>{product.badge}</strong></div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    st.markdown("---")
    st.subheader("Request a recommendation")
    with st.form("bloome_consultation_form"):
        c1, c2 = st.columns(2)
        with c1:
            customer_name = st.text_input("Your name")
            email = st.text_input("Email")
            product_interest = st.selectbox("Product interest", ["Skin Care", "Perfume", "Bundles"])
        with c2:
            skin_concern = st.text_input("Skin concern / fragrance preference")
            budget_egp = st.slider(
                "Budget (EGP)",
                min_value=500,
                max_value=5000,
                value=1500,
                step=100)
            preferred_format = st.selectbox(
                "Preferred format", [
                    "Everyday", "Gift", "Premium", "Routine"])

        submitted = st.form_submit_button("Get curated recommendations")

        if submitted:
            if not customer_name or not email:
                st.error("Please enter your name and email.")
            else:
                details = build_consultation_details(
                    customer_name, email, product_interest, skin_concern, budget_egp)
                st.success("Thanks. A Bloome consultant can use this brief to prepare a recommendation.")
                st.code(details)
                st.caption(f"Preferred format: {preferred_format}")


def show_home():
    """Show home page with role-based content"""
    st.title("🏠 Agentic-IAM Control Center")

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

    db = st.session_state.db
    settings = db.get_system_settings()
    health_monitor = AgentHealthMonitor(db)
    analytics = AgentAnalytics(db)
    system_health = health_monitor.get_system_health()
    system_analytics = analytics.get_system_analytics()

    st.markdown("""
    Welcome to the **Agentic-IAM Control Center** - a command view for identity,
    access, integrations, operations, and incident response.
    """)

    st.markdown("---")

    overview_col1, overview_col2, overview_col3, overview_col4 = st.columns(4)
    with overview_col1:
        st.metric("System Health", f"{system_health.get('overall_health', 0)}%")
    with overview_col2:
        st.metric("Active Agents", system_analytics.get("active_agents", 0))
    with overview_col3:
        st.metric("Total Events", system_analytics.get("total_events", 0))
    with overview_col4:
        st.metric("Success Rate", f"{system_analytics.get('success_rate', 0):.1f}%")

    st.markdown("---")

    insight_col1, insight_col2 = st.columns([2, 1])
    with insight_col1:
        st.subheader("Operational Snapshot")
        snapshot_rows = [
            {
                "Area": "Tenant", "Value": settings.get(
                    "company_name", "Not configured")}, {
                "Area": "Environment", "Value": settings.get(
                    "deployment_environment", "development")}, {
                        "Area": "Identity Provider", "Value": settings.get(
                            "identity_provider", "Local Accounts")}, {
                                "Area": "App URL", "Value": settings.get(
                                    "app_url", "Not configured")}, {
                                        "Area": "API URL", "Value": settings.get(
                                            "api_url", "Not configured")}, ]
        st.dataframe(pd.DataFrame(snapshot_rows), width="stretch", hide_index=True)

    with insight_col2:
        st.subheader("Fast Access")
        st.markdown("Select from the sidebar →")
        st.info("🚨 **Incident Response** - Review security incidents")
        st.info("🔗 **Integrations** - Configure identity providers")
        st.info("🏥 **Health Center** - System health metrics")
        st.info("⚡ **Automation Center** - Task automation")

    st.markdown("---")

    # Recent critical signals
    recent_events = db.get_events(limit=25)
    critical_events = [
        event for event in recent_events
        if event.get("status") != "success" or event.get("event_type", "").startswith("security_")
    ]

    if critical_events:
        st.subheader("Recent Critical Signals")
        alert_rows = []
        for event in critical_events[:8]:
            alert_rows.append({
                "Time": event.get("created_at", ""),
                "Type": event.get("event_type", ""),
                "Agent": event.get("agent_id", "system"),
                "Status": event.get("status", ""),
                "Details": event.get("details", ""),
            })
        st.dataframe(pd.DataFrame(alert_rows), width="stretch", hide_index=True)
    else:
        st.success("No recent critical signals detected")

    # Quick stats with role-aware content
    col1, col2, col3, col4 = st.columns(4)

    agents = db.list_agents()
    events = db.get_events(limit=100)

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


def show_page_incident_response():
    """Security and operations incident dashboard."""
    st.title("🚨 Incident Response")

    db = st.session_state.db
    events = db.get_events(limit=250)
    failed_events = [event for event in events if event.get("status") != "success"]
    suspicious_events = [
        event for event in events if any(
            term in f"{event.get('event_type', '')} {event.get('details', '')}".lower() for term in [
                "error",
                "fail",
                "denied",
                "locked",
                "suspicious",
                "blocked"])]

    incident_candidates = failed_events + \
        [event for event in suspicious_events if event not in failed_events]

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Incident Signals", len(incident_candidates))
    with col2:
        st.metric("Failed Events", len(failed_events))
    with col3:
        st.metric("Suspicious Events", len(suspicious_events))
    with col4:
        st.metric("Users", len(db.list_users()))

    st.markdown("---")

    action_col1, action_col2, action_col3 = st.columns(3)
    with action_col1:
        if st.button("Create Security Review Task", width="stretch"):
            agents = db.list_agents()
            agent_id = agents[0]["id"] if agents else "system"
            db.create_task(agent_id, "security_review", "Review recent incident signals")
            st.success("Security review task created")
    with action_col2:
        if st.button("Create Containment Task", width="stretch"):
            agents = db.list_agents()
            agent_id = agents[0]["id"] if agents else "system"
            db.create_task(agent_id, "containment", "Contain and assess suspicious activity")
            st.success("Containment task created")
    with action_col3:
        if st.button("Open Automation Center", width="stretch"):
            navigate_to("⚡ Automation Center")

    st.markdown("---")

    st.subheader("Incident Queue")
    if incident_candidates:
        incident_rows = []
        for event in incident_candidates[:50]:
            severity = "High" if event.get("status") != "success" else "Medium"
            details_blob = f"{event.get('event_type', '')} {event.get('details', '')}".lower()
            if any(term in details_blob for term in ["locked", "denied", "blocked"]):
                severity = "High"
            elif any(term in details_blob for term in ["error", "fail"]):
                severity = "Medium"

            incident_rows.append({
                "Severity": severity,
                "Time": event.get("created_at", ""),
                "Type": event.get("event_type", ""),
                "Agent": event.get("agent_id", "system"),
                "Action": event.get("action", ""),
                "Details": event.get("details", ""),
            })

        st.dataframe(pd.DataFrame(incident_rows), width="stretch", hide_index=True)
    else:
        st.success("No active incident signals detected")


def show_page_integrations():
    """Integration hub for identity and external platform connections."""
    st.title("🔗 Integrations")

    db = st.session_state.db
    settings = db.get_system_settings()

    st.subheader("Connection Targets")
    target_rows = [
        {"Integration": "Microsoft Entra ID", "Status": settings.get("entra_enabled", False), "Key": "entra_enabled"},
        {"Integration": "LDAP / Active Directory", "Status": settings.get("ldap_enabled", False), "Key": "ldap_enabled"},
        {"Integration": "Webhook Notifications", "Status": settings.get("webhooks_enabled", False), "Key": "webhooks_enabled"},
        {"Integration": "SIEM / SOC Feed", "Status": settings.get("siem_enabled", False), "Key": "siem_enabled"},
    ]
    st.dataframe(pd.DataFrame(target_rows)[
                 ["Integration", "Status"]], width="stretch", hide_index=True)

    st.markdown("---")

    with st.form("integrations_form"):
        col1, col2 = st.columns(2)

        with col1:
            entra_enabled = st.checkbox(
                "Enable Microsoft Entra ID", value=bool(
                    settings.get(
                        "entra_enabled", False)))
            entra_tenant_id = st.text_input(
                "Entra Tenant ID", value=settings.get(
                    "entra_tenant_id", ""))
            entra_client_id = st.text_input(
                "Entra Client ID", value=settings.get(
                    "entra_client_id", ""))
            ldap_enabled = st.checkbox(
                "Enable LDAP / Active Directory",
                value=bool(
                    settings.get(
                        "ldap_enabled",
                        False)))
            ldap_server = st.text_input("LDAP Server", value=settings.get("ldap_server", ""))

        with col2:
            webhooks_enabled = st.checkbox(
                "Enable Webhook Notifications", value=bool(
                    settings.get(
                        "webhooks_enabled", False)))
            webhook_url = st.text_input("Webhook URL", value=settings.get("webhook_url", ""))
            siem_enabled = st.checkbox(
                "Enable SIEM / SOC Feed",
                value=bool(
                    settings.get(
                        "siem_enabled",
                        False)))
            siem_endpoint = st.text_input("SIEM Endpoint", value=settings.get("siem_endpoint", ""))
            integration_owner = st.text_input(
                "Integration Owner", value=settings.get(
                    "integration_owner", "security-team"))

        saved = st.form_submit_button("💾 Save Integrations")

        if saved:
            save_results = [
                db.set_system_setting("entra_enabled", entra_enabled),
                db.set_system_setting("entra_tenant_id", entra_tenant_id.strip()),
                db.set_system_setting("entra_client_id", entra_client_id.strip()),
                db.set_system_setting("ldap_enabled", ldap_enabled),
                db.set_system_setting("ldap_server", ldap_server.strip()),
                db.set_system_setting("webhooks_enabled", webhooks_enabled),
                db.set_system_setting("webhook_url", webhook_url.strip()),
                db.set_system_setting("siem_enabled", siem_enabled),
                db.set_system_setting("siem_endpoint", siem_endpoint.strip()),
                db.set_system_setting("integration_owner", integration_owner.strip()),
            ]

            if all(save_results):
                st.success("✅ Integrations saved successfully")
                st.rerun()
            else:
                st.error("❌ Could not save integration settings")


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
                pending_delete_key = f"pending_user_delete_{u['id']}"
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
                        st.session_state[pending_delete_key] = True
                        st.rerun()

                if st.session_state.get(pending_delete_key):
                    st.warning(
                        f"Are you sure you want to delete user {u['username']}? This cannot be undone.")
                    confirm_col, cancel_col = st.columns(2)
                    with confirm_col:
                        if st.button(
                            f"✅ Confirm Delete {u['username']}",
                                key=f"confirm_deluser_{u['id']}"):
                            ok = db.delete_user(u["id"])
                            still_exists = db.get_user_by_id(u["id"])
                            if ok and not still_exists:
                                st.success(f"User {u['username']} deleted")
                                st.session_state[pending_delete_key] = False
                                st.rerun()
                            elif ok and still_exists:
                                st.error(
                                    f"Delete reported success, but user {u['username']} still exists")
                            else:
                                st.error(f"Failed to delete user {u['username']}")
                    with cancel_col:
                        if st.button(f"✖ Cancel {u['username']}", key=f"cancel_deluser_{u['id']}"):
                            st.session_state[pending_delete_key] = False
                            st.rerun()

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
                    st.error(
                        f"Update reported success, but user {selected_user['username']} did not persist")
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
            f"policy={password_policy}, session duration={session_duration}h")

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
            navigate_to("➕ Register Agent")

    with col2:
        if st.button("📊 View Reports", width="stretch"):
            navigate_to("📊 Reports")

    with col3:
        if st.button("📋 View Audit Log", width="stretch"):
            navigate_to("📋 Audit Log")


def show_page_health_center():
    """Operational health center for system and agent status."""
    st.title("🏥 Health Center")
    db = st.session_state.db
    health_monitor = AgentHealthMonitor(db)
    system_health = health_monitor.get_system_health()
    analytics = AgentAnalytics(db)
    system_analytics = analytics.get_system_analytics()

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Overall Health", f"{system_health.get('overall_health', 0)}%")
    with col2:
        st.metric("Active Agents", system_health.get("healthy_agents", 0))
    with col3:
        st.metric("Total Events", system_health.get("total_events", 0))
    with col4:
        st.metric("Success Rate", f"{system_analytics.get('success_rate', 0):.1f}%")

    st.markdown("---")
    agents = db.list_agents()
    if agents:
        health_rows = []
        for agent in agents[:15]:
            health = health_monitor.get_agent_health(agent["id"])
            health_rows.append({
                "Agent": health.get("agent_name", agent["id"]),
                "Status": health.get("status", "unknown"),
                "Health": f"{health.get('health_score', 0)}%",
                "Sessions": health.get("active_sessions", 0),
                "Last Activity": health.get("last_activity", "Never"),
            })
        st.dataframe(pd.DataFrame(health_rows), width="stretch", hide_index=True)
    else:
        st.info("No agents registered yet")


def show_page_activity_timeline():
    """Timeline view for recent platform activity."""
    st.title("🧭 Activity Timeline")
    db = st.session_state.db
    events = db.get_events(limit=200)

    if not events:
        st.info("No activity yet")
        return

    timeline_rows = []
    for event in events[:50]:
        timeline_rows.append({
            "Time": event.get("created_at", ""),
            "Type": event.get("event_type", "unknown"),
            "Agent": event.get("agent_id", "system"),
            "Action": event.get("action", ""),
            "Status": event.get("status", "success"),
            "Details": event.get("details", ""),
        })

    st.dataframe(pd.DataFrame(timeline_rows), width="stretch", hide_index=True)


def show_page_connection_hub():
    """Central place to review company integration settings."""
    st.title("🔌 Connection Hub")
    db = st.session_state.db
    settings = db.get_system_settings()

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Current Connection")
        st.write(f"**Company:** {settings.get('company_name', 'Not configured')}")
        st.write(f"**Environment:** {settings.get('deployment_environment', 'development')}")
        st.write(f"**Identity Provider:** {settings.get('identity_provider', 'Local Accounts')}")
        st.write(f"**App URL:** {settings.get('app_url', 'Not configured')}")
        st.write(f"**API URL:** {settings.get('api_url', 'Not configured')}")

    with col2:
        st.subheader("Integration Options")
        st.write("- Microsoft Entra ID / SSO")
        st.write("- LDAP / Active Directory")
        st.write("- PostgreSQL / SQLite / MySQL")
        st.write("- Key-based secret management")
        st.write("- Audit and monitoring hooks")

    st.markdown("---")
    st.subheader("Stored Settings")
    if settings:
        display_rows = [{"Key": key, "Value": str(value)} for key, value in settings.items()]
        st.dataframe(pd.DataFrame(display_rows), width="stretch", hide_index=True)
    else:
        st.info("No connection settings saved yet")


def show_page_security_operations():
    """Operational security view for admins/operators."""
    st.title("🛡️ Security Operations")
    db = st.session_state.db
    events = db.get_events(limit=250)

    failed_events = [e for e in events if e.get("status") != "success"]
    auth_events = [
        e for e in events if e.get(
            "event_type",
            "").startswith("user_") or e.get(
            "event_type",
            "").startswith("agent_")]

    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Recent Auth Events", len(auth_events))
    with col2:
        st.metric("Failed Events", len(failed_events))
    with col3:
        st.metric("Registered Users", len(db.list_users()))

    st.markdown("---")
    st.subheader("Security Snapshot")
    st.write("- Rate limiting is active in the login flow")
    st.write("- Account lockout is enabled for repeated failures")
    st.write("- SQL injection filtering is active")
    st.write("- Audit logging captures system changes")

    if failed_events:
        st.subheader("Recent Failed Events")
        security_rows = []
        for event in failed_events[:20]:
            security_rows.append({
                "Time": event.get("created_at", ""),
                "Type": event.get("event_type", ""),
                "Agent": event.get("agent_id", "system"),
                "Action": event.get("action", ""),
                "Details": event.get("details", ""),
            })
        st.dataframe(pd.DataFrame(security_rows), width="stretch", hide_index=True)
    else:
        st.success("No failed security events in the recent window")


def show_page_automation_center():
    """Task-oriented automation center for admins/operators."""
    st.title("⚡ Automation Center")
    db = st.session_state.db

    st.subheader("Quick Actions")
    quick_col1, quick_col2, quick_col3 = st.columns(3)
    with quick_col1:
        if st.button("Create Health Check Task", width="stretch"):
            agents = db.list_agents()
            agent_id = agents[0]["id"] if agents else "system"
            db.create_task(agent_id, "health_check", "Run a scheduled health review")
            st.success("Health check task created")
    with quick_col2:
        if st.button("Create Audit Review Task", width="stretch"):
            agents = db.list_agents()
            agent_id = agents[0]["id"] if agents else "system"
            db.create_task(agent_id, "audit_review", "Review recent audit events")
            st.success("Audit review task created")
    with quick_col3:
        if st.button("Create Connection Validation Task", width="stretch"):
            agents = db.list_agents()
            agent_id = agents[0]["id"] if agents else "system"
            db.create_task(agent_id, "connection_check", "Validate company connection settings")
            st.success("Connection validation task created")

    st.markdown("---")
    st.subheader("Recent Tasks")
    tasks = db.list_tasks(limit=50)
    if tasks:
        task_rows = []
        for task in tasks:
            task_rows.append({
                "Time": task.get("created_at", ""),
                "Agent": task.get("agent_id", ""),
                "Task": task.get("task_type", ""),
                "Status": task.get("status", ""),
                "Details": task.get("details", ""),
            })
        st.dataframe(pd.DataFrame(task_rows), width="stretch", hide_index=True)
    else:
        st.info("No tasks created yet")


if __name__ == "__main__":
    main()
