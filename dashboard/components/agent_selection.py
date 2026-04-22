"""
Agent Registration and Selection Module

Provides functionality for registering new agents and selecting existing agents.
"""

import streamlit as st
import uuid
import logging

logger = logging.getLogger(__name__)


def show_agent_registration():
    """Display agent registration form"""
    db = st.session_state.db

    with st.form("agent_registration_form"):
        col1, col2 = st.columns(2)

        with col1:
            agent_name = st.text_input("🏷️ Agent Name", placeholder="e.g., AI Assistant 1")

        with col2:
            agent_type = st.selectbox(
                "🔧 Agent Type",
                ["Standard", "Intelligent", "Processor", "Monitor"],
            )

        description = st.text_area("📝 Description", placeholder="Optional: Agent description")

        submitted = st.form_submit_button("✅ Register Agent", use_container_width=True)

        if submitted:
            if not agent_name:
                st.error("❌ Please enter agent name")
                return

            # Generate unique agent ID
            agent_id = f"agent_{uuid.uuid4().hex[:8]}"

            # Add agent to database
            success = db.add_agent(
                agent_id=agent_id,
                name=agent_name,
                agent_type=agent_type,
                metadata={"description": description, "created_by": "dashboard"}
            )

            if success:
                st.success("✅ Agent registered successfully!")
                st.info(f"🆔 Agent ID: {agent_id}")
                st.balloons()
            else:
                st.error("❌ Registration failed. Please try again")


def show_agent_selector():
    """Display agent selector dropdown"""
    db = st.session_state.db

    # Get all agents from database
    agents = db.list_agents()

    if not agents:
        st.info("📋 No agents registered yet")
        return None

    # Create selectbox with agent names and IDs
    agent_options = {f"{agent['name']} (ID: {agent['id']})": agent['id'] for agent in agents}

    selected = st.selectbox(
        "👥 Select Agent",
        options=list(agent_options.keys()),
        key="agent_selector"
    )

    if selected:
        agent_id = agent_options[selected]
        st.session_state.selected_agent = agent_id
        return agent_id

    return None


def show_agent_list():
    """Display list of all agents from database"""
    db = st.session_state.db
    agents = db.list_agents()

    if not agents:
        st.info("📭 No agents registered")
        return

    # Display agents as cards
    for agent in agents:
        with st.container():
            col1, col2, col3 = st.columns([2, 2, 1])

            with col1:
                st.write(f"**🤖 {agent['name']}**")
                st.caption(f"ID: `{agent['id']}`")

            with col2:
                st.write(f"**Type:** {agent['type']}")
                st.caption(f"**Status:** {agent['status']}")

            with col3:
                col_btn1, col_btn2, col_btn3 = st.columns(3)

                def _select_agent(aid=agent['id']):
                    st.session_state.selected_agent = aid
                    st.rerun()

                def _edit_agent(aid=agent['id']):
                    st.session_state.edit_agent_id = aid
                    st.rerun()

                pending_delete_key = f"pending_delete_agent_{agent['id']}"

                def _begin_delete(aid=agent['id']):
                    st.session_state[pending_delete_key] = True
                    st.rerun()

                def _cancel_delete(aid=agent['id']):
                    st.session_state[pending_delete_key] = False
                    st.rerun()

                def _confirm_delete(aid=agent['id']):
                    try:
                        deleted = db.delete_agent(aid)
                        still_exists = db.get_agent(aid)

                        # Keep registry-backed views in sync when IAM exists in session.
                        registry_exists_before = False
                        registry_deleted = True
                        registry_still_exists = None
                        iam = st.session_state.get("iam")
                        if iam and getattr(iam, "agent_registry", None):
                            registry_exists_before = iam.agent_registry.get_agent(aid) is not None
                            if registry_exists_before:
                                registry_deleted = iam.agent_registry.delete_agent(aid)
                                registry_still_exists = iam.agent_registry.get_agent(aid)

                        if (
                            deleted
                            and still_exists is None
                            and (not registry_exists_before or (registry_deleted and registry_still_exists is None))
                        ):
                            st.success(f"✅ Agent {aid} deleted successfully")
                            if st.session_state.get("selected_agent") == aid:
                                st.session_state.selected_agent = None
                            st.session_state[pending_delete_key] = False
                            st.rerun()
                        elif deleted and still_exists is None and registry_exists_before:
                            st.error(f"Agent {aid} deleted from DB, but registry cleanup failed")
                            st.session_state[pending_delete_key] = False
                            st.rerun()
                        elif deleted and still_exists is not None:
                            st.error(f"Delete reported success, but agent {aid} still exists")
                            st.session_state[pending_delete_key] = False
                            st.rerun()
                        else:
                            st.error(f"Failed to delete agent {aid}")
                            st.session_state[pending_delete_key] = False
                            st.rerun()
                    except Exception as e:
                        st.error(f"Error deleting agent: {e}")
                        st.session_state[pending_delete_key] = False
                        st.rerun()

                with col_btn1:
                    st.button("📊 Details", key=f"detail_{agent['id']}", on_click=_select_agent, use_container_width=True)

                with col_btn2:
                    st.button("📝 Edit", key=f"edit_{agent['id']}", on_click=_edit_agent, use_container_width=True)

                with col_btn3:
                    st.button("🗑️ Delete", key=f"del_{agent['id']}", on_click=_begin_delete, use_container_width=True)

            if st.session_state.get(pending_delete_key):
                st.warning(f"⚠️ **Are you sure you want to delete agent '{agent['name']}' (ID: {agent['id']})?**\n\nThis action **cannot be undone**. All agent data and sessions will be permanently removed.")
                confirm_col, cancel_col = st.columns(2)
                with confirm_col:
                    if st.button("✅ Confirm Delete", key=f"confirm_del_{agent['id']}", use_container_width=True):
                        # Call _confirm_delete with the agent ID
                        _confirm_delete(agent['id'])
                with cancel_col:
                    if st.button("✖ Cancel", key=f"cancel_del_{agent['id']}", use_container_width=True):
                        _cancel_delete(agent['id'])
                        st.rerun()

            st.divider()


def show_agent_details(agent_id: str):
    """Show detailed information about an agent"""
    db = st.session_state.db
    agent = db.get_agent(agent_id)

    if not agent:
        st.error("❌ Agent not found")
        return

    st.subheader(f"📊 Agent Details: {agent['name']}")

    # Agent info
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("🆔 ID", agent['id'])
    with col2:
        st.metric("🔧 Type", agent['type'])
    with col3:
        st.metric("✅ Status", agent['status'])

    st.divider()

    # Metadata
    if agent['metadata']:
        st.write("**📝 Additional Metadata:**")
        for key, value in agent['metadata'].items():
            st.write(f"- **{key}:** {value}")

    st.divider()

    # Agent events/logs
    st.write("**📋 Event Log:**")
    events = db.get_events(agent_id=agent_id, limit=20)

    if events:
        import pandas as pd
        df = pd.DataFrame(events)
        df['created_at'] = pd.to_datetime(df['created_at']).dt.strftime('%Y-%m-%d %H:%M:%S')
        st.dataframe(df[['event_type', 'action', 'details', 'created_at', 'status']], use_container_width=True)
    else:
        st.info("No events yet")

    st.divider()

    # Agent sessions
    st.write("**🔐 Agent Sessions:**")
    sessions = db.get_agent_sessions(agent_id)

    if sessions:
        import pandas as pd
        df = pd.DataFrame(sessions)
        df['started_at'] = pd.to_datetime(df['started_at']).dt.strftime('%Y-%m-%d %H:%M:%S')
        df['ended_at'] = df['ended_at'].apply(lambda x: pd.to_datetime(x).strftime('%Y-%m-%d %H:%M:%S') if x else 'Still Active')
        st.dataframe(df[['id', 'status', 'started_at', 'ended_at']], use_container_width=True)
    else:
        st.info("No sessions")
