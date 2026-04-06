import streamlit as st
from typing import Dict, Any

def compute_risk_score(agent: Dict[str, Any]) -> float:
    # Simple heuristic risk score for demo: combine failed actions and age
    failures = agent.get('failed_actions', 0)
    alerts = agent.get('alerts', 0)
    uptime_days = agent.get('uptime_days', 1)
    score = min(100.0, (failures * 2.5) + (alerts * 5.0) + max(0, 10 - uptime_days))
    return round(score, 2)


def show_risk_assessment(db):
    st.header("⚠️ Risk Assessment")
    st.write("Quick agent risk assessment and remediation guidance.")

    agents = db.list_agents()
    if not agents:
        st.info("No agents available to assess.")
        return

    cols = st.columns([3, 1])
    with cols[0]:
        names = [f"{a['id']} - {a.get('name','(unnamed)')}" for a in agents]
        sel = st.selectbox("Select agent", names)
    with cols[1]:
        if st.button("Assess all"):
            for a in agents:
                a['risk_score'] = compute_risk_score(a)
            st.success("Assessed risk for all agents")
            st.rerun()

    # show details for selected
    if sel:
        aid = sel.split(' - ')[0]
        agent = db.get_agent(aid)
        score = compute_risk_score(agent)
        st.metric("Risk Score", f"{score}/100")

        st.subheader("Risk Factors")
        st.write({
            'failed_actions': agent.get('failed_actions', 0),
            'alerts': agent.get('alerts', 0),
            'uptime_days': agent.get('uptime_days', 1)
        })

        st.subheader("Recommended Actions")
        if score > 70:
            st.warning("High risk: quarantine agent, rotate credentials, run forensic audit.")
        elif score > 40:
            st.info("Medium risk: increase monitoring, review recent config changes.")
        else:
            st.success("Low risk: normal monitoring")

        if st.button("Create remediation task"):
            st.session_state.db.create_task(agent_id=aid, task_type='remediation', details='Auto-generated remediation')
            st.success("Remediation task created")
            st.rerun()
