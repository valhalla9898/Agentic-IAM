"""
Agentic-IAM: Dashboard Utilities

Helper functions for dashboard components including formatting, alerts, and data management.
"""
import asyncio
import streamlit as st
from datetime import datetime
from typing import Optional, Dict, Any, List, Tuple


def safe_async_run(coro):
    """Safely run async function"""
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


def format_datetime(dt: Optional[datetime]) -> str:
    """Format datetime for display"""
    if not dt:
        return "N/A"
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def get_status_color(status: str) -> str:
    """Get emoji color for status"""
    colors = {
        "active": "🟢",
        "inactive": "🔴",
        "suspended": "🟡"
    }
    return colors.get(status, "⚪")


def format_trust_score(score: float) -> str:
    """Format trust score for display"""
    if score is None:
        return "N/A"
    return f"{score:.2%}"


def create_metric_card(title: str, value: Any, delta: str = None) -> Dict:
    """Create metric card data"""
    return {
        "title": title,
        "value": value,
        "delta": delta
    }


def show_alert(message: str, alert_type: str = "info"):
    """Show alert message"""
    if alert_type == "error":
        st.error(message)
    elif alert_type == "warning":
        st.warning(message)
    elif alert_type == "success":
        st.success(message)
    else:
        st.info(message)


def paginate_data(data: List[Dict], page_size: int, page_number: int) -> Dict:
    """Paginate list data"""
    total_pages = (len(data) + page_size - 1) // page_size
    
    if page_number < 1:
        page_number = 1
    if page_number > total_pages:
        page_number = total_pages
    
    start_idx = (page_number - 1) * page_size
    end_idx = start_idx + page_size
    
    return {
        "data": data[start_idx:end_idx],
        "page": page_number,
        "total_pages": total_pages,
        "total_items": len(data)
    }


def render_pagination(pagination: Dict, key: str = "page"):
    """Render pagination controls"""
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col1:
        if pagination["page"] > 1:
            if st.button("← Previous", key=f"{key}_prev"):
                st.session_state[f"{key}_page"] = pagination["page"] - 1
                st.rerun()
    
    with col2:
        st.markdown(f"**Page {pagination['page']} of {pagination['total_pages']}**", unsafe_allow_html=True)
    
    with col3:
        if pagination["page"] < pagination["total_pages"]:
            if st.button("Next →", key=f"{key}_next"):
                st.session_state[f"{key}_page"] = pagination["page"] + 1
                st.rerun()


def validate_agent_id(agent_id: str) -> bool:
    """Validate agent ID format"""
    if not agent_id:
        return False
    if not agent_id.startswith("agent:"):
        return False
    if len(agent_id) < 8:
        return False
    return True


def handle_error(error: Exception, context: str = ""):
    """Handle and display error"""
    error_msg = f"Error {f'while {context}' if context else ''}: {str(error)}"
    st.error(error_msg)
    print(f"[ERROR] {error_msg}")
