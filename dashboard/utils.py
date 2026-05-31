"""
Agentic-IAM: Dashboard Utilities

Helper functions for dashboard components including formatting, alerts, and data management.
"""

import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional

import streamlit as st


def inject_ui_enhancements(rtl: bool = False):
        """Inject lightweight CSS and JS for improved UI (responsive, RTL, toasts, spinner).

        Non-invasive: does not change structure of Streamlit components, only styles and
        adds optional client-side helpers. Call early in `app.py`.
        """
        css = """
        :root{
            --brand-bg: #0b3d91;
            --brand-accent: #ffb400;
            --brand-foreground: #ffffff;
            --card-radius: 8px;
            --gap: 12px;
            --max-width: 1100px;
        }

        /* Container sizing and centering */
        .reportview-container .main > div {
            max-width: var(--max-width) !important;
            margin: 0 auto !important;
            padding: 18px !important;
        }

        /* Card-style sections */
        .stContainer, .css-1d391kg {
            border-radius: var(--card-radius) !important;
            box-shadow: 0 1px 4px rgba(0,0,0,0.06) !important;
        }

        /* Buttons and inputs */
        button, input[type=text], textarea {
            border-radius: 6px !important;
            padding: 8px 10px !important;
        }

        /* Small responsive tweaks */
        @media (max-width: 640px){
            :root{ --max-width: 100%; }
            .reportview-container .main > div { padding: 12px !important; }
        }

        /* RTL support: applied when `rtl` is true by adding `dir="rtl"` to body */
        body[dir="rtl"] { direction: rtl !important; }

        /* Simple toast container */
        #agentic-toast {
            position: fixed;
            right: 16px;
            bottom: 16px;
            z-index: 9999;
            display: none;
            background: rgba(11,61,145,0.95);
            color: white;
            padding: 10px 14px;
            border-radius: 6px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.2);
        }
        """

        js = """
        function showAgenticToast(msg, timeout){
            timeout = timeout || 3500;
            let t = document.getElementById('agentic-toast');
            if(!t){
                t = document.createElement('div');
                t.id = 'agentic-toast';
                document.body.appendChild(t);
            }
            t.innerText = msg;
            t.style.display = 'block';
            clearTimeout(window.__agentic_toast_timeout);
            window.__agentic_toast_timeout = setTimeout(()=>{ t.style.display='none'; }, timeout);
        }

        // Attach to global for debugging
        window.showAgenticToast = showAgenticToast;
        """

        # Apply CSS and JS via an HTML injection
        html = f"""
        <style>{css}</style>
        <script>{js}</script>
        """

        # Use Streamlit HTML injection; allow unsafe HTML because we only inject style/script
        st.markdown(html, unsafe_allow_html=True)

        # If RTL requested, set body dir via a small script
        if rtl:
                st.markdown("""<script>document.body.setAttribute('dir', 'rtl');</script>""", unsafe_allow_html=True)


def show_toast(message: str, timeout: int = 3500):
        """Show a small toast notification using the injected JS helper."""
        safe = str(message).replace("\n", "\\n").replace("'", "\'")
        script = f"<script>if(window.showAgenticToast){{window.showAgenticToast('{safe}', {timeout});}}else{{console.log('toast:', '{safe}');}}</script>"
        st.markdown(script, unsafe_allow_html=True)


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
    colors = {"active": "🟢", "inactive": "🔴", "suspended": "🟡"}
    return colors.get(status, "⚪")


def format_trust_score(score: float) -> str:
    """Format trust score for display"""
    if score is None:
        return "N/A"
    return f"{score:.2%}"


def create_metric_card(title: str, value: Any, delta: str = None) -> Dict:
    """Create metric card data"""
    return {"title": title, "value": value, "delta": delta}


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
        "total_items": len(data),
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
        st.markdown(
            f"**Page {pagination['page']} of {pagination['total_pages']}**", unsafe_allow_html=True
        )

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
