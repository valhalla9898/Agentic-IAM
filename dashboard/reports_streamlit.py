"""
Streamlit UI to browse imported scan reports saved under `data/reports`.

Usage:
  pip install streamlit requests
  streamlit run dashboard/reports_streamlit.py

The app expects the Agentic-IAM API running at http://127.0.0.1:8000 by default.
"""
import streamlit as st
import requests
from urllib.parse import urljoin

st.set_page_config(page_title="Scan Reports", layout="wide")

st.title("Imported Scan Reports")

api_base = st.sidebar.text_input("API base URL", "http://127.0.0.1:8000")
poll = st.sidebar.checkbox("Auto-refresh (30s)", value=False)

def fetch_reports(base_url: str):
    try:
        r = requests.get(urljoin(base_url, "/reports/list"), timeout=5)
        r.raise_for_status()
        return r.json().get("reports", [])
    except Exception as e:
        st.error(f"Failed to fetch reports: {e}")
        return []


def fetch_alerts(base_url: str):
    try:
        r = requests.get(urljoin(base_url, "/alerts/list"), timeout=5)
        r.raise_for_status()
        return r.json().get("alerts", [])
    except Exception as e:
        # Do not spam UI with errors for alerts
        return []

def render_report_block(rep):
    target = rep.get("target")
    ts = rep.get("timestamp")
    files = rep.get("files", [])

    st.subheader(f"{target} — {ts}")
    if not files:
        st.info("No files found for this report")
        return

    cols = st.columns([3, 1])
    with cols[0]:
        for f in files:
            name = f.get("name")
            path = f.get("path")
            url = urljoin(api_base, f"/reports/static/{path}")
            st.markdown(f"- [{name}]({url})")
    with cols[1]:
        if st.button("Open folder", key=f"open_{target}_{ts}"):
            folder_url = urljoin(api_base, f"/reports/static/{target}/{ts}/")
            st.write(f"Open folder: {folder_url}")


def main():
    st.sidebar.markdown("---")
    if st.sidebar.button("Refresh"):
        st.rerun()

    # Auto refresh
    if poll:
        st.rerun()

    alerts = fetch_alerts(api_base)
    if alerts:
        st.markdown("## Recent Alerts")
        for a in alerts[:10]:
            st.warning(f"{a.get('timestamp')} • {a.get('target')} • {a.get('severity').upper()} — {a.get('message')}")
            for url in a.get('evidence_urls', []):
                full = urljoin(api_base, url)
                st.markdown(f"- Evidence: [{url}]({full})")

    reports = fetch_reports(api_base)
    if not reports:
        st.info("No imported reports found. Use `scripts/import_scan.ps1` after running a scan.")
    else:
        for rep in reports:
            render_report_block(rep)

if __name__ == "__main__":
    main()
