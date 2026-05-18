"""Enhanced Streamlit component for real-time security alerts and attack visualization."""
import os
import json
import time
import streamlit as st
import requests
from datetime import datetime
from typing import Optional, List

RESULTS_DIR = os.path.join(os.getcwd(), 'attack_results')
API_BASE = "http://127.0.0.1:8000"


def fetch_active_alerts() -> List[dict]:
    """Fetch active security alerts from API."""
    try:
        response = requests.get(f"{API_BASE}/alerts/active", timeout=5)
        if response.status_code == 200:
            return response.json()
        return []
    except Exception as e:
        st.warning(f"Failed to fetch alerts: {e}")
        return []


def fetch_attack_events() -> List[dict]:
    """Fetch detected attack events from API."""
    try:
        response = requests.get(f"{API_BASE}/alerts/attacks", timeout=5)
        if response.status_code == 200:
            return response.json()
        return []
    except Exception as e:
        st.warning(f"Failed to fetch attacks: {e}")
        return []


def fetch_blocked_ips() -> List[dict]:
    """Fetch blocked IP addresses from API."""
    try:
        response = requests.get(f"{API_BASE}/alerts/blocked-ips", timeout=5)
        if response.status_code == 200:
            return response.json()
        return []
    except Exception as e:
        st.warning(f"Failed to fetch blocked IPs: {e}")
        return []


def show_attack_simulation_results():
    """Display attack simulation results with real-time alerts."""
    st.header('🛡️ Attack Simulation & Security Monitoring')

    # Try to load results from file
    last_meta = os.path.join(RESULTS_DIR, 'last_run.json')
    simulation_data = None

    if os.path.exists(last_meta):
        try:
            with open(last_meta, 'r', encoding='utf-8') as fh:
                simulation_data = json.load(fh)
        except Exception as e:
            st.error(f"Failed to load simulation data: {e}")

    # Create columns for dashboard
    col1, col2, col3 = st.columns(3)

    # Real-time alerts fetch
    alerts = fetch_active_alerts()
    attacks = fetch_attack_events()
    blocked_ips = fetch_blocked_ips()

    with col1:
        st.metric("🔴 Active Alerts", len(alerts))
    with col2:
        st.metric("⚠️ Attack Events", len(attacks))
    with col3:
        st.metric("🚫 Blocked IPs", len(blocked_ips))

    st.divider()

    # Display active alerts with real-time updates
    st.subheader("📢 Active Security Alerts")

    if alerts:
        for alert in alerts[:10]:  # Show top 10
            severity = alert.get('severity', 'medium').upper()
            alert_type = alert.get('alert_type', 'unknown')
            title = alert.get('title', 'Security Alert')
            message = alert.get('message', '')
            created_at = alert.get('created_at', 'unknown')

            # Color based on severity
            if severity == 'CRITICAL':
                emoji = "🔴"
                color = "#FF0000"
            elif severity == 'HIGH':
                emoji = "🟠"
                color = "#FF6600"
            elif severity == 'MEDIUM':
                emoji = "🟡"
                color = "#FFAA00"
            else:
                emoji = "🟢"
                color = "#00AA00"

            # Display alert box
            st.markdown(f"""
            <div style="border-left: 4px solid {color}; padding: 10px; margin: 10px 0; background-color: #f0f0f0; border-radius: 4px;">
                <b>{emoji} {title}</b><br/>
                <small style="color: gray;">{alert_type} | {created_at}</small><br/>
                {message}
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("✅ No active alerts")

    st.divider()

    # Display detected attacks
    st.subheader("🎯 Detected Attack Events")

    if attacks:
        for attack in attacks[:10]:
            attack_type = attack.get('attack_type', 'unknown').upper()
            source_ip = attack.get('source_ip', 'unknown')
            severity = attack.get('severity', 'medium').upper()
            status = attack.get('status', 'unknown').upper()
            detected_at = attack.get('detected_at', 'unknown')

            col_type, col_ip, col_status = st.columns(3)
            with col_type:
                st.write(f"**Type**: {attack_type}")
            with col_ip:
                st.write(f"**Source**: {source_ip}")
            with col_status:
                st.write(f"**Status**: {status}")

            st.caption(f"Detected: {detected_at}")
            st.divider()
    else:
        st.info("No attack events detected")

    st.divider()

    # Display blocked IPs
    st.subheader("🚫 Blocked IP Addresses")

    if blocked_ips:
        for block in blocked_ips[:10]:
            ip = block.get('ip', 'unknown')
            reason = block.get('reason', 'unknown')
            blocked_at = block.get('blocked_at', 'unknown')

            st.warning(f"**{ip}** - {reason} (blocked at {blocked_at})")
    else:
        st.info("No blocked IPs")

    st.divider()

    # Display simulation video
    if simulation_data:
        st.subheader("📹 Attack Simulation Recording")

        # Look for video
        video = simulation_data.get('video')
        demo_video = os.path.join(RESULTS_DIR, 'attack_demo.mp4')

        # Prefer demo video if available
        if os.path.exists(demo_video):
            video = demo_video
            st.info("🎬 Showing annotated simulation video")

        if video and os.path.exists(video):
            st.video(video)
        else:
            st.warning("No video recording available")

        # Display simulation events timeline
        st.subheader("📊 Simulation Event Timeline")
        events = simulation_data.get('events', [])

        if events:
            for i, event in enumerate(events, 1):
                event_type = event.get('event', 'unknown')
                ts = event.get('ts', 'unknown')

                # Different colors for different event types
                if 'attack' in event_type.lower():
                    emoji = "⚔️"
                elif 'block' in event_type.lower():
                    emoji = "🛡️"
                elif 'alert' in event_type.lower():
                    emoji = "⚠️"
                else:
                    emoji = "📍"

                st.markdown(f"{emoji} **{event_type}** - {ts}")

                # Show details if available
                details = {k: v for k, v in event.items() if k not in ('ts', 'event')}
                if details:
                    st.json(details)
        else:
            st.info("No simulation events recorded")
    else:
        st.info("No simulation data available. Run attack simulator to generate results.")

    # Auto-refresh option
    st.divider()
    if st.checkbox("Auto-refresh alerts every 5 seconds"):
        import time
        placeholder = st.empty()
        while True:
            with placeholder.container():
                st.info("Auto-refreshing... (check back in 5 seconds)")
            time.sleep(5)
            st.rerun()
