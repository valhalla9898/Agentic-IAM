"""Streamlit component to display latest attack simulation video and metadata."""

import json
import os

import streamlit as st

RESULTS_DIR = os.path.join(os.getcwd(), "attack_results")


def show_attack_results():
    st.header("Attack Simulation Results")
    if not os.path.exists(RESULTS_DIR):
        st.info("No attack results found. Run `scripts/attack_simulator.py` to generate results.")
        return

    last_meta = os.path.join(RESULTS_DIR, "last_run.json")
    if not os.path.exists(last_meta):
        st.info("No last_run.json found in attack_results.")
        return

    with open(last_meta, "r", encoding="utf-8") as fh:
        meta = json.load(fh)

    st.subheader("Summary")
    st.json({k: v for k, v in meta.items() if k != "events"})

    # Look for video in multiple locations
    video = meta.get("video")
    demo_video = os.path.join(RESULTS_DIR, "attack_demo.mp4")

    if not video or not os.path.exists(video):
        video = None

    # Prefer demo video if available, otherwise use recorded video
    if os.path.exists(demo_video):
        video = demo_video
        st.info("Showing annotated demo video (animated event log)")

    if video and os.path.exists(video):
        st.subheader("Recorded Video")
        st.video(video)
    else:
        st.warning("No recorded video available")

    st.subheader("Events")
    st.write(len(meta.get("events", [])), "events")
    for e in meta.get("events", []):
        st.markdown(f"- **{e.get('ts')}**: {e.get('event')}")
