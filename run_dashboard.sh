#!/bin/bash
# Agentic-IAM Dashboard Launcher (Linux/Mac)

echo "Starting Agentic-IAM Dashboard..."
cd "$(dirname "$0")"
streamlit run app.py
