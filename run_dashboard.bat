@echo off
REM Agentic-IAM Dashboard Launcher
echo Starting Agentic-IAM Dashboard...
cd /d "%~dp0"
streamlit run app.py
pause
