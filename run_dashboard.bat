@echo off
REM Agentic-IAM Dashboard Launcher
echo Starting Agentic-IAM Dashboard...
cd /d "%~dp0"
python -m streamlit run app.py
pause
