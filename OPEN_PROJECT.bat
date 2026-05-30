@echo off
REM One-click launcher for Agentic-IAM
cd /d "%~dp0"
REM Activate venv (cmd)
call "%~dp0venv\Scripts\Activate.bat"
REM Start Streamlit app in a new window
start "Agentic-IAM" "%~dp0venv\Scripts\python.exe" -m streamlit run "%~dp0app.py" --server.port 8502
exit /b 0
