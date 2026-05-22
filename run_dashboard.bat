@echo off
REM Agentic-IAM Dashboard Launcher
echo Starting Agentic-IAM Dashboard...
cd /d "%~dp0"
start "Agentic-IAM Streamlit" /b cmd /c "venv\Scripts\python.exe -m streamlit run app.py --server.address 127.0.0.1 --server.port 8501 --server.headless true"
timeout /t 8 /nobreak >nul
start "" "http://localhost:8501/?page=Bloome"
pause
