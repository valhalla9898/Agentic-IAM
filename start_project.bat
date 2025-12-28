@echo off
REM Agentic-IAM Project Launcher
REM Launches VS Code and starts all services

setlocal enabledelayedexpansion

REM Get the script directory
set SCRIPT_DIR=%~dp0
cd /d "%SCRIPT_DIR%"

echo.
echo ========================================
echo  Agentic-IAM Project Launcher
echo ========================================
echo.

REM Check if virtual environment exists
if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
    echo Virtual environment created.
)

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat

REM Install dependencies if needed
pip list | find "fastapi" >nul
if errorlevel 1 (
    echo Installing dependencies...
    pip install -e .
)

REM Open VS Code
echo Opening VS Code...
start code .

REM Wait a moment for VS Code to open
timeout /t 2 /nobreak

REM Start API server in a new window
echo Starting API server on http://localhost:8000...
start cmd /k "cd /d "%SCRIPT_DIR%" && venv\Scripts\activate.bat && uvicorn api.main:app --reload --port 8000"

REM Wait for API to start
timeout /t 3 /nobreak

REM Start Streamlit dashboard in a new window
echo Starting Streamlit dashboard on http://localhost:8501...
start cmd /k "cd /d "%SCRIPT_DIR%" && venv\Scripts\activate.bat && streamlit run dashboard/components/agent_management.py"

echo.
echo ========================================
echo Project launched successfully!
echo.
echo Services:
echo - VS Code IDE: Now opening...
echo - API Server: http://localhost:8000
echo - API Docs: http://localhost:8000/docs
echo - Dashboard: http://localhost:8501
echo.
echo Close the command windows when done.
echo ========================================
echo.
