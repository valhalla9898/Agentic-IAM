@echo off
REM Agentic-IAM Quick Launcher
REM This script starts the Agentic-IAM system with automatic setup

setlocal enabledelayedexpansion
cd /d "%~dp0"

cls
echo.
echo ============================================
echo   🔐 AGENTIC-IAM - QUICK LAUNCHER 🔐
echo ============================================
echo.
echo Checking system status...
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ ERROR: Python is not installed or not in PATH
    echo Please install Python 3.10+ from https://www.python.org/
    pause
    exit /b 1
)

REM Check if venv exists
if not exist ".venv" (
    echo ⏳ Creating virtual environment...
    python -m venv .venv
    if errorlevel 1 (
        echo ❌ Failed to create virtual environment
        pause
        exit /b 1
    )
)

REM Activate venv
echo ⏳ Activating virtual environment...
call .venv\Scripts\activate.bat

REM Check if requirements are installed
pip show fastapi >nul 2>&1
if errorlevel 1 (
    echo ⏳ Installing dependencies (first time only)...
    pip install -q -r requirements.txt
)

REM Check if .env exists
if not exist ".env" (
    echo ⏳ Creating .env file from template...
    copy .env.example .env >nul 2>&1
    if errorlevel 1 (
        echo ⚠️  Could not create .env file. Using defaults...
    )
)

REM Show menu
echo.
echo ============================================
echo   SELECT WHAT TO START:
echo ============================================
echo.
echo  [1] 🖥️  Web Dashboard (Easiest)
echo  [2] ⚡ REST API Server
echo  [3] 🐳 Both (Docker Compose)
echo  [4] 🧪 Run Tests
echo  [5] ❌ Exit
echo.

set /p choice="Enter your choice (1-5): "

if "%choice%"=="1" (
    echo.
    echo Starting Web Dashboard...
    echo 🌐 Dashboard will open at http://localhost:8501
    echo.
    timeout /t 2 >nul
    python run_gui.py
) else if "%choice%"=="2" (
    echo.
    echo Starting REST API Server...
    echo 📡 API Docs available at http://localhost:8000/docs
    echo.
    timeout /t 2 >nul
    python api/main.py
) else if "%choice%"=="3" (
    echo.
    echo Starting with Docker Compose...
    docker-compose up
) else if "%choice%"=="4" (
    echo.
    echo Running tests...
    pytest tests/ -v
) else if "%choice%"=="5" (
    exit /b 0
) else (
    echo ❌ Invalid choice
    pause
    goto :eof
)

pause
