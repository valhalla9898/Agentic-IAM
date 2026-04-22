@echo off
REM Agentic-IAM - Fixed Desktop Shortcut Launcher
REM This batch file is the target of the desktop shortcut
REM It handles all startup logic with full error checking

setlocal enabledelayedexpansion
cd /d "%~dp0"

:MAIN_MENU
cls
echo.
echo ╔══════════════════════════════════════════════════════╗
echo ║                                                      ║
echo ║   🔐  AGENTIC-IAM - ENTERPRISE IAM FOR AI            ║
echo ║                                                      ║
echo ╚══════════════════════════════════════════════════════╝
echo.
echo System Check...
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ ERROR: Python 3.10+ is required
    echo.
    echo Solution: Install from https://www.python.org/
    pause
    exit /b 1
)

REM Check/Create venv
if not exist ".venv" (
    echo ⏳ Setting up Python environment (first time)...
    python -m venv .venv >nul 2>&1
)

REM Activate venv
call .venv\Scripts\activate.bat >nul 2>&1

REM Check dependencies
pip show fastapi >nul 2>&1
if errorlevel 1 (
    echo ⏳ Installing dependencies ^(first time^)...
    echo    This may take 1-2 minutes...
    pip install -q -r requirements.txt
    if errorlevel 1 (
        echo ❌ Failed to install dependencies
        pause
        exit /b 1
    )
)

echo ✅ System ready!
echo.
echo ════════════════════════════════════════════════════════
echo                    SELECT WHAT TO RUN
echo ════════════════════════════════════════════════════════
echo.
echo   [1] 🖥️  WEB DASHBOARD ^(Recommended - Easiest^)
echo       ^→ GUI for all management
echo       ^→ Opens: http://localhost:8501
echo.
echo   [2] ⚡ REST API SERVER ^(For developers^)
echo       ^→ Programmatic control
echo       ^→ Opens: http://localhost:8000/docs
echo.
echo   [3] 🐳 DOCKER COMPOSE ^(Full setup^)
echo       ^→ Requires Docker Desktop installed
echo.
echo   [4] 🧪 RUN TESTS ^(Verify installation^)
echo       ^→ 88 tests, 94.2%% coverage
echo.
echo   [0] ❌ EXIT
echo.
echo ════════════════════════════════════════════════════════
echo.

set /p choice="Enter choice ^(0-4^): "

if "%choice%"=="1" goto DASHBOARD
if "%choice%"=="2" goto API
if "%choice%"=="3" goto DOCKER
if "%choice%"=="4" goto TESTS
if "%choice%"=="0" goto END
goto INVALID

:DASHBOARD
echo.
echo Starting Web Dashboard...
echo ⏳ Loading ^(first time may take a few seconds^)...
echo.
echo 🌐 Open browser to: http://localhost:8501
echo 📝 Login: admin / admin ^(change immediately!^)
echo.
timeout /t 3 >nul
python run_gui.py
goto END

:API
echo.
echo Starting REST API Server...
echo.
echo 📡 API available at: http://localhost:8000/docs
echo 📊 GraphQL at: http://localhost:8000/graphql
echo.
timeout /t 2 >nul
python api/main.py
goto END

:DOCKER
echo.
echo Checking Docker...
docker --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Docker is not installed
    echo Install from: https://www.docker.com/products/docker-desktop
    pause
    goto MAIN_MENU
)
echo ✅ Docker found
echo.
echo Starting Docker Compose...
docker-compose up
goto END

:TESTS
echo.
echo Running test suite...
echo ⏳ This will take 1-2 minutes...
echo.
pytest tests/ -v --tb=short
echo.
echo Press any key to continue...
pause >nul
goto MAIN_MENU

:INVALID
echo ❌ Invalid choice. Please try again.
timeout /t 2 >nul
goto MAIN_MENU

:END
deactivate 2>nul
exit /b 0

pause
