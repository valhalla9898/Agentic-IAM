@echo off
REM ================================================================
REM  AGENTIC-IAM - FIRST TIME SETUP
REM  Run this script ONCE to set up everything automatically
REM ================================================================

setlocal enabledelayedexpansion
set "PY_CMD="

echo.
echo ================================================================
echo           AGENTIC-IAM SETUP - First Time Setup
echo ================================================================
echo.

REM Go back to parent directory (the actual project root)
cd /d "%~dp0.."

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    py -3 --version >nul 2>&1
    if errorlevel 1 (
        echo ERROR: Python is not installed or not in PATH
        echo Please install Python 3.9 or higher from https://www.python.org
        echo.
        pause
        exit /b 1
    )
    set "PY_CMD=py -3"
) else (
    set "PY_CMD=python"
)

echo [OK] Python found
echo.

REM Step 1: Create virtual environment
echo [Step 1/4] Creating Python environment...
if exist ".venv\" (
    echo        Virtual environment already exists, skipping...
) else (
    %PY_CMD% -m venv .venv
    if errorlevel 1 (
        echo ERROR: Failed to create virtual environment
        pause
        exit /b 1
    )
    echo        [OK] Virtual environment created
)

echo.

REM Step 2: Activate virtual environment
echo [Step 2/4] Activating environment...
call .venv\Scripts\activate.bat
if errorlevel 1 (
    echo ERROR: Failed to activate virtual environment
    pause
    exit /b 1
)
echo        [OK] Environment activated

echo.

REM Step 3: Install dependencies
echo [Step 3/4] Installing dependencies (this may take 1-2 minutes)...
python -m pip install --upgrade pip
if errorlevel 1 (
    echo ERROR: Failed to upgrade pip
    pause
    exit /b 1
)

pip install -r requirements.txt
if errorlevel 1 (
    echo ERROR: Failed to install dependencies from requirements.txt
    echo Please check internet connection and rerun this script.
    pause
    exit /b 1
) else (
    echo        [OK] All dependencies installed
)

echo.

REM Step 4: Create desktop shortcut
echo [Step 4/4] Creating desktop shortcut...
powershell -NoProfile -ExecutionPolicy Bypass -File ".\create-shortcut.ps1"
if errorlevel 0 (
    echo        [OK] Desktop shortcut created
) else (
    echo        [WARN] Shortcut creation failed.
    echo        You can still run app with: start_login.bat
)

echo.
echo ================================================================
echo                    SETUP COMPLETE!
echo ================================================================
echo.
echo You can now:
echo   1. Double-click "Agentic-IAM" on your desktop
echo   2. Or run: start_login.bat
echo   3. Or run: python run_gui.py
echo.
echo The dashboard will open at: http://localhost:8501
echo.
echo Login with:
echo   Admin: admin / admin123
echo   User:  user / user123
echo.
echo [IMPORTANT] Change these passwords after first login!
echo.
echo ================================================================
echo.
choice /C YN /N /M "Open application now? (Y/N): "
if errorlevel 2 goto end

echo Starting application...
call start_login.bat

:end
echo.
echo Setup script finished.
pause
