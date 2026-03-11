@echo off
REM ================================================================
REM       Agentic-IAM One-Click Launcher (PowerShell Wrapper)
REM ================================================================

setlocal enabledelayedexpansion

echo.
echo ================================================================
echo           AGENTIC-IAM LAUNCHER - Enterprise Edition
echo ================================================================
echo.

REM Get the directory where this script is
cd /d "%~dp0"

REM Step 1: Check Docker
echo Checking Docker...
docker --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Docker not found. Please install Docker Desktop.
    echo.
    pause
    exit /b 1
)
echo [OK] Docker is installed
echo.

REM Step 2: Start containers
echo Checking Docker containers...
docker ps | find "agentic-iam" >nul 2>&1
if errorlevel 1 (
    echo Starting Docker containers...
    docker-compose up -d >nul 2>&1
    echo Waiting for services to start (10 seconds)...
    timeout /t 10 /nobreak
) else (
    echo [OK] Containers already running
)
echo.

REM Step 3: Display connection info
echo ================================================================
echo                    CONNECTION DETAILS
echo ================================================================
echo.
echo [DASHBOARD]   http://localhost:8501
echo [API SERVER]  http://localhost:8000
echo [MONITORING]  http://localhost:9090
echo [DATABASE]    localhost:5432
echo [REDIS CACHE] localhost:6379
echo.
echo ================================================================
echo                    USEFUL COMMANDS
echo ================================================================
echo.
echo Stop all services   : docker-compose down
echo View logs          : docker-compose logs -f agentic-iam-app
echo Restart services   : docker-compose restart
echo Check containers   : docker ps
echo.
echo ================================================================
echo.

REM Step 4: Open dashboard
echo Opening dashboard in browser...
timeout /t 2 /nobreak >nul
start "Agentic-IAM Dashboard" http://localhost:8501

echo.
echo SUCCESS: Agentic-IAM is running!
echo.
echo Press any key to continue...
pause >nul

cls
@REM Keep launcher window open with info
:loop
echo.
echo Agentic-IAM is running in Docker containers
echo Press Ctrl+C to stop the launcher (containers will keep running)
echo.
echo Dashboard: http://localhost:8501
echo.
timeout /t 30 /nobreak >nul
cls
goto loop
