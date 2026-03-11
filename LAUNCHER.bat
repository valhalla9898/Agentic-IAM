@echo off
REM ================================================================
REM       Agentic-IAM One-Click Launcher
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
    echo Download from: https://www.docker.com/products/docker-desktop
    echo.
    pause
    exit /b 1
)
echo [OK] Docker is installed

REM Step 2: Start containers
echo Checking Docker containers...
docker-compose ps >nul 2>&1
if errorlevel 1 (
    echo.
    echo Starting Docker containers...
    call docker-compose up -d
    echo.
    echo Waiting for services to start...
    timeout /t 10 /nobreak
) else (
    echo [OK] Containers are ready
)

REM Step 3: Display connection info
echo.
echo ================================================================
echo                    CONNECTION DETAILS
echo ================================================================
echo.
echo    DASHBOARD       http://localhost:8501
echo    API SERVER      http://localhost:8000
echo    MONITORING      http://localhost:9090
echo    DATABASE        localhost:5432
echo    REDIS CACHE     localhost:6379
echo.
echo ================================================================
echo                    USEFUL COMMANDS
echo ================================================================
echo.
echo    docker-compose down
echo    docker-compose logs -f agentic-iam-app
echo    docker-compose restart
echo    docker ps
echo.
echo ================================================================
echo.

REM Step 4: Open dashboard
echo Opening dashboard in browser...
timeout /t 2 /nobreak >nul
start "" "http://localhost:8501"

echo.
echo SUCCESS - Agentic-IAM is now running!
echo Access dashboard at: http://localhost:8501
echo.
pause

REM Keep launcher running
:loop
timeout /t 60 /nobreak >nul
goto loop
