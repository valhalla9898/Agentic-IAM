@echo off
REM Quick Start Script for Agentic-IAM with Login System
REM Run this to start the application

echo.
echo ================================================================
echo              AGENTIC-IAM - LOGIN SYSTEM
echo ================================================================
echo.
echo Starting Agentic-IAM Dashboard with Authentication...
echo.
echo Default Credentials:
echo   Admin: admin / admin123
echo   User:  user / user123
echo.
echo IMPORTANT: Change these passwords after first login!
echo.
echo ================================================================
echo.

REM Run the application
python run_gui.py

REM If run_gui.py doesn't work, try direct launch
if errorlevel 1 (
    echo.
    echo run_gui.py failed, trying direct launch...
    echo.
    streamlit run app.py
)

pause
