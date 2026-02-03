@echo off
REM Quick run script that activates venv and starts the app

echo.
echo ================================================================
echo              AGENTIC-IAM - Starting with venv
echo ================================================================
echo.

REM Check if venv exists
if not exist "venv\" (
    echo ERROR: Virtual environment not found!
    echo.
    echo Please run setup_venv.bat first to create the virtual environment.
    echo.
    pause
    exit /b 1
)

REM Activate venv
echo Activating virtual environment...
call venv\Scripts\activate.bat

echo Virtual environment activated!
echo.
echo Starting Agentic-IAM Dashboard...
echo.
echo Default Login Credentials:
echo   Admin: admin / admin123
echo   User:  user / user123
echo.
echo Application will open at: http://localhost:8501
echo.
echo Press Ctrl+C to stop the application
echo.
echo ================================================================
echo.

REM Run the application
streamlit run app.py

REM Deactivate on exit
deactivate
