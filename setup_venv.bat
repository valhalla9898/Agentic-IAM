@echo off
REM Automated Virtual Environment Setup for Agentic-IAM
REM This script creates a venv, installs dependencies, and starts the app

echo.
echo ================================================================
echo          AGENTIC-IAM - Virtual Environment Setup
echo ================================================================
echo.

REM Check if venv already exists
if exist "venv\" (
    echo Virtual environment already exists.
    choice /C YN /M "Do you want to recreate it"
    if errorlevel 2 goto :activate
    if errorlevel 1 goto :create
) else (
    goto :create
)

:create
echo.
echo [1/4] Creating virtual environment...
echo ----------------------------------------------------------------
python -m venv venv
if errorlevel 1 (
    echo ERROR: Failed to create virtual environment
    echo Make sure Python is installed and in PATH
    pause
    exit /b 1
)
echo ✓ Virtual environment created successfully
echo.

:activate
echo [2/4] Activating virtual environment...
echo ----------------------------------------------------------------
call venv\Scripts\activate.bat
if errorlevel 1 (
    echo ERROR: Failed to activate virtual environment
    pause
    exit /b 1
)
echo ✓ Virtual environment activated
echo.

echo [3/4] Installing dependencies...
echo ----------------------------------------------------------------
echo Upgrading pip...
python -m pip install --upgrade pip
echo.
echo Installing requirements...
pip install -r requirements.txt
if errorlevel 1 (
    echo WARNING: Some packages may not have installed correctly
    echo You can try manually with: pip install -r requirements.txt
    pause
)
echo ✓ Dependencies installed
echo.

echo [4/4] Verifying installation...
echo ----------------------------------------------------------------
python --version
pip --version
streamlit --version
echo.

echo ================================================================
echo                    SETUP COMPLETE!
echo ================================================================
echo.
echo Virtual environment is ready and activated!
echo.
echo Default Login Credentials:
echo   Admin: admin / admin123
echo   User:  user / user123
echo.
echo ================================================================
echo.

choice /C YN /M "Do you want to start the application now"
if errorlevel 2 goto :end
if errorlevel 1 goto :run

:run
echo.
echo Starting Agentic-IAM Dashboard...
echo.
echo The application will open in your browser at:
echo http://localhost:8501
echo.
echo Press Ctrl+C to stop the application
echo.
streamlit run app.py
goto :end

:end
echo.
echo To manually start the application later:
echo   1. Activate venv:    venv\Scripts\activate
echo   2. Run application:  streamlit run app.py
echo   3. Deactivate venv:  deactivate
echo.
pause
