@echo off
title Agentic-IAM Dashboard
setlocal
set "ROOT=%~dp0"
cd /d "%ROOT%"

set "PYTHON_CMD="
if exist "%ROOT%.venv\Scripts\python.exe" set "PYTHON_CMD="%ROOT%.venv\Scripts\python.exe""
if not defined PYTHON_CMD if exist "C:\Users\Lenovo\AppData\Local\Programs\Python\Python311\python.exe" set "PYTHON_CMD="C:\Users\Lenovo\AppData\Local\Programs\Python\Python311\python.exe""
if not defined PYTHON_CMD (
	where py >nul 2>&1
	if not errorlevel 1 set "PYTHON_CMD=py -3.11"
)

echo.
echo ================================================
echo   Agentic-IAM Dashboard
echo ================================================
echo   Admin:  admin / admin123
echo   User:   user  / user123
echo ================================================
echo.
echo Checking Python environment...

if not exist "%ROOT%.venv\Scripts\python.exe" goto REBUILD_VENV
"%ROOT%.venv\Scripts\python.exe" -c "import sys" >nul 2>&1
if errorlevel 1 goto REBUILD_VENV
goto START_SERVER

:REBUILD_VENV
echo.
echo Detected broken or missing .venv. Rebuilding environment...
if not defined PYTHON_CMD (
	echo ERROR: No working Python found to rebuild .venv.
	echo Please install Python 3.11 from https://www.python.org/downloads/
	pause
	exit /b 1
)

if exist "%ROOT%.venv" rmdir /s /q "%ROOT%.venv"
call %PYTHON_CMD% -m venv "%ROOT%.venv"
if errorlevel 1 (
	echo ERROR: Failed to create virtual environment.
	pause
	exit /b 1
)

"%ROOT%.venv\Scripts\python.exe" -m pip install --upgrade pip
if exist "%ROOT%requirements.txt" (
	echo Installing requirements...
	"%ROOT%.venv\Scripts\python.exe" -m pip install -r "%ROOT%requirements.txt"
)

:START_SERVER
echo Starting server, please wait...

REM Start Streamlit in the background
start "Streamlit" "%ROOT%.venv\Scripts\python.exe" -m streamlit run "%ROOT%app.py" --server.port 8501 --server.headless true

REM Wait up to 20 seconds for server readiness
for /l %%i in (1,1,20) do (
	powershell -NoProfile -Command "try { (Invoke-WebRequest -UseBasicParsing 'http://localhost:8501' -TimeoutSec 2) ^| Out-Null; exit 0 } catch { exit 1 }" >nul 2>&1
	if not errorlevel 1 goto OPEN_BROWSER
	timeout /t 1 /nobreak >nul
)

:OPEN_BROWSER
REM Open the browser
start "" "http://localhost:8501"

echo.
echo Dashboard is running at http://localhost:8501
echo Close this window to stop the server.
echo.
pause
