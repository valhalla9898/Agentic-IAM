@echo off
REM Automatic Test Runner for Agentic-IAM
REM Runs all tests with reporting and auto-summary

setlocal enabledelayedexpansion
cd /d "%~dp0"

cls
echo.
echo ╔═══════════════════════════════════════════════════════╗
echo ║                                                       ║
echo ║   🧪  AGENTIC-IAM - AUTOMATIC TEST RUNNER            ║
echo ║                                                       ║
echo ╚═══════════════════════════════════════════════════════╝
echo.

REM Activate virtual environment
if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat >nul 2>&1
) else (
    echo ❌ Virtual environment not found
    echo Run LAUNCHER.bat first to setup environment
    pause
    exit /b 1
)

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python not found
    pause
    exit /b 1
)

echo Preparing test environment...
echo.

REM Run pytest with detailed output
echo ═══════════════════════════════════════════════════════
echo Running Test Suite...
echo ═══════════════════════════════════════════════════════
echo.

pytest tests/ -v --tb=short --color=yes 2>&1 | tee test_output.log

echo.
echo ═══════════════════════════════════════════════════════
echo Test Summary
echo ═══════════════════════════════════════════════════════
echo.

REM Extract test summary
for /f "delims=" %%i in ('findstr /c:"passed" test_output.log ^| findstr /c:"failed"') do (
    echo %%i
)

echo.
echo Test report saved to: test_output.log
echo.

REM Ask user what to do next
echo.
echo ═══════════════════════════════════════════════════════
echo.
echo [1] Return to Main Menu
echo [2] Run Tests Again
echo [3] Open Test Report
echo [0] Exit
echo.

set /p testchoice="Choose option (0-3): "

if "%testchoice%"=="1" goto MAIN_MENU
if "%testchoice%"=="2" goto TEST_AGAIN
if "%testchoice%"=="3" start test_output.log & goto MAIN_MENU
if "%testchoice%"=="0" exit /b 0

goto MAIN_MENU

:TEST_AGAIN
cls
goto TEST

:MAIN_MENU
deactivate 2>nul
cd /d "%~dp0" && call LAUNCHER.bat
exit /b 0
