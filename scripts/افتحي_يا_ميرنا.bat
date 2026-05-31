@echo off
REM Wrapper to run the PowerShell launcher (for convenience)
set SCRIPT_DIR=%~dp0
powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%\افتحي_يا_ميرنا.ps1" -UseVenv
