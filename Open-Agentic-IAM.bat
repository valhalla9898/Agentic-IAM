@echo off
REM Open Agentic-IAM via venv launcher
cd /d "%~dp0"
call .venv\Scripts\activate.bat
start start_login.bat
