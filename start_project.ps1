# Agentic-IAM Project Launcher for PowerShell

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Agentic-IAM Project Launcher" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if virtual environment exists
if (-not (Test-Path "venv")) {
    Write-Host "Creating virtual environment..." -ForegroundColor Yellow
    python -m venv venv
    Write-Host "Virtual environment created." -ForegroundColor Green
}

# Activate virtual environment
Write-Host "Activating virtual environment..." -ForegroundColor Yellow
& ".\venv\Scripts\Activate.ps1"

# Install dependencies if needed
$hasFastapi = pip list | Select-String "fastapi"
if (-not $hasFastapi) {
    Write-Host "Installing dependencies..." -ForegroundColor Yellow
    pip install -e .
}

# Open VS Code
Write-Host "Opening VS Code..." -ForegroundColor Yellow
& code .

# Wait for VS Code to open
Start-Sleep -Seconds 2

# Start API server in new window
Write-Host "Starting API server on http://localhost:8000..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit -Command `"cd '$ScriptDir'; & '.\venv\Scripts\Activate.ps1'; uvicorn api.main:app --reload --port 8000`""

# Wait for API to start
Start-Sleep -Seconds 3

# Start Streamlit dashboard in new window
Write-Host "Starting Streamlit dashboard on http://localhost:8501..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit -Command `"cd '$ScriptDir'; & '.\venv\Scripts\Activate.ps1'; streamlit run dashboard/components/agent_management.py`""

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Project launched successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Services:" -ForegroundColor Cyan
Write-Host "- VS Code IDE: Now opening..." -ForegroundColor Green
Write-Host "- API Server: http://localhost:8000" -ForegroundColor Green
Write-Host "- API Docs: http://localhost:8000/docs" -ForegroundColor Green
Write-Host "- Dashboard: http://localhost:8501" -ForegroundColor Green
Write-Host ""
Write-Host "Close the PowerShell windows when done." -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
