param(
    [switch]$UseVenv
)

# Change to repository root (script folder)
Set-Location -Path (Split-Path -Parent $MyInvocation.MyCommand.Definition)

# Activate virtual environment if requested and available
if ($UseVenv) {
    $venvActivate = Join-Path -Path $PWD -ChildPath "venv\Scripts\Activate.ps1"
    if (Test-Path $venvActivate) {
        Write-Output "Activating virtual environment..."
        & $venvActivate
    } else {
        Write-Output "No virtual environment found at: $venvActivate"
    }
}

# Start Streamlit app in a new process
Write-Output "Starting Streamlit on http://localhost:8501 ..."
Start-Process -FilePath "powershell" -ArgumentList "-NoProfile -NoExit -Command \"python -m streamlit run app.py --server.port 8501 --server.headless true\""

Start-Sleep -Seconds 1

# Open default browser to the app
Start-Process "http://localhost:8501"
