# Set full permissions for the project folder and create desktop shortcut
# Run this script as Administrator to allow permission changes.

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = (Resolve-Path (Join-Path $scriptDir ".." )).Path

Write-Host "Project root: $projectRoot"

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script requires Administrator privileges to set permissions. Please run PowerShell as Administrator and re-run the script."
    exit 1
}

Write-Host "Granting 'Users' full control to project folder (recursively)..."
icacls "$projectRoot" /grant "Users":(OI)(CI)F /T /C

if ($LASTEXITCODE -ne 0) {
    Write-Warning "icacls returned a non-zero exit code. You may need to adjust group name or run manually."
} else {
    Write-Host "Permissions applied successfully." -ForegroundColor Green
}

$createScript = Join-Path $projectRoot "create-shortcut.ps1"
if (Test-Path $createScript) {
    Write-Host "Creating desktop shortcut using create-shortcut.ps1..."
    & $createScript
} else {
    Write-Warning "create-shortcut.ps1 not found at $createScript"
}

Write-Host "All done. If the shortcut was created, double-click it to launch the app." -ForegroundColor Cyan
