# Create Desktop Shortcut for Agentic-IAM
# This script creates a clean desktop icon for launching the application

# Get paths
$desktopPath = [Environment]::GetFolderPath('Desktop')
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$shortcutPath = "$desktopPath\Agentic-IAM.lnk"
$launcherPath = "$scriptDir\LAUNCHER.bat"

# Create WScript Shell object
$WshShell = New-Object -ComObject WScript.Shell

# Create the shortcut
$shortcut = $WshShell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $launcherPath
$shortcut.WorkingDirectory = $scriptDir
$shortcut.Description = "Launch Agentic-IAM - Enterprise IAM & Agent Management System"
$shortcut.IconLocation = "$scriptDir\icon.ico,0"

# Save the shortcut
$shortcut.Save()

Write-Host "✅ Desktop shortcut created successfully!" -ForegroundColor Green
Write-Host "Location: $shortcutPath" -ForegroundColor Cyan
Write-Host ""
Write-Host "You can now double-click 'Agentic-IAM' on your desktop to launch the application." -ForegroundColor Green
