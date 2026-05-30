# Create Admin Shortcut pointing to run_admin.bat

$desktopPath = [Environment]::GetFolderPath('Desktop')
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$shortcutPath = "$desktopPath\Agentic-IAM (Admin).lnk"
$batchFile = "$scriptDir\run_admin.bat"

# Create WScript Shell object
$WshShell = New-Object -ComObject WScript.Shell

# Create the shortcut
$shortcut = $WshShell.CreateShortcut($shortcutPath)

# Point to the batch file with admin privileges
$shortcut.TargetPath = "cmd.exe"
$shortcut.Arguments = "/c `"$batchFile`""
$shortcut.WorkingDirectory = $scriptDir
$shortcut.Description = "Launch Agentic-IAM Dashboard with Admin Privileges"
$shortcut.IconLocation = "$env:SystemRoot\System32\cmd.exe,0"

# Save the shortcut
$shortcut.Save()

# Set the shortcut to run as Administrator
# This modifies the shortcut file directly to set the admin flag
$bytes = [System.IO.File]::ReadAllBytes($shortcutPath)
$bytes[0x15] = $bytes[0x15] -bor 0x20
[System.IO.File]::WriteAllBytes($shortcutPath, $bytes)

Write-Host "✅ Admin Shortcut created successfully!" -ForegroundColor Green
Write-Host "Name: Agentic-IAM (Admin)" -ForegroundColor Cyan
Write-Host "Location: $shortcutPath" -ForegroundColor Cyan
Write-Host ""
Write-Host "The shortcut will:" -ForegroundColor Yellow
Write-Host "  1. Request Admin Privileges" -ForegroundColor Yellow
Write-Host "  2. Activate Virtual Environment" -ForegroundColor Yellow
Write-Host "  3. Launch Streamlit Dashboard" -ForegroundColor Yellow
