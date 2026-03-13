param(
    [string]$target = "juice-shop",
    [string]$scanFile = "zap-report.html",
    [string]$logsFile = "juice-shop-logs.txt",
    [string]$screenshotsDir = ".\screenshots"
)

$timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
$dest = Join-Path -Path ".\data\reports\$target" -ChildPath $timestamp
New-Item -ItemType Directory -Path $dest -Force | Out-Null

if (Test-Path $scanFile) {
    Copy-Item -Path $scanFile -Destination $dest -Force
}

if (Test-Path $logsFile) {
    Copy-Item -Path $logsFile -Destination $dest -Force
}

if (Test-Path $screenshotsDir) {
    Copy-Item -Path (Join-Path $screenshotsDir "*") -Destination $dest -Recurse -Force -ErrorAction SilentlyContinue
}

# Try to notify local API about the new report (best-effort)
try {
    $body = @{ target = $target; timestamp = $timestamp } | ConvertTo-Json
    Invoke-RestMethod -Uri "http://127.0.0.1:8000/reports/notify" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 10
} catch {
    Write-Host "Warning: failed to notify API - $_"
}

Write-Host "Imported scan to $dest"
