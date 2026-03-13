<#
Simple attack detector (best-effort) for local testing.
It continuously tails the Docker container logs for a target container
(like `juice-shop`) and triggers an alert to the API when suspicious
patterns appear.

Usage:
  .\scripts\attack_detector.ps1 -ContainerName juice-shop -ApiBase http://127.0.0.1:8000

Notes:
- This is a lightweight helper for demonstrations and testing only.
- Customize `$Patterns` for what you consider suspicious.
#>

param(
    [string]$ContainerName = "juice-shop",
    [string]$ApiBase = "http://127.0.0.1:8000",
    [int]$PollSeconds = 5
)

function Send-Alert($target, $severity, $message, $evidencePath) {
    $timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
    $body = @{
        target = $target
        severity = $severity
        message = $message
        details = @{ detector = 'simple-log-monitor' }
        evidence_urls = @()
    } | ConvertTo-Json

    try {
        # If an evidence file exists under project data, copy it to reports and include URL
        if (Test-Path $evidencePath) {
            $destDir = Join-Path -Path ".\data\reports\$target" -ChildPath $timestamp
            New-Item -ItemType Directory -Path $destDir -Force | Out-Null
            Copy-Item -Path $evidencePath -Destination $destDir -Force
            $rel = "$target/$timestamp/$(Split-Path $evidencePath -Leaf)" -replace '\\\\','/'
            $bodyObj = $body | ConvertFrom-Json
            $bodyObj.evidence_urls = @("/reports/static/$rel")
            $body = $bodyObj | ConvertTo-Json
        }

        Invoke-RestMethod -Uri "$ApiBase/alerts" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 10
        Write-Host "[Alert] Sent: $message"
    }
    catch {
        Write-Warning "Failed to send alert: $_"
    }
}

# Patterns (edit as needed) - keep generic, not exploit steps
$Patterns = @(
    'unauthorized',
    'error',
    'exception',
    'sql',
    'xss',
    'forbidden',
    'attack'
)

Write-Host "Starting simple detector for container: $ContainerName (poll every $PollSeconds seconds)"

# Keep a marker file for last log offset
$markerFile = ".\scripts\attack_detector.offset"
$lastSize = 0
if (Test-Path $markerFile) { $lastSize = [int](Get-Content $markerFile -ErrorAction SilentlyContinue) }

while ($true) {
    try {
        $logs = docker logs $ContainerName 2>&1 | Out-String
        if (-not $logs) { Start-Sleep -Seconds $PollSeconds; continue }

        # simple check: if logs length increased, inspect new content
        $currentSize = $logs.Length
        if ($currentSize -le $lastSize) { Start-Sleep -Seconds $PollSeconds; continue }

        $newContent = $logs.Substring($lastSize)
        $lastSize = $currentSize
        Set-Content -Path $markerFile -Value $lastSize

        foreach ($p in $Patterns) {
            if ($newContent -match [regex]::Escape($p)) {
                $snippet = ($newContent -split "`n" | Select-String -Pattern $p -SimpleMatch -Context 2,2 | Select-Object -First 1).ToString()
                $evidencePath = ".\data\reports\$ContainerName`_evidence.txt"
                $snippet | Out-File -FilePath $evidencePath -Encoding utf8 -Append
                Send-Alert -target $ContainerName -severity "high" -message "Suspicious pattern matched: $p" -evidencePath $evidencePath
                break
            }
        }
    }
    catch {
        Write-Warning "Detector error: $_"
    }

    Start-Sleep -Seconds $PollSeconds
}
