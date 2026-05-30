Start-Process -FilePath (Join-Path $env:USERPROFILE 'Desktop\Agentic-IAM (AutoLogin).lnk')
Start-Sleep -Seconds 6
try {
    $r = Invoke-WebRequest -Uri 'http://127.0.0.1:8502' -UseBasicParsing -TimeoutSec 5
    Write-Output $r.StatusCode
} catch {
    Write-Output ("ERR8502: $($_.Exception.Message)")
}
try {
    $r = Invoke-WebRequest -Uri 'http://127.0.0.1:8501' -UseBasicParsing -TimeoutSec 5
    Write-Output $r.StatusCode
} catch {
    Write-Output ("ERR8501: $($_.Exception.Message)")
}
