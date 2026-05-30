$project = 'C:\Users\Lenovo\Desktop\Agentic-IAM-main'
$openbat = Join-Path $project 'OPEN_PROJECT.bat'
$ws = New-Object -ComObject WScript.Shell
# Start the app (non-blocking)
Start-Process -FilePath $openbat
# Give streamlit a few seconds to start
Start-Sleep -Seconds 4
# Open default browser to the dashboard
Start-Process "http://127.0.0.1:8502/"
# Wait for browser to open
Start-Sleep -Seconds 3
# Try to activate the browser window (try several common titles)
$activated = $false
$tries = 0
$targets = @('127.0.0.1:8502', 'Agentic-IAM', 'Q&A Dashboard', 'Agentic-IAM Dashboard', 'localhost:8502')
while(-not $activated -and $tries -lt 12){
    foreach($t in $targets){
        try{
            if($ws.AppActivate($t)){
                $activated = $true
                break
            }
        } catch { }
    }
    if(-not $activated){ Start-Sleep -Milliseconds 500 }
    $tries++
}
Start-Sleep -Milliseconds 400
# Send login keys (may fail if focus is different)
$ws.SendKeys('admin{TAB}admin123{ENTER}')
