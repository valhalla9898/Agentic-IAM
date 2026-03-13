<#
End-to-end non-interactive demo runner.
Runs the vulnerable target (Juice Shop), runs an OWASP ZAP full scan,
imports the report into the repo, starts the simple detector and opens
the Streamlit viewer. Designed for local lab/demo use only.

Usage (PowerShell):
  .\scripts\run_full_demo.ps1

Requirements:
- Docker installed and running
- Streamlit installed and available on PATH
- Python + uvicorn running api.app separately (recommended)
- Run from project root
#>

# Configuration
$TargetName = "juice-shop"
$TargetImage = "bkimminich/juice-shop:latest"
$TargetPort = 3000
$ApiBase = "http://127.0.0.1:8000"
$ZapReport = "zap-report.html"
$PollDelay = 8

function Run-ContainerIfMissing($name, $image, $port) {
    $exists = docker ps -a --format "{{.Names}}" | Select-String -Pattern "^$name$" -SimpleMatch
    if (-not $exists) {
        docker pull $image | Out-Null
        docker run -d --name $name -p 127.0.0.1:$port:3000 $image | Out-Null
        Start-Sleep -Seconds $PollDelay
    } else {
        $running = docker ps --format "{{.Names}}" | Select-String -Pattern "^$name$" -SimpleMatch
        if (-not $running) {
            docker start $name | Out-Null
            Start-Sleep -Seconds $PollDelay
        }
    }
}

function Run-ZapScan($targetUrl, $outputFile) {
    Write-Host "Running ZAP full scan against $targetUrl ..."
    docker run --rm -v ${PWD}:/zap/wrk/:rw -t owasp/zap2docker-stable zap-full-scan.py -t $targetUrl -r $outputFile | Out-Null
}

function Import-Scan($target, $scanFile) {
    Write-Host "Importing scan results..."
    & .\scripts\import_scan.ps1 -target $target -scanFile $scanFile -logsFile "${target}-logs.txt"
}

function Start-Detector($container, $apiBase) {
    Write-Host "Starting detector in background..."
    Start-Process -FilePath pwsh -ArgumentList "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File .\scripts\attack_detector.ps1 -ContainerName $container -ApiBase $apiBase" -NoNewWindow | Out-Null
}

function Start-StreamlitViewer() {
    Write-Host "Starting Streamlit viewer in background..."
    Start-Process -FilePath streamlit -ArgumentList "run dashboard/reports_streamlit.py" -NoNewWindow | Out-Null
}

# 1) Ensure Docker target is running
Run-ContainerIfMissing -name $TargetName -image $TargetImage -port $TargetPort

# 2) Run ZAP scan
$targetUrl = "http://127.0.0.1:$TargetPort"
Run-ZapScan -targetUrl $targetUrl -outputFile $ZapReport

# 3) Import results
Import-Scan -target $TargetName -scanFile $ZapReport

# 4) Start detector (background)
Start-Detector -container $TargetName -apiBase $ApiBase

# 5) Start Streamlit viewer (background)
Start-StreamlitViewer

Write-Host "Demo started: Juice Shop running, ZAP scan imported, detector and Streamlit started."
Write-Host "Open http://127.0.0.1:8501 to view the Streamlit reports UI (or the CLI output for the streamlit process)."
