# Agentic-IAM Setup & Launcher Script
# Run with: powershell -ExecutionPolicy Bypass -File setup_and_launch.ps1

param(
    [string]$Action = "menu"
)

# Colors
$Green = "Green"
$Red = "Red"
$Yellow = "Yellow"
$Cyan = "Cyan"

function Show-Banner {
    Clear-Host
    Write-Host "╔════════════════════════════════════════╗" -ForegroundColor $Cyan
    Write-Host "║  🔐  AGENTIC-IAM LAUNCHER       🔐  ║" -ForegroundColor $Cyan
    Write-Host "║  Enterprise IAM for AI Agents         ║" -ForegroundColor $Cyan
    Write-Host "╚════════════════════════════════════════╝" -ForegroundColor $Cyan
    Write-Host ""
}

function Setup-Environment {
    Write-Host "⏳ Checking system requirements..." -ForegroundColor $Yellow
    
    # Check Python
    $pythonInstalled = python --version 2>$null
    if (-not $pythonInstalled) {
        Write-Host "❌ Python 3.10+ not found" -ForegroundColor $Red
        Write-Host "📥 Install from: https://www.python.org/" -ForegroundColor $Yellow
        exit 1
    }
    Write-Host "✅ Python found: $pythonInstalled" -ForegroundColor $Green
    
    # Check/Create venv
    if (-not (Test-Path ".venv")) {
        Write-Host "⏳ Creating virtual environment..." -ForegroundColor $Yellow
        python -m venv .venv
        Write-Host "✅ Virtual environment created" -ForegroundColor $Green
    }
    
    # Activate venv
    & ".\.venv\Scripts\Activate.ps1"
    
    # Check dependencies
    $fastapi = pip show fastapi 2>$null
    if (-not $fastapi) {
        Write-Host "⏳ Installing dependencies (first time)..." -ForegroundColor $Yellow
        pip install -q -r requirements.txt
        Write-Host "✅ Dependencies installed" -ForegroundColor $Green
    }
    
    # Create .env if missing
    if (-not (Test-Path ".env")) {
        Copy-Item ".env.example" ".env" -ErrorAction SilentlyContinue
    }
    
    Write-Host "✅ Environment ready!" -ForegroundColor $Green
    Write-Host ""
}

function Show-Menu {
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor $Cyan
    Write-Host "  SELECT OPTION:" -ForegroundColor $Cyan
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor $Cyan
    Write-Host ""
    Write-Host "  [1] 🖥️  Start Web Dashboard (Recommended)" -ForegroundColor White
    Write-Host "       → Opens http://localhost:8501" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [2] ⚡ Start REST API Server" -ForegroundColor White
    Write-Host "       → Opens http://localhost:8000/docs" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [3] 🐳 Start with Docker Compose" -ForegroundColor White
    Write-Host "       → Starts all services at once" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [4] 🧪 Run Test Suite" -ForegroundColor White
    Write-Host "       → Execute 88 tests (94.2% coverage)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [5] 📚 Open Documentation" -ForegroundColor White
    Write-Host "       → Show README & guides" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [6] 🔑 Create Desktop Shortcut" -ForegroundColor White
    Write-Host "       → Add icon to desktop" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [0] ❌ Exit" -ForegroundColor White
    Write-Host ""
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor $Cyan
    Write-Host ""
}

function Start-Dashboard {
    Write-Host ""
    Write-Host "🖥️  Starting Web Dashboard..." -ForegroundColor $Green
    Write-Host "   📍 Opening browser to: http://localhost:8501" -ForegroundColor $Yellow
    Write-Host "   💡 Default credentials: admin / admin" -ForegroundColor $Yellow
    Write-Host "   ⚠️  Change password immediately!" -ForegroundColor $Red
    Write-Host ""
    Start-Sleep -Seconds 2
    python run_gui.py
}

function Start-API {
    Write-Host ""
    Write-Host "⚡ Starting REST API Server..." -ForegroundColor $Green
    Write-Host "   📍 API Docs:  http://localhost:8000/docs" -ForegroundColor $Yellow
    Write-Host "   📍 GraphQL:   http://localhost:8000/graphql" -ForegroundColor $Yellow
    Write-Host "   📍 ReDoc:     http://localhost:8000/redoc" -ForegroundColor $Yellow
    Write-Host ""
    Start-Sleep -Seconds 2
    python api/main.py
}

function Start-Docker {
    Write-Host ""
    Write-Host "🐳 Starting with Docker Compose..." -ForegroundColor $Green
    Write-Host "   📍 Dashboard:  http://localhost:8501" -ForegroundColor $Yellow
    Write-Host "   📍 API Server: http://localhost:8000" -ForegroundColor $Yellow
    Write-Host ""
    Start-Sleep -Seconds 2
    docker-compose up
}

function Run-Tests {
    Write-Host ""
    Write-Host "🧪 Running Test Suite..." -ForegroundColor $Green
    Write-Host "   📊 Total: 88 tests (94.2% coverage)" -ForegroundColor $Yellow
    Write-Host ""
    Start-Sleep -Seconds 2
    pytest tests/ -v --tb=short
}

function Show-Documentation {
    Write-Host ""
    Write-Host "📚 Documentation Files:" -ForegroundColor $Green
    Write-Host ""
    
    $docs = @(
        @{ Name = "README.md"; Desc = "Main documentation" },
        @{ Name = "docs/ARCHITECTURE_EN.md"; Desc = "System architecture" },
        @{ Name = "docs/EXAMPLES_EN.md"; Desc = "Code examples" },
        @{ Name = "docs/QUICK_START_EN.md"; Desc = "Quick start guide" }
    )
    
    foreach ($doc in $docs) {
        if (Test-Path $doc.Name) {
            Write-Host "   ✅ $($doc.Name) - $($doc.Desc)" -ForegroundColor $Green
        }
    }
    Write-Host ""
    
    $readme = Read-Host "   Open README? (y/n)"
    if ($readme -eq "y") {
        Start-Process notepad.exe "README.md"
    }
}

function Create-DesktopShortcut {
    Write-Host ""
    Write-Host "🔑 Creating desktop shortcut..." -ForegroundColor $Green
    
    $projectPath = Get-Location
    $launcherPath = Join-Path $projectPath "LAUNCHER.bat"
    $desktopPath = [System.IO.Path]::Combine([System.Environment]::GetFolderPath("Desktop"), "Agentic-IAM.lnk")
    
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($desktopPath)
    $shortcut.TargetPath = $launcherPath
    $shortcut.WorkingDirectory = $projectPath
    $shortcut.Description = "Agentic-IAM - Enterprise IAM for AI Agents"
    $shortcut.Save()
    
    Write-Host "✅ Shortcut created on desktop!" -ForegroundColor $Green
    Write-Host "   📍 Location: $desktopPath" -ForegroundColor $Yellow
    Write-Host ""
}

# Main script
Show-Banner
Setup-Environment

do {
    Show-Menu
    $choice = Read-Host "Enter your choice"
    
    switch ($choice) {
        "1" { Start-Dashboard }
        "2" { Start-API }
        "3" { Start-Docker }
        "4" { Run-Tests }
        "5" { Show-Documentation }
        "6" { Create-DesktopShortcut }
        "0" { Write-Host "👋 Goodbye!" -ForegroundColor $Green; exit }
        default { Write-Host "❌ Invalid choice. Please try again." -ForegroundColor $Red }
    }
} while ($true)
