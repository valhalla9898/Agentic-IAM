param(
    [string]$message = "",
    [switch]$Push
)

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Error "git not found in PATH. Install Git and retry."
    exit 1
}

if (-not $message) {
    $message = Read-Host "Commit message"
}

Write-Host "Staging changes..."
git add .

Write-Host "Committing with message: $message"
git commit -m "$message"

if ($Push) {
    Write-Host "Pushing to origin/main..."
    git push origin main
} else {
    $doPush = Read-Host "Do you want to push to origin/main now? (y/N)"
    if ($doPush -match '^[yY]') {
        git push origin main
    } else {
        Write-Host "Skipped push. Run 'git push origin main' when ready."
    }
}
