# AI Threat Detection Engine Launcher
# Right-click this file -> "Run with PowerShell" (as Administrator)

$projectDir = "D:\aaaaaaaaaaa my"

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "Not running as Administrator. Re-launching elevated..." -ForegroundColor Yellow
    Start-Process powershell -Verb RunAs -ArgumentList "-NoExit -Command `"Set-Location '$projectDir'; python -m src.decision_engine`""
    exit
}

# Already admin - just run it
Set-Location $projectDir
Write-Host "Working directory: $(Get-Location)" -ForegroundColor Cyan
Write-Host "Starting AI Threat Detection Engine..." -ForegroundColor Green
python -m src.decision_engine
