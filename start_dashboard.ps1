# Dashboard Startup Script with Diagnostics
# Run this as: .\start_dashboard.ps1

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "AI Threat Detection Dashboard - Startup Script" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Check if we're in the right directory
$currentDir = Get-Location
Write-Host "Current directory: $currentDir" -ForegroundColor Yellow

if (-not (Test-Path "dashboard\app.py")) {
    Write-Host "ERROR: dashboard\app.py not found!" -ForegroundColor Red
    Write-Host "Please run this script from the project root directory" -ForegroundColor Red
    exit 1
}

Write-Host "[OK] Project structure verified" -ForegroundColor Green
Write-Host ""

# Step 2: Check Python
Write-Host "Checking Python installation..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    Write-Host "[OK] $pythonVersion" -ForegroundColor Green
}
catch {
    Write-Host "ERROR: Python not found in PATH" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Step 3: Check required packages
Write-Host "Checking required packages..." -ForegroundColor Yellow
$requiredPackages = @("Flask", "Flask-Login", "Flask-WTF", "waitress")
$missingPackages = @()

foreach ($package in $requiredPackages) {
    $installed = pip show $package 2>&1 | Select-String "Name:"
    if ($installed) {
        Write-Host "[OK] $package installed" -ForegroundColor Green
    }
    else {
        Write-Host "[MISSING] $package" -ForegroundColor Red
        $missingPackages += $package
    }
}

if ($missingPackages.Count -gt 0) {
    Write-Host ""
    Write-Host "Installing missing packages..." -ForegroundColor Yellow
    pip install Flask Flask-Login Flask-WTF waitress
}
Write-Host ""

# Step 4: Check SECRET_KEY
Write-Host "Checking SECRET_KEY..." -ForegroundColor Yellow
if (-not $env:DASHBOARD_SECRET_KEY) {
    Write-Host "[WARNING] DASHBOARD_SECRET_KEY not set" -ForegroundColor Yellow
    Write-Host "Generating and setting a temporary key..." -ForegroundColor Yellow
    $env:DASHBOARD_SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"
    Write-Host "[OK] Temporary secret key set for this session" -ForegroundColor Green
    Write-Host ""
    Write-Host "IMPORTANT: For production, set a permanent key:" -ForegroundColor Red
    Write-Host '  $env:DASHBOARD_SECRET_KEY="your-permanent-key"' -ForegroundColor White
}
else {
    Write-Host "[OK] SECRET_KEY is set" -ForegroundColor Green
}
Write-Host ""

# Step 5: Check if backend database exists
Write-Host "Checking backend database..." -ForegroundColor Yellow
if (Test-Path "data\threat_defense.db") {
    Write-Host "[OK] Backend database found" -ForegroundColor Green
}
else {
    Write-Host "[WARNING] Backend database not found" -ForegroundColor Yellow
    Write-Host "The dashboard will start, but won't show data until:" -ForegroundColor Yellow
    Write-Host "  1. Suricata is running" -ForegroundColor White
    Write-Host "  2. Detection engine is running" -ForegroundColor White
}
Write-Host ""

# Step 6: Check if user account exists
Write-Host "Checking dashboard users..." -ForegroundColor Yellow
if (Test-Path "data\dashboard_auth.db") {
    $userCount = python -c "import sqlite3; conn = sqlite3.connect('data/dashboard_auth.db'); cursor = conn.cursor(); cursor.execute('SELECT COUNT(*) FROM users'); print(cursor.fetchone()[0]); conn.close()" 2>$null
    if ($userCount -gt 0) {
        Write-Host "[OK] $userCount user(s) exist" -ForegroundColor Green
    }
    else {
        Write-Host "[WARNING] No users found" -ForegroundColor Yellow
        Write-Host "Create a user first: python scripts\create_user.py" -ForegroundColor White
    }
}
else {
    Write-Host "[INFO] No users created yet" -ForegroundColor Yellow
    Write-Host "The authentication database will be created automatically." -ForegroundColor White
    Write-Host "Create your first user: python scripts\create_user.py" -ForegroundColor White
}
Write-Host ""

# Step 7: Check if port 5000 is available
Write-Host "Checking if port 5000 is available..." -ForegroundColor Yellow
$portInUse = Get-NetTCPConnection -LocalPort 5000 -ErrorAction SilentlyContinue
if ($portInUse) {
    Write-Host "[WARNING] Port 5000 is already in use" -ForegroundColor Red
    Write-Host "Another application is using port 5000." -ForegroundColor Red
    Write-Host "You can either:" -ForegroundColor Yellow
    Write-Host "  1. Stop the other application" -ForegroundColor White
    Write-Host "  2. Use a different port: `$env:DASHBOARD_PORT=8080" -ForegroundColor White
    Write-Host ""
    $continue = Read-Host "Do you want to continue anyway? (y/n)"
    if ($continue -ne 'y') {
        exit 1
    }
}
else {
    Write-Host "[OK] Port 5000 is available" -ForegroundColor Green
}
Write-Host ""

# Step 8: Start the dashboard
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Starting Dashboard Server..." -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Dashboard will be accessible at: http://127.0.0.1:5000" -ForegroundColor Green
Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Yellow
Write-Host ""

# Run the dashboard
python -m dashboard.app
