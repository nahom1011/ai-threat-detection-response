#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Start Dashboard for Network/Server Access
    
.DESCRIPTION
    Starts the dashboard accessible from other computers on the network.
    Binds to 0.0.0.0 (all interfaces) instead of just localhost.
    
.PARAMETER Port
    Port to listen on (default: 5000)
    
.EXAMPLE
    .\start_dashboard_server.ps1
    
.EXAMPLE
    .\start_dashboard_server.ps1 -Port 8080
    
.NOTES
    For production deployment, see DEPLOYMENT_GUIDE.md
#>

param(
    [int]$Port = 5000
)

# Color output
function Write-Info { param($msg) Write-Host $msg -ForegroundColor Cyan }
function Write-Success { param($msg) Write-Host $msg -ForegroundColor Green }
function Write-Warning { param($msg) Write-Host $msg -ForegroundColor Yellow }
function Write-Error { param($msg) Write-Host $msg -ForegroundColor Red }

Write-Info ("=" * 70)
Write-Info "AI-Powered Threat Detection Dashboard - SERVER MODE"
Write-Info "Debre Berhan University - Department of IT"
Write-Info ("=" * 70)
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Warning "⚠️  NOT running as Administrator"
    Write-Info "   Firewall configuration may not work properly"
    Write-Info "   For full functionality, run PowerShell as Administrator"
    Write-Host ""
}

# Get server IP addresses
Write-Info "Server Network Configuration:"
Write-Info ("-" * 70)
$ipAddresses = Get-NetIPAddress | Where-Object {$_.AddressFamily -eq "IPv4" -and $_.IPAddress -ne "127.0.0.1"}
foreach ($ip in $ipAddresses) {
    Write-Success "  Interface: $($ip.InterfaceAlias)"
    Write-Success "  IP Address: $($ip.IPAddress)"
    Write-Host ""
}

# Set environment variables for network access
Write-Info "Configuring for network access..."

# Generate secret key if not set
if (-not $env:DASHBOARD_SECRET_KEY) {
    Write-Warning "Generating new secret key..."
    $secretKey = python -c "import secrets; print(secrets.token_hex(32))"
    $env:DASHBOARD_SECRET_KEY = $secretKey
    Write-Success "✓ Secret key generated"
    Write-Host ""
    Write-Warning "⚠️  To persist this key, add to your PowerShell profile:"
    Write-Host "   `$env:DASHBOARD_SECRET_KEY = '$secretKey'" -ForegroundColor Yellow
    Write-Host ""
} else {
    Write-Success "✓ Secret key already set"
}

# Set host to 0.0.0.0 (all interfaces)
$env:DASHBOARD_HOST = "0.0.0.0"
$env:DASHBOARD_PORT = $Port

Write-Success "✓ Dashboard will listen on all network interfaces"
Write-Host ""

# Check firewall rule
Write-Info "Checking Windows Firewall..."
$firewallRule = Get-NetFirewallRule -DisplayName "Threat Detection Dashboard" -ErrorAction SilentlyContinue

if ($firewallRule) {
    Write-Success "✓ Firewall rule already exists"
} else {
    Write-Warning "⚠️  Firewall rule not found"
    
    if ($isAdmin) {
        Write-Info "Creating firewall rule..."
        try {
            New-NetFirewallRule -DisplayName "Threat Detection Dashboard" `
                -Direction Inbound `
                -LocalPort $Port `
                -Protocol TCP `
                -Action Allow `
                -ErrorAction Stop | Out-Null
            Write-Success "✓ Firewall rule created"
        } catch {
            Write-Error "✗ Failed to create firewall rule: $_"
            Write-Info "   You may need to configure firewall manually"
        }
    } else {
        Write-Warning "   Run as Administrator to create firewall rule automatically"
        Write-Info "   Or create manually: Control Panel → Windows Firewall → Advanced Settings"
    }
}

Write-Host ""
Write-Info ("=" * 70)
Write-Info "Dashboard Access Information:"
Write-Info ("=" * 70)

# Show all access URLs
Write-Host ""
Write-Success "Local Access:"
Write-Host "  http://localhost:$Port" -ForegroundColor White
Write-Host ""

Write-Success "Network Access (from other computers):"
foreach ($ip in $ipAddresses) {
    Write-Host "  http://$($ip.IPAddress):$Port" -ForegroundColor White
}

Write-Host ""
Write-Info "=" * 70
Write-Host ""

Write-Warning "⚠️  SECURITY NOTES:"
Write-Info "  1. Dashboard is now accessible from your network"
Write-Info "  2. Make sure to use strong passwords for all users"
Write-Info "  3. For internet access, use HTTPS and reverse proxy"
Write-Info "  4. See DEPLOYMENT_GUIDE.md for production setup"
Write-Host ""

Write-Info "=" * 70
Write-Success "Starting Dashboard Server..."
Write-Info "=" * 70
Write-Info "Press Ctrl+C to stop"
Write-Info "=" * 70
Write-Host ""

# Start the dashboard
python -m dashboard.app
