# 🌐 Server Deployment Guide

Complete guide to deploy the AI-Powered Threat Detection System on servers to protect real network infrastructure.

---

## 🎯 Deployment Architectures

### Architecture 1: Single Server Protection (Simple)
```
Internet → [Firewall/Router] → [Server with Threat Detection] → Internal Network
                                    ↓
                                  Suricata monitors traffic
                                    ↓
                                  AI Detection
                                    ↓
                                  Auto-block attacks
```

### Architecture 2: Gateway/Firewall Protection (Recommended)
```
Internet → [Gateway Server with Threat Detection] → Internal Servers
              ↓
            Suricata monitors all traffic
              ↓
            AI Detection blocks threats
              ↓
            Protects entire network
```

### Architecture 3: Distributed Monitoring
```
                    [Central Dashboard Server]
                           ↑ ↑ ↑
                           | | |
    [Server 1] -------- [Detection] -------- [Server 2]
    [Server 3] -------- [Detection] -------- [Server 4]
```

---

## 📋 Prerequisites for Server Deployment

### Hardware Requirements
- **CPU:** 4+ cores (for AI processing)
- **RAM:** 8GB minimum, 16GB recommended
- **Disk:** 100GB+ for logs and databases
- **Network:** 2 NICs recommended (one for monitoring, one for management)

### Software Requirements
- **OS:** Windows Server 2019/2022 or Windows 10/11
- **Network:** Static IP address
- **Access:** Administrator privileges
- **Ports:** 
  - 5000 (Dashboard - can be changed)
  - Management ports for remote access

---

## 🔧 Configuration Changes for Server Deployment

### 1. Network Interface Configuration

Edit `config.yaml`:

```yaml
# Network monitoring settings
network:
  # Interface to monitor (get from: Get-NetAdapter)
  interface: "Ethernet"  # Change to your server's interface name
  
  # Monitor mode: "promiscuous" to see all network traffic
  promiscuous: true
  
  # IP addresses to protect (your servers)
  protected_networks:
    - "192.168.1.0/24"    # Internal network
    - "10.0.0.0/8"        # Private network
    - "YOUR_PUBLIC_IP"    # Server public IP

suricata:
  # Update to monitor correct interface
  eve_json_path: "C:/Program Files/Suricata/log/eve.json"
  
  # Suricata configuration file
  config_path: "C:/Program Files/Suricata/suricata.yaml"

# Dashboard accessible from other machines
dashboard:
  host: "0.0.0.0"  # Listen on all interfaces (was 127.0.0.1)
  port: 5000       # Change if needed
  public_url: "http://YOUR_SERVER_IP:5000"

# Response settings
response:
  # Whitelist trusted IPs (don't block these)
  whitelist:
    - "127.0.0.1"              # Localhost
    - "YOUR_ADMIN_IP"          # Your management IP
    - "192.168.1.1"            # Gateway
    - "10.0.0.0/8"             # Trusted internal network
  
  # Block duration (seconds)
  default_block_ttl: 3600      # 1 hour
  
  # Firewall rule prefix
  firewall_rule_prefix: "ThreatBlock"
  
  # Cleanup interval
  cleanup_interval: 300        # 5 minutes

# Alert notifications for critical events
alerts:
  smtp_enabled: true
  smtp_server: "smtp.gmail.com"  # Your SMTP server
  smtp_port: 587
  smtp_use_tls: true
  smtp_username: "your-email@gmail.com"
  smtp_password: "your-app-password"  # Use environment variable!
  alert_from: "security@yourdomain.com"
  alert_to: ["admin@yourdomain.com", "security-team@yourdomain.com"]
```

---

### 2. Dashboard Configuration for Network Access

Edit `dashboard/config.py`:

```python
class DashboardConfig:
    """Dashboard configuration."""
    
    # Network binding
    HOST = os.getenv('DASHBOARD_HOST', '0.0.0.0')  # Changed from 127.0.0.1
    PORT = int(os.getenv('DASHBOARD_PORT', '5000'))
    
    # Security
    SECRET_KEY = os.getenv('DASHBOARD_SECRET_KEY')
    SESSION_COOKIE_SECURE = True  # Enable in production with HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # CORS for API access (if needed)
    ALLOWED_HOSTS = [
        'localhost',
        '127.0.0.1',
        'YOUR_SERVER_IP',
        'your-domain.com'
    ]
```

---

### 3. Suricata Configuration for Server

Edit `C:\Program Files\Suricata\suricata.yaml`:

```yaml
# Network interface configuration
af-packet:
  - interface: YOUR_INTERFACE_NAME  # Get from: Get-NetAdapter
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes

# Or use pcap (Windows)
pcap:
  - interface: YOUR_INTERFACE_NAME
    
# Promiscuous mode (see all traffic)
promiscuous: yes

# Home network (your protected servers)
vars:
  address-groups:
    HOME_NET: "[192.168.1.0/24,10.0.0.0/8,YOUR_PUBLIC_IP/32]"
    EXTERNAL_NET: "!$HOME_NET"
    
  port-groups:
    HTTP_PORTS: "80"
    HTTPS_PORTS: "443"
    SSH_PORTS: "22"
    RDP_PORTS: "3389"

# Enable flow logging
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - flow:
            enabled: yes
        - alert:
            enabled: yes
            payload: yes
            metadata: yes

# Performance tuning for server
threading:
  set-cpu-affinity: yes
  cpu-affinity:
    - management-cpu-set:
        cpu: [ 0 ]
    - receive-cpu-set:
        cpu: [ 0,1,2,3 ]
    - worker-cpu-set:
        cpu: [ 0,1,2,3 ]
```

---

## 🚀 Deployment Steps

### Step 1: Prepare Server

```powershell
# 1. Install Python 3.10+
# Download from: https://www.python.org/downloads/

# 2. Install Npcap (WinPcap compatible mode)
# Download from: https://npcap.com/

# 3. Install Suricata for Windows
# Download from: https://suricata.io/download/

# 4. Get network interface name
Get-NetAdapter

# Output example:
# Name: Ethernet
# InterfaceDescription: Intel(R) I219-V Gigabit Network Connection
```

---

### Step 2: Configure Network Interface

```powershell
# Find your interface
Get-NetAdapter | Select-Object Name, Status, LinkSpeed

# Get IP configuration
Get-NetIPAddress | Where-Object {$_.AddressFamily -eq "IPv4"}

# Note your:
# - Interface name (e.g., "Ethernet")
# - Server IP address
# - Gateway IP
```

---

### Step 3: Deploy Application

```powershell
# 1. Copy project to server
# Option A: Git clone
git clone https://github.com/nahom1011/ai-threat-detection-response.git
cd ai-threat-detection-response

# Option B: Copy files directly
# Copy d:\aaaaaaaaaaa my\ to C:\ThreatDetection\

# 2. Install dependencies
pip install -r requirements.txt
pip install -r requirements-dashboard.txt

# 3. Configure for your network
# Edit config.yaml with your interface and IPs

# 4. Set environment variables
$env:DASHBOARD_SECRET_KEY = "$(python -c 'import secrets; print(secrets.token_hex(32))')"
$env:DASHBOARD_HOST = "0.0.0.0"
$env:SMTP_PASSWORD = "your-smtp-password"

# 5. Create admin user
python quick_create_user.py
```

---

### Step 4: Configure Firewall

```powershell
# Allow dashboard access from network
New-NetFirewallRule -DisplayName "Threat Detection Dashboard" `
    -Direction Inbound `
    -LocalPort 5000 `
    -Protocol TCP `
    -Action Allow

# Allow from specific IPs only (more secure)
New-NetFirewallRule -DisplayName "Threat Detection Dashboard" `
    -Direction Inbound `
    -LocalPort 5000 `
    -Protocol TCP `
    -Action Allow `
    -RemoteAddress "192.168.1.0/24"
```

---

### Step 5: Install as Windows Service

```powershell
# Run as Administrator
cd C:\ThreatDetection

# Install detection engine as service
.\service\install_service.ps1

# Or manually create scheduled task
schtasks /create /tn "ThreatDetectionEngine" /tr "python C:\ThreatDetection\src\decision_engine.py" /sc onstart /ru SYSTEM /rl HIGHEST

# Start the service
Start-Service "ThreatDetectionEngine"
```

---

### Step 6: Start Dashboard as Service

Create `start_dashboard_service.ps1`:

```powershell
# Dashboard Windows Service installer
$pythonPath = (Get-Command python).Source
$scriptPath = "C:\ThreatDetection\dashboard\app.py"

# Create scheduled task for dashboard
$action = New-ScheduledTaskAction -Execute $pythonPath -Argument "-m dashboard.app" -WorkingDirectory "C:\ThreatDetection"
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

Register-ScheduledTask -TaskName "ThreatDetectionDashboard" -Action $action -Trigger $trigger -Principal $principal -Settings $settings

# Start task
Start-ScheduledTask -TaskName "ThreatDetectionDashboard"
```

---

## 🔒 Security Hardening

### 1. HTTPS/SSL Configuration

```powershell
# Generate self-signed certificate (for testing)
$cert = New-SelfSignedCertificate -DnsName "your-server.local" -CertStoreLocation "cert:\LocalMachine\My"

# For production, use Let's Encrypt or commercial certificate
```

Update `dashboard/app.py`:

```python
if __name__ == '__main__':
    from waitress import serve
    
    # Production with HTTPS
    serve(
        app,
        host='0.0.0.0',
        port=443,
        url_scheme='https',
        # Add SSL certificate paths
        # ssl_cert='path/to/cert.pem',
        # ssl_key='path/to/key.pem'
    )
```

---

### 2. Authentication Hardening

```python
# In dashboard/config.py

class DashboardConfig:
    # Stronger session security
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Strict'
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour
    
    # Rate limiting
    RATELIMIT_ENABLED = True
    RATELIMIT_DEFAULT = "100 per hour"
```

---

### 3. IP Whitelisting

```yaml
# In config.yaml
response:
  whitelist:
    # Add all trusted IPs
    - "127.0.0.1"
    - "YOUR_ADMIN_IP"
    - "192.168.1.0/24"  # Internal network
    - "10.0.0.0/8"       # Corporate network
```

---

## 🌍 Remote Access Setup

### Access Dashboard from Another Computer

1. **Find server IP:**
   ```powershell
   Get-NetIPAddress | Where-Object {$_.AddressFamily -eq "IPv4"}
   ```

2. **On client computer, open browser:**
   ```
   http://SERVER_IP:5000
   ```

3. **For internet access (advanced):**
   - Configure router port forwarding: External Port 80/443 → Server:5000
   - Use reverse proxy (nginx, IIS)
   - Use VPN for secure access

---

### Setting Up Reverse Proxy (IIS)

```powershell
# Install IIS URL Rewrite and Application Request Routing
# Then configure reverse proxy:

# In IIS Manager:
# 1. Create new site
# 2. Bindings: *:80 or *:443
# 3. Add URL Rewrite rule:
#    Pattern: (.*)
#    Rewrite URL: http://localhost:5000/{R:1}
```

---

## 📊 Multi-Server Deployment

### Central Dashboard + Multiple Detection Engines

**Server 1 (Gateway):**
- Runs: Detection Engine + Dashboard
- Monitors: All incoming traffic
- Database: Central database

**Server 2 (Web Server):**
- Runs: Detection Engine only
- Monitors: Local traffic
- Reports to: Central database

**Server 3 (Database Server):**
- Runs: Detection Engine only  
- Monitors: Local traffic
- Reports to: Central database

**Configuration for distributed setup:**

```yaml
# On each detection server
database:
  # Point to central database server
  path: "\\\\CENTRAL_SERVER\\ThreatDetection\\data\\threat_defense.db"
  # Or use network share
  
dashboard:
  # Only on central server
  enabled: true
  host: "0.0.0.0"
```

---

## 🧪 Testing Server Deployment

```powershell
# 1. Verify Suricata is capturing
Get-Content "C:\Program Files\Suricata\log\eve.json" -Tail 10

# 2. Test detection engine
python -m src.decision_engine

# 3. Test dashboard access
# From another computer:
Invoke-WebRequest -Uri "http://SERVER_IP:5000"

# 4. Generate test traffic
# From client computer:
curl http://SERVER_IP
ping SERVER_IP

# 5. Check firewall rules
Get-NetFirewallRule -DisplayName "*ThreatBlock*"
```

---

## 📝 Monitoring and Maintenance

### Daily Checks

```powershell
# Check service status
Get-Service | Where-Object {$_.Name -like "*ThreatDetection*"}

# Check recent blocks
python -c "import sqlite3; conn = sqlite3.connect('data/threat_defense.db'); cursor = conn.cursor(); cursor.execute('SELECT COUNT(*) FROM active_blocks'); print(f'Active blocks: {cursor.fetchone()[0]}')"

# Check disk space
Get-PSDrive C
```

### Weekly Tasks

- Review audit logs
- Update ML model if needed
- Review whitelisted IPs
- Check for false positives
- Backup database

---

## 🔍 Troubleshooting

### Dashboard not accessible from network

```powershell
# 1. Check if listening on 0.0.0.0
netstat -an | findstr :5000

# 2. Check firewall rules
Get-NetFirewallRule -DisplayName "*5000*"

# 3. Test locally first
curl http://localhost:5000

# 4. Check Windows Firewall
# Control Panel → Windows Defender Firewall → Advanced Settings
```

### Suricata not capturing traffic

```powershell
# 1. Verify interface name
Get-NetAdapter

# 2. Check Suricata is running
Get-Process | Where-Object {$_.Name -eq "suricata"}

# 3. Test capture
suricata -c "C:\Program Files\Suricata\suricata.yaml" -i YOUR_INTERFACE_NAME
```

---

## 📚 Additional Resources

- **Suricata Windows Setup:** https://suricata.readthedocs.io/
- **Windows Server Hardening:** https://docs.microsoft.com/security
- **Python Service Deployment:** https://docs.python.org/3/using/windows.html

---

**Your system is now ready for production server deployment!** 🚀🛡️
