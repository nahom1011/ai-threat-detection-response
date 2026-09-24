# ✅ Server Deployment Checklist

Quick checklist to deploy the AI Threat Detection System on a server to protect real network traffic.

---

## 🎯 Quick Start (10 Minutes)

### 1. Get Your Server's Network Interface

```powershell
Get-NetAdapter | Select-Object Name, Status, InterfaceDescription, LinkSpeed
```

**Copy the Name** (e.g., "Ethernet", "Wi-Fi", "Ethernet0")

---

### 2. Get Your Server's IP Address

```powershell
Get-NetIPAddress | Where-Object {$_.AddressFamily -eq "IPv4"}
```

**Note down:**
- Your server's IP (e.g., 192.168.1.100)
- Your gateway IP (e.g., 192.168.1.1)

---

### 3. Start Dashboard for Network Access

```powershell
.\start_dashboard_server.ps1
```

**This will:**
- ✅ Listen on ALL network interfaces (0.0.0.0)
- ✅ Show all access URLs
- ✅ Create firewall rule automatically
- ✅ Generate security warnings

**Expected output:**
```
Server Network Configuration:
  Interface: Ethernet
  IP Address: 192.168.1.100

Dashboard Access Information:
  Local Access:
    http://localhost:5000
  
  Network Access (from other computers):
    http://192.168.1.100:5000
```

---

### 4. Test Access from Another Computer

**On another computer on the same network:**

Open browser and go to:
```
http://YOUR_SERVER_IP:5000
```

Example:
```
http://192.168.1.100:5000
```

**You should see the login page!**

---

### 5. Configure Suricata for Your Interface

Edit: `C:\Program Files\Suricata\suricata.yaml`

Find the `pcap` section and update:

```yaml
pcap:
  - interface: YOUR_INTERFACE_NAME  # From step 1
```

Example:
```yaml
pcap:
  - interface: Ethernet
```

---

### 6. Update config.yaml

```yaml
suricata:
  interface: "Ethernet"  # Your interface from step 1

response:
  whitelist:
    - "127.0.0.1"
    - "192.168.1.1"        # Your gateway
    - "YOUR_ADMIN_IP"      # Your management computer

network:
  protected_networks:
    - "192.168.1.0/24"     # Your network range

dashboard:
  host: "0.0.0.0"          # Network access
  public_url: "http://192.168.1.100:5000"  # Your server IP
```

---

### 7. Start Detection Engine

```powershell
# Run as Administrator
python -m src.decision_engine
```

**This monitors real network traffic and blocks threats!**

---

### 8. Verify It's Working

**Check if Suricata is capturing:**
```powershell
Get-Content "C:\Program Files\Suricata\log\eve.json" -Tail 10
```

**Check dashboard shows flows:**
- Open dashboard: http://YOUR_SERVER_IP:5000
- Watch the 🔴 Live Network Feed
- Should show real traffic flowing through your server

---

## 📋 Full Deployment Checklist

### Pre-Deployment

- [ ] Server has static IP address
- [ ] Python 3.10+ installed
- [ ] Npcap installed (WinPcap-compatible mode)
- [ ] Suricata for Windows installed
- [ ] Administrator access available
- [ ] Network interface identified

### Configuration

- [ ] Copied `config.server.yaml` to `config.yaml`
- [ ] Updated interface name in config.yaml
- [ ] Updated protected_networks in config.yaml  
- [ ] Updated whitelist with trusted IPs
- [ ] Set DASHBOARD_SECRET_KEY environment variable
- [ ] Configured Suricata to monitor correct interface

### Security

- [ ] Firewall rule created for dashboard port
- [ ] Strong passwords set for dashboard users
- [ ] Admin IP addresses whitelisted
- [ ] SMTP credentials configured (if using alerts)
- [ ] SSL/HTTPS configured (for production)

### Testing

- [ ] Dashboard accessible from localhost
- [ ] Dashboard accessible from another computer
- [ ] Suricata capturing network traffic
- [ ] Detection engine processing flows
- [ ] Firewall rules being created for threats
- [ ] Audit log recording all actions

### Production

- [ ] Detection engine installed as Windows service
- [ ] Dashboard installed as Windows service
- [ ] Auto-start configured on boot
- [ ] Backup scheduled for database
- [ ] Monitoring/alerting configured
- [ ] Documentation provided to team

---

## 🚀 Common Deployment Scenarios

### Scenario 1: Single Web Server Protection

**Setup:**
- Install on web server
- Monitor Ethernet interface
- Protect against DDoS, port scans, brute force

**Config:**
```yaml
network:
  protected_networks:
    - "YOUR_SERVER_PUBLIC_IP"
  mode: "host"

response:
  whitelist:
    - "YOUR_CDN_IPS"
    - "YOUR_OFFICE_IP"
```

---

### Scenario 2: Gateway/Firewall Server

**Setup:**
- Install on gateway/edge server
- Monitor traffic to/from internet
- Protect entire internal network

**Config:**
```yaml
network:
  protected_networks:
    - "192.168.1.0/24"  # Your internal network
  mode: "gateway"
  promiscuous: true  # See all traffic

response:
  whitelist:
    - "192.168.1.0/24"  # Don't block internal network
```

---

### Scenario 3: Database Server Protection

**Setup:**
- Install on database server
- Monitor connections to database ports
- Block brute force attempts

**Config:**
```yaml
network:
  protected_networks:
    - "YOUR_DB_SERVER_IP"
  mode: "host"

response:
  whitelist:
    - "APP_SERVER_1_IP"
    - "APP_SERVER_2_IP"
  
  # Shorter TTL for DB server
  default_block_ttl: 7200  # 2 hours
```

---

## 🔍 Verification Commands

### Check Dashboard is Listening on Network

```powershell
netstat -an | findstr :5000
```

**Should show:**
```
TCP    0.0.0.0:5000    0.0.0.0:0    LISTENING
```

---

### Check Firewall Rules

```powershell
Get-NetFirewallRule -DisplayName "*ThreatBlock*" | Select-Object DisplayName, Enabled, Direction, Action
```

---

### Check Active Network Connections

```powershell
Get-NetTCPConnection | Where-Object {$_.State -eq "Established"} | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State
```

---

### Monitor Suricata Logs in Real-Time

```powershell
Get-Content "C:\Program Files\Suricata\log\eve.json" -Wait -Tail 10
```

---

### Check Database for Recent Detections

```powershell
python -c "import sqlite3; conn = sqlite3.connect('data/threat_defense.db'); cursor = conn.cursor(); cursor.execute('SELECT timestamp, src_ip, dest_ip, score FROM flow_scores ORDER BY timestamp DESC LIMIT 10'); print('\n'.join(str(row) for row in cursor.fetchall()))"
```

---

## ⚠️ Troubleshooting

### Dashboard Not Accessible from Network

**Problem:** Can't access http://SERVER_IP:5000 from another computer

**Solutions:**
1. Check firewall rule exists:
   ```powershell
   Get-NetFirewallRule -DisplayName "Threat Detection Dashboard"
   ```

2. Test locally first:
   ```powershell
   curl http://localhost:5000
   ```

3. Check if bound to 0.0.0.0:
   ```powershell
   netstat -an | findstr :5000
   ```

4. Verify $env:DASHBOARD_HOST is set to "0.0.0.0"

---

### No Network Traffic Being Detected

**Problem:** Live feed shows "Waiting for network data"

**Solutions:**
1. Check Suricata is running:
   ```powershell
   Get-Process | Where-Object {$_.Name -eq "suricata"}
   ```

2. Verify interface name in config:
   ```powershell
   Get-NetAdapter
   ```

3. Check eve.json is being written:
   ```powershell
   Get-Content "C:\Program Files\Suricata\log\eve.json" -Tail 5
   ```

4. Generate test traffic:
   ```powershell
   # From another computer
   curl http://YOUR_SERVER_IP
   ping YOUR_SERVER_IP
   ```

---

### Firewall Rules Not Created

**Problem:** Threats detected but IPs not blocked

**Solutions:**
1. Run PowerShell as Administrator
2. Check admin rights:
   ```powershell
   ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
   ```

3. Test manual firewall rule:
   ```powershell
   New-NetFirewallRule -DisplayName "Test" -Direction Inbound -RemoteAddress "1.2.3.4" -Action Block
   Remove-NetFirewallRule -DisplayName "Test"
   ```

---

## 📚 Additional Resources

- **Full Deployment Guide:** `DEPLOYMENT_GUIDE.md`
- **Testing Guide:** `TESTING_GUIDE.md`
- **Dashboard Usage:** `DASHBOARD_USAGE.md`
- **Configuration Reference:** `config.server.yaml`

---

## 🎓 For Your University Project

**To demonstrate server deployment:**

1. **Show laptop as "admin station"**
   - Access dashboard from your laptop
   - Show: http://SERVER_IP:5000

2. **Show server protecting network**
   - Generate traffic from multiple sources
   - Show detection in real-time
   - Demonstrate auto-blocking

3. **Show scalability**
   - "Can protect multiple servers"
   - "Can centralize monitoring"
   - "Can handle high traffic"

---

**Your system is ready for server deployment!** 🚀
