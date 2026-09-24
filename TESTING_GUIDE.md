# 🧪 Testing Guide - DDoS Attack Simulation

Complete guide for testing your AI-Powered Threat Detection System with simulated attacks.

---

## 📋 Prerequisites

Before testing, ensure:

✅ **Dashboard is running:** http://127.0.0.1:5000  
✅ **Decision engine is running:** `python -m src.decision_engine`  
✅ **You're logged into dashboard** as admin  
✅ **Dashboard shows in browser** with live feed  

---

## 🎯 Testing Methods

### Method 1: Simple Synthetic Attack (Recommended for Quick Test)

**Best for:** Quick testing, demo purposes, no dataset required

```powershell
# DDoS Attack (30 seconds, 20 flows/sec)
python simulate_attack.py --type ddos --duration 30 --rate 20

# Port Scan (20 seconds)
python simulate_attack.py --type portscan --duration 20

# Brute Force (30 seconds)
python simulate_attack.py --type bruteforce --duration 30
```

**What to expect:**
- Dashboard live feed shows flows in real-time
- High-confidence flows (≥85%) trigger blocks
- Statistics cards update
- IPs appear in Active Blocks section

---

### Method 2: Real DDoS Dataset (Realistic Test)

**Best for:** Realistic testing, final presentation, requires CICIDS2017 data

```powershell
# Medium intensity (20 flows/sec, 60 seconds)
python test_ddos_attack.py --intensity medium --duration 60

# High intensity (50 flows/sec, 30 seconds)
python test_ddos_attack.py --intensity high --duration 30

# Low intensity (5 flows/sec, 120 seconds)
python test_ddos_attack.py --intensity low --duration 120
```

**Attack Intensities:**
- **Low:** 5 flows/sec - Subtle attack
- **Medium:** 20 flows/sec - Moderate attack
- **High:** 50 flows/sec - Aggressive attack

---

## 📊 What to Watch in Dashboard

### 1. 🔴 Live Network Feed (Top Section)

**Before Attack:**
```
10:05:12  10.68.145.29 → 3.85.156.34:443  TCP  BENIGN 0%
10:05:15  10.68.145.29 → 10.68.145.181:53  UDP  BENIGN 0%
```

**During Attack:**
```
10:10:45  203.0.113.45 → 192.168.1.100:80  TCP  MALICIOUS 94%  ← Red!
10:10:46  203.0.113.78 → 192.168.1.100:80  TCP  MALICIOUS 91%  ← Red!
10:10:47  203.0.113.12 → 192.168.1.100:80  TCP  SUSPICIOUS 76%
```

**Expected:** Rapid flow updates, many red MALICIOUS labels

---

### 2. 📈 Statistics Cards

**Before Attack:**
```
Total Threats: 15
Active Blocks: 2
Critical Alerts: 8
```

**During Attack:**
```
Total Threats: 67  ← Increasing!
Active Blocks: 12  ← More IPs blocked!
Critical Alerts: 45 ← Rising!
```

**Expected:** Numbers rapidly increase

---

### 3. 🌐 Network Activity Monitor

**Columns to watch:**
- **Time** - Should show current timestamps
- **Classification** - Changes to "High Confidence Threat"
- **Confidence** - 85%+ scores (red background)
- **Status** - Changes to "Blocked" or "Critical"
- **Action** - Unblock button appears for blocked IPs

**Expected:** Table fills with high-confidence detections

---

### 4. 🚫 Active Blocks Section

**Shows:**
- Blocked IP addresses (e.g., 203.0.113.45)
- Block time
- Expiry time (1 hour default)
- Reason: "ML detection score 0.9456"
- Confidence score

**Expected:** New IPs appear as they get blocked

---

### 5. 📜 Audit Log

**Shows:**
- Action: BLOCK
- IP: 203.0.113.45
- Actor: system
- Timestamp
- Reason: ML detection score

**Expected:** BLOCK entries appear for each malicious IP

---

## 🎬 Step-by-Step Test Procedure

### Full Test (15 minutes)

1. **Preparation (2 min)**
   ```powershell
   # Terminal 1: Start decision engine
   python -m src.decision_engine
   
   # Terminal 2: Start dashboard
   .\start_dashboard.ps1
   
   # Browser: Open http://127.0.0.1:5000
   # Login as admin
   ```

2. **Baseline Check (1 min)**
   - Note current statistics
   - Watch normal traffic in live feed
   - Take screenshot (for comparison)

3. **Run Attack (2 min)**
   ```powershell
   # Terminal 3: Run attack simulator
   python simulate_attack.py --type ddos --duration 120 --rate 20
   ```

4. **Observe Detection (2 min)**
   - Watch live feed turn red
   - See statistics increase
   - Note blocked IPs appearing

5. **Verify Response (2 min)**
   - Check Active Blocks section
   - Verify firewall rules created:
     ```powershell
     # Check Windows Firewall rules
     Get-NetFirewallRule | Where-Object {$_.DisplayName -like "*ThreatBlock*"}
     ```

6. **Test Unblock (2 min)**
   - Click "Unblock" on a blocked IP
   - Verify IP removed from Active Blocks
   - Check audit log for UNBLOCK entry

7. **Review Results (2 min)**
   - Final statistics
   - Audit log review
   - Take final screenshot

8. **Cleanup (2 min)**
   - Stop attack simulator (Ctrl+C)
   - Optional: Unblock all IPs
   - Optional: Clear firewall rules

---

## 🔍 Expected Detection Accuracy

Based on CICIDS2017 training:

| Attack Type | Expected Detection Rate |
|-------------|------------------------|
| DDoS | 95-98% |
| Port Scan | 92-95% |
| Brute Force | 90-94% |
| Benign Traffic | 2-5% false positives |

---

## 🐛 Troubleshooting

### Attack Running But No Detections

**Problem:** Flows injected but not detected

**Solutions:**
1. Check decision engine is running:
   ```powershell
   Get-Process python | Where-Object {$_.CommandLine -like "*decision_engine*"}
   ```

2. Verify eve.json path in config.yaml:
   ```yaml
   suricata:
     eve_json_path: "C:/Program Files/Suricata/log/eve.json"
   ```

3. Check if eve.json is being written:
   ```powershell
   Get-Content "C:\Program Files\Suricata\log\eve.json" -Tail 10
   ```

4. Check decision engine logs:
   ```powershell
   Get-Content logs/decision_engine.log -Tail 50
   ```

---

### High False Positive Rate

**Problem:** Normal traffic being blocked

**Solutions:**
1. Increase confidence threshold in config.yaml:
   ```yaml
   model:
     confidence_threshold: 0.90  # Increase from 0.85
   ```

2. Add IPs to whitelist:
   ```yaml
   response:
     whitelist:
       - "10.68.145.29"  # Your local IP
       - "192.168.1.1"   # Gateway
   ```

3. Retrain model with more diverse data

---

### Dashboard Not Updating

**Problem:** Live feed shows "Waiting for network data"

**Solutions:**
1. Hard refresh browser: `Ctrl+Shift+F5`
2. Check JavaScript console (F12) for errors
3. Verify dashboard can read database:
   ```powershell
   Test-Path "data\threat_defense.db"
   ```
4. Restart dashboard

---

### Firewall Rules Not Created

**Problem:** Detection works but IPs not blocked

**Solutions:**
1. Run PowerShell as **Administrator**:
   ```powershell
   # Right-click PowerShell → Run as Administrator
   python -m src.decision_engine
   ```

2. Check firewall rules:
   ```powershell
   Get-NetFirewallRule -DisplayName "*ThreatBlock*"
   ```

3. Test manual block:
   ```python
   from src.response import ResponseManager
   from src.config import load_config
   
   config = load_config('config.yaml')
   rm = ResponseManager(
       db_path=config.database.path,
       whitelist=config.response.whitelist
   )
   rm.block_ip("1.2.3.4", "test", actor="admin")
   ```

---

## 📸 Screenshots to Capture

For your presentation:

1. **Normal operation** - Benign traffic flowing
2. **Attack in progress** - Live feed showing malicious flows
3. **Statistics during attack** - Rising numbers
4. **Active blocks** - List of blocked IPs
5. **Unblock action** - Admin unblocking an IP
6. **Audit log** - Complete history
7. **Windows Firewall** - Show actual firewall rules

---

## 🎓 Demo Script for Presentation

**5-Minute Live Demo:**

1. **Show dashboard** (30 sec)
   - "This is our real-time monitoring interface"
   - Point out live feed, statistics, activity monitor

2. **Start attack** (15 sec)
   ```powershell
   python simulate_attack.py --type ddos --duration 60
   ```
   - "I'm now simulating a DDoS attack"

3. **Watch detection** (2 min)
   - Point to red flows appearing
   - "AI model detects malicious patterns"
   - Show statistics increasing
   - "System automatically blocks attacker IPs"

4. **Show response** (1 min)
   - Navigate to Active Blocks
   - "These IPs are now blocked by Windows Firewall"
   - Show PowerShell: `Get-NetFirewallRule`

5. **Demonstrate unblock** (1 min)
   - Click unblock button
   - "Admin can manually unblock false positives"
   - Show audit log entry

6. **Wrap up** (30 sec)
   - Final statistics
   - "97% detection accuracy on CICIDS2017 dataset"

---

## 📚 Additional Testing

### Stress Test
```powershell
# Multiple simultaneous attacks
python simulate_attack.py --type ddos --duration 300 --rate 50
```

### Long-Duration Test
```powershell
# 1 hour sustained attack
python test_ddos_attack.py --intensity medium --duration 3600
```

### Mixed Attack Types
```powershell
# Run multiple terminals simultaneously:
# Terminal 1:
python simulate_attack.py --type ddos --duration 60

# Terminal 2 (after 20s):
python simulate_attack.py --type portscan --duration 60

# Terminal 3 (after 40s):
python simulate_attack.py --type bruteforce --duration 60
```

---

**Good luck with your testing and presentation!** 🎓🛡️
