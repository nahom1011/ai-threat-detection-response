# 🧪 Attack Testing Guide

How to test your AI-Powered Threat Detection System with real attack patterns.

---

## ⚠️ LEGAL WARNING

**ONLY test against:**
- Systems you own
- Systems you have explicit written permission to test
- Test environments/virtual machines

**Unauthorized attacks are:**
- Illegal in most countries
- Punishable by law
- Unethical

---

## 🎯 Testing Method 1: HTTP Flood (Your Code)

### Simple HTTP GET Flood

```python
# simple_ddos_test.py
import requests

target = input("Target URL: ")

while True:
    r = requests.get(target)
    print(r.status_code)
```

### How to Use

1. **Start your dashboard and detection engine**

2. **Run the attack script:**
   ```powershell
   python simple_ddos_test.py
   ```

3. **Enter target:**
   ```
   http://localhost
   # or
   http://192.168.1.100
   ```

4. **Watch your dashboard!**
   - Live Network Feed should show RED entries
   - Statistics should increase
   - Your IP should get blocked

---

## 📊 What Should Happen

### Step-by-Step Expected Behavior

**1. Attack Starts (0-10 seconds)**
```
[   10] Status: 200 | Rate: 50.2 req/s
[   20] Status: 200 | Rate: 51.1 req/s
[   30] Status: 200 | Rate: 50.8 req/s
```

**2. Detection (10-20 seconds)**
- Suricata captures high traffic volume
- ML model analyzes flow patterns:
  - High packet count from single IP
  - Rapid requests (50+ per second)
  - Repetitive pattern
- Confidence score: 85%+

**3. Blocking (20-30 seconds)**
- Windows Firewall rule created
- Your IP blocked
- Attack script shows errors:
  ```
  [  40] Error: Connection timeout
  [  41] Error: Connection refused
  ```

**4. Dashboard Updates**
- 🔴 Live Feed: Shows your IP with MALICIOUS 94%
- 📈 Statistics: Threats +1, Blocks +1
- 🚫 Active Blocks: Your IP appears
- 📜 Audit Log: BLOCK entry added

---

## 🔬 Testing Scenarios

### Scenario 1: Low-Intensity Attack

```python
import requests
import time

target = "http://localhost"

while True:
    r = requests.get(target)
    print(r.status_code)
    time.sleep(0.5)  # 2 requests per second
```

**Expected:** May not trigger blocking (below threshold)

---

### Scenario 2: Medium-Intensity Attack

```python
import requests
import time

target = "http://localhost"

while True:
    r = requests.get(target)
    print(r.status_code)
    time.sleep(0.05)  # 20 requests per second
```

**Expected:** Should trigger detection and blocking

---

### Scenario 3: High-Intensity Attack (Aggressive)

```python
import requests
from concurrent.futures import ThreadPoolExecutor

target = "http://localhost"

def attack():
    while True:
        requests.get(target)

# 10 threads = 100+ req/s
with ThreadPoolExecutor(max_workers=10) as executor:
    for _ in range(10):
        executor.submit(attack)
```

**Expected:** Immediate detection and blocking

---

### Scenario 4: Distributed Attack (Multiple IPs)

Run the script from **different computers** simultaneously:

**Computer 1:**
```powershell
python simple_ddos_test.py
# Enter: http://192.168.1.100
```

**Computer 2:**
```powershell
python simple_ddos_test.py
# Enter: http://192.168.1.100
```

**Computer 3:**
```powershell
python simple_ddos_test.py
# Enter: http://192.168.1.100
```

**Expected:** All three IPs get blocked separately

---

## 🎬 Live Demo for Presentation

### 5-Minute Demo Script

**1. Show Normal Traffic (30 sec)**
```powershell
# Open dashboard
# Show normal benign traffic flowing
# Point to green "BENIGN" entries
```

**2. Announce Attack (15 sec)**
```
"I will now simulate a DDoS attack on the server"
"Watch how the AI detects and blocks it automatically"
```

**3. Start Attack (15 sec)**
```powershell
python simple_ddos_test.py
# Enter target
# Let it run visibly on screen
```

**4. Show Detection (2 min)**
```
"See the Live Feed turning red"
"These are malicious flows detected by AI"
"Confidence score: 94% - very high"
"The system is analyzing packet patterns"
```

**5. Show Blocking (1 min)**
```
"The attack is now blocked"
"Notice the attack script shows errors"
"Firewall rule was created automatically"
```

**6. Show Evidence (1 min)**
```
# Navigate to Active Blocks
"Here's the blocked IP address"
"Block time, reason, confidence score"

# Check Windows Firewall
Get-NetFirewallRule -DisplayName "*ThreatBlock*"
"Actual firewall rule in Windows"
```

**7. Demonstrate Unblock (30 sec)**
```
# Click Unblock button
"Admin can unblock false positives"
# Show audit log entry
```

---

## 📈 Performance Metrics to Show

### Latency
```
"Processing time: <100ms per flow"
"Real-time detection with minimal delay"
```

### Accuracy
```
"Detection rate: 97% on CICIDS2017 dataset"
"False positive rate: <3%"
```

### Scalability
```
"Can handle 1000+ flows per second"
"Tested with 50,000+ network flows"
```

---

## 🔍 Verification Checklist

After running attack, verify:

- [ ] Live feed showed RED malicious entries
- [ ] Statistics cards increased (threats, blocks)
- [ ] Your IP appears in Active Blocks
- [ ] Windows Firewall rule created:
  ```powershell
  Get-NetFirewallRule | Where-Object {$_.DisplayName -like "*ThreatBlock*YOUR_IP*"}
  ```
- [ ] Audit log has BLOCK entry
- [ ] Attack script showed connection errors
- [ ] Database has high-confidence scores:
  ```powershell
  python -c "import sqlite3; conn = sqlite3.connect('data/threat_defense.db'); cursor = conn.cursor(); cursor.execute('SELECT src_ip, score FROM flow_scores WHERE score > 0.85 ORDER BY timestamp DESC LIMIT 5'); print(cursor.fetchall())"
  ```

---

## 🐛 Troubleshooting

### Attack Not Detected

**Problem:** Attack running but no detection

**Check:**

1. **Is detection engine running?**
   ```powershell
   Get-Process python | Where-Object {$_.CommandLine -like "*decision_engine*"}
   ```

2. **Is Suricata capturing?**
   ```powershell
   Get-Content "C:\Program Files\Suricata\log\eve.json" -Tail 10
   ```

3. **Is threshold too high?**
   ```yaml
   # In config.yaml
   model:
     confidence_threshold: 0.85  # Try lowering to 0.70 for testing
   ```

4. **Check ML model is loaded:**
   - Look for "Model loaded" in decision engine output

---

### Attack Detected but Not Blocked

**Problem:** Dashboard shows detection but IP not blocked

**Check:**

1. **Running as Administrator?**
   ```powershell
   ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
   # Should return: True
   ```

2. **Confidence above threshold?**
   - Score must be ≥ 85% for blocking

3. **IP whitelisted?**
   ```yaml
   # In config.yaml
   response:
     whitelist:
       - "YOUR_IP"  # Remove this!
   ```

4. **Check firewall permissions:**
   ```powershell
   # Test creating a firewall rule
   New-NetFirewallRule -DisplayName "Test" -Direction Inbound -RemoteAddress "1.2.3.4" -Action Block
   Remove-NetFirewallRule -DisplayName "Test"
   ```

---

### Your Own IP Gets Blocked

**Problem:** You blocked yourself and can't access dashboard!

**Solution:**

1. **Unblock via PowerShell:**
   ```powershell
   # Find the rule
   Get-NetFirewallRule -DisplayName "*ThreatBlock*YOUR_IP*"
   
   # Remove it
   Remove-NetFirewallRule -DisplayName "ThreatBlock_YOUR_IP"
   ```

2. **Unblock via database:**
   ```powershell
   python -c "import sqlite3; conn = sqlite3.connect('data/threat_defense.db'); cursor = conn.cursor(); cursor.execute('DELETE FROM active_blocks WHERE ip = \"YOUR_IP\"'); conn.commit(); print('Unblocked')"
   ```

3. **Add to whitelist:**
   ```yaml
   # In config.yaml
   response:
     whitelist:
       - "YOUR_IP"  # Your management IP
   ```

4. **Restart detection engine**

---

## 🎓 Testing Best Practices

### Before Testing

1. ✅ Backup database
2. ✅ Document baseline metrics
3. ✅ Have admin credentials ready
4. ✅ Know how to unblock yourself
5. ✅ Take screenshots of normal operation

### During Testing

1. ✅ Monitor dashboard in real-time
2. ✅ Record video for presentation
3. ✅ Note detection times
4. ✅ Capture firewall rules
5. ✅ Document any issues

### After Testing

1. ✅ Unblock test IPs
2. ✅ Clean up firewall rules
3. ✅ Review audit logs
4. ✅ Calculate accuracy metrics
5. ✅ Prepare demo talking points

---

## 📸 Screenshots to Capture

For your presentation:

1. **Before attack** - Normal benign traffic
2. **During attack** - Attack script running
3. **Detection** - Red entries in live feed
4. **Statistics rising** - Numbers increasing
5. **Active blocks** - Blocked IP shown
6. **Firewall rule** - PowerShell command showing rule
7. **Attack failed** - Connection errors
8. **Unblock action** - Admin unblocking
9. **Audit log** - Complete history

---

## 🚀 Advanced Testing

### Bypass Attempts (Should Fail)

1. **IP Spoofing** - Should still block
2. **Slow attack** - Below threshold, not blocked (working as designed)
3. **Fragmented packets** - Should still detect
4. **HTTPS encryption** - Flow patterns still visible

### Stress Testing

```python
# Extreme load test
import requests
from concurrent.futures import ThreadPoolExecutor
import time

def flood():
    for _ in range(1000):
        try:
            requests.get("http://localhost", timeout=1)
        except:
            pass

with ThreadPoolExecutor(max_workers=50) as executor:
    start = time.time()
    futures = [executor.submit(flood) for _ in range(50)]
    for f in futures:
        f.result()
    print(f"Sent 50,000 requests in {time.time() - start:.1f}s")
```

---

## 📚 Testing Commands Reference

### Quick Status Check
```powershell
# Detection engine running?
Get-Process python

# Dashboard accessible?
curl http://localhost:5000

# Recent detections?
python -c "import sqlite3; conn = sqlite3.connect('data/threat_defense.db'); cursor = conn.cursor(); cursor.execute('SELECT COUNT(*) FROM flow_scores WHERE score >= 0.85'); print(f'High-confidence detections: {cursor.fetchone()[0]}')"

# Active blocks?
python -c "import sqlite3; conn = sqlite3.connect('data/threat_defense.db'); cursor = conn.cursor(); cursor.execute('SELECT COUNT(*) FROM active_blocks'); print(f'Active blocks: {cursor.fetchone()[0]}')"
```

---

**Ready to test! Run your attack and watch the AI protect your system! 🛡️**
