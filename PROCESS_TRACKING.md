# 🔍 Process Tracking Feature

## Overview

The dashboard now shows **which application/process** is making each network connection, just like `netstat -abno`! This provides critical context for threat analysis.

---

## 📊 What You'll See

### Network Activity Monitor Table
New **"Application"** column showing:
```
chrome.exe (15234)      ← Process name and PID
svchost.exe (892)
firefox.exe (7821)
Unknown                 ← When process can't be determined
```

### Live Network Feed
Processes shown inline:
```
10:35:12  192.168.1.100 → 52.2.211.10:443  TCP  [chrome.exe]  BENIGN 2%
```

---

## 🔧 How It Works

### 1. Process Resolver (`src/process_resolver.py`)
- Runs `netstat -ano` every 30 seconds (cached)
- Maps local IP:Port → Process Name + PID
- Uses PowerShell `Get-Process` to resolve PID → Name
- Thread-safe with caching for performance

### 2. Decision Engine Integration
- Resolves process for each flow before logging
- Passes process info to database

### 3. Database Schema
Added two new columns to `flow_scores` table:
- `process_name TEXT` - Application name (e.g., "chrome.exe")
- `pid TEXT` - Process ID (e.g., "15234")

### 4. Dashboard Display
- API returns process info with each flow
- JavaScript displays in table and live feed
- Styled with blue monospace font

---

## 🎯 Benefits

### Better Threat Context
**Before:**
```
192.168.1.100 → 52.2.211.10:443  MALICIOUS 94%
❓ What application is this?
```

**After:**
```
192.168.1.100 → 52.2.211.10:443  [chrome.exe]  MALICIOUS 94%
✅ Chrome browser - might be legitimate or compromised
```

### Use Cases

1. **Identify Compromised Apps**
   - See if malware is using legitimate processes
   - Example: `svchost.exe` making suspicious connections

2. **Whitelist Trusted Apps**
   - Allow traffic from known good applications
   - Example: Windows Update, antivirus

3. **Incident Response**
   - Quickly identify which process to terminate
   - Track malware process names

4. **Forensics & Auditing**
   - Complete trail: IP + Port + Process + Time
   - Helps in post-incident analysis

---

## 💻 Technical Details

### Process Resolution Flow

```
Network Flow Event
       ↓
Extract: src_ip, src_port, dest_ip, dest_port, proto
       ↓
ProcessResolver.get_process_for_connection()
       ↓
Check cache (30s TTL)
       ↓
If expired: Run netstat -ano
       ↓
Parse netstat output
       ↓
Get-Process -Id <PID>
       ↓
Return: {process: "chrome.exe", pid: "15234"}
       ↓
Store in database
       ↓
Display in dashboard
```

### Cache Strategy
- **TTL**: 30 seconds
- **Reason**: Balance between accuracy and performance
- **Impact**: netstat is expensive, caching reduces overhead

### Limitations

1. **Administrator Privileges**
   - Full process names require admin rights
   - Without admin: shows PID only, resolves name via PowerShell

2. **Short-Lived Connections**
   - Process may exit before netstat runs
   - Shows "Unknown" for very brief connections

3. **Performance**
   - netstat adds ~50-100ms overhead
   - Mitigated by caching

4. **Multiple Processes**
   - If multiple processes use same port, shows first match
   - Rare but possible

---

## 🚀 Usage

### Refresh Dashboard
```powershell
# Hard refresh to see new column
Press Ctrl+Shift+F5 in browser
```

### Existing Data
- Old flows (before migration) show **"Unknown"** for process
- New flows (after backend restart) will show actual process names

### Backend Must Be Running
To populate process information, the backend detection engine must be running:
```powershell
python -m src.decision_engine
```

---

## 🔬 Testing

### Manual Test
1. Start backend: `python -m src.decision_engine`
2. Open browser and visit a website (generates traffic)
3. Check dashboard - should see "chrome.exe" or "firefox.exe"
4. Open Spotify/Discord - should see those process names

### Verify Process Resolution
```powershell
# Check your current connections
netstat -ano

# Find a specific process
Get-Process -Name chrome | Select-Object Id, ProcessName
```

---

## 📁 Files Modified/Added

### New Files
- ✅ `src/process_resolver.py` - Process resolution logic
- ✅ `migrate_add_process_columns.py` - Database migration script
- ✅ `PROCESS_TRACKING.md` - This documentation

### Modified Files
- ✅ `src/decision_engine.py` - Added process resolver, resolve before logging
- ✅ `src/response.py` - Added process_name & pid parameters to log_flow_score()
- ✅ `dashboard/api.py` - Added process columns to SELECT query
- ✅ `dashboard/templates/dashboard.html` - Added "Application" column header
- ✅ `dashboard/static/dashboard.js` - Display process in table & live feed
- ✅ `dashboard/static/dashboard.css` - Styling for app-name class

### Database
- ✅ `data/threat_defense.db` - Added `process_name` and `pid` columns to flow_scores

---

## 🎓 Example Output

### Dashboard Display

**Network Activity Monitor:**
| Time | Source IP | Destination | Application | Classification | Confidence | Status |
|------|-----------|-------------|-------------|----------------|------------|--------|
| 10:35:12 | 192.168.1.100 | 52.2.211.10:443 | **chrome.exe (15234)** | Normal Traffic | 2% | Low |
| 10:35:15 | 192.168.1.100 | 10.0.0.50:53 | **svchost.exe (892)** | Normal Traffic | 0.1% | Low |
| 10:35:18 | 192.168.1.100 | 203.0.113.45:22 | **cmd.exe (7821)** | Suspicious | 94% | Blocked |

**Live Network Feed:**
```
10:35:12  192.168.1.100 → 52.2.211.10:443  TCP  [chrome.exe]  BENIGN 2%
10:35:15  192.168.1.100 → 10.0.0.50:53     UDP  [svchost.exe]  BENIGN 0.1%
10:35:18  192.168.1.100 → 203.0.113.45:22  TCP  [cmd.exe]  MALICIOUS 94%
```

---

## 🔒 Security Implications

### Advantages
- **Better Attribution** - Know which process is responsible
- **Faster Response** - Kill suspicious processes immediately
- **Malware Detection** - Identify unknown/suspicious process names

### Privacy Note
- Process names are logged locally only
- Not sent to external services
- Stored in local SQLite database

---

## 🎉 Summary

You can now see **exactly which application** is behind each network connection in your dashboard, making threat detection and response much more effective!

**Feature Status:** ✅ Complete and Running

**Next Steps:**
1. Refresh your browser (Ctrl+Shift+F5)
2. Check the new "Application" column
3. Generate some traffic to see live process names
4. Enjoy enhanced threat visibility!

---

**Added:** 2026-09-24 10:35  
**Version:** 1.2 (with process tracking)  
**Dashboard:** http://127.0.0.1:5000
