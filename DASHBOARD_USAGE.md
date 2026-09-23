# 🎯 AI-Powered Threat Detection Dashboard - Usage Guide

## 🚀 Quick Start

### Starting the Dashboard

```powershell
cd "d:\aaaaaaaaaaa my"
.\start_dashboard.ps1
```

Or manually:
```powershell
python -m dashboard.app
```

### Access URL
**http://127.0.0.1:5000**

---

## 👤 User Management

### Creating Users

Use the standalone user creation script:

```powershell
python quick_create_user.py
```

**Available Roles:**
- `admin` - Full access including IP unblock functionality
- `analyst` - Read-only monitoring access

### Default Test Users
Create these for testing:
- Username: `admin@dbu.edu.et`, Password: `Admin@2026`, Role: `admin`
- Username: `analyst@dbu.edu.et`, Password: `Analyst@2026`, Role: `analyst`

---

## 📊 Dashboard Features

### 1. 🔴 Live Network Feed (NEW!)

**Real-time Wireshark-style packet view:**
- Updates every 3 seconds automatically
- Shows ALL flows as they occur (benign + malicious)
- Color-coded threat levels:
  - 🟢 **BENIGN** (score < 50%) - Normal traffic
  - 🟡 **SUSPICIOUS** (50-84%) - Monitored traffic
  - 🔴 **MALICIOUS** (≥85%) - Blocked threats

**Controls:**
- ⏸️ **Pause/Resume** - Stop/start live updates
- 🗑️ **Clear** - Clear the feed history
- Auto-scrolls to show newest packets first
- Keeps last 50 flows in memory

**Display Format:**
```
23:45:12  192.168.1.100 → 10.0.0.50:443  TCP  BENIGN 12%
23:45:15  203.0.113.45 → 10.0.0.50:22   TCP  MALICIOUS 94%
```

### 2. 📈 Statistics Cards

Four real-time metric cards:
- **Total Threats Detected** - High-confidence malicious flows (≥85%)
- **Active Blocks** - Currently blocked IPs
- **Critical Alerts** - Urgent threats requiring attention
- **System Status** - Overall health indicator

### 3. 🌐 Network Activity Monitor

**Complete traffic analysis table:**
- Shows ALL analyzed flows (not just threats)
- Columns:
  - Time - When the flow was detected
  - Source IP - Origin of the traffic
  - Destination - Target IP:Port
  - Classification - "Normal Traffic" or attack type
  - Confidence - AI model score (0-100%)
  - Status - Blocked/Logged/Low/Critical
  - Action - Unblock button (admin only)

**Color Coding:**
- 🟢 Green border = Low risk (benign traffic)
- 🟡 Yellow border = Logged (suspicious but not blocked)
- 🔴 Red border = Blocked/Critical (malicious)

### 4. 🚫 Active Blocks

List of currently blocked IPs with:
- IP address
- Block time
- Expiry time
- Reason for block
- Confidence score
- **Unblock** button (admin only)

### 5. 📜 Audit Log

Complete audit trail showing:
- All block/unblock actions
- Actor (who performed the action)
- Timestamps
- Reasons and confidence scores

---

## 🔐 Security Features

### Authentication
- Session-based login with CSRF protection
- Password hashing (PBKDF2-SHA256, 150,000 iterations)
- Secure session cookies (HTTPOnly, Secure in production)

### Authorization (RBAC)
- **Admin Role:**
  - View all data
  - Unblock IPs
  - Full audit trail access
  
- **Analyst Role:**
  - View-only access to all monitoring data
  - Cannot modify blocks or perform actions

### Audit Trail
- Every block/unblock action logged
- Immutable record in SQLite database
- Includes actor, timestamp, reason, IP, score

---

## 🗄️ Database Schema

### Threat Defense DB (`data/threat_defense.db`) - READ ONLY
```sql
-- Flow scores table (AI predictions)
flow_scores (
    id INTEGER PRIMARY KEY,
    timestamp TEXT,
    src_ip TEXT,
    dest_ip TEXT,
    src_port INTEGER,
    dest_port INTEGER,
    proto TEXT,
    score REAL,
    prediction TEXT,
    action_taken TEXT
)

-- Active blocks table
active_blocks (
    ip TEXT PRIMARY KEY,
    blocked_at TEXT,
    expires_at TEXT,
    reason TEXT,
    actor TEXT,
    score REAL
)

-- Audit log table
audit_log (
    id INTEGER PRIMARY KEY,
    timestamp TEXT,
    action TEXT,
    ip TEXT,
    actor TEXT,
    reason TEXT,
    score REAL,
    details TEXT
)
```

### Dashboard Auth DB (`data/dashboard_auth.db`) - Dashboard Only
```sql
-- Users table
users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    password_hash TEXT,
    role TEXT,
    created_at TEXT,
    last_login TEXT
)
```

---

## 🔧 Architecture

### Components
```
dashboard/
├── app.py           - Flask application & routes
├── auth.py          - Authentication & RBAC
├── api.py           - Data access layer (read-only to threat DB)
├── config.py        - Configuration management
├── templates/
│   ├── login.html   - Login page with CSRF
│   └── dashboard.html - Main dashboard UI
└── static/
    ├── dashboard.js  - Frontend logic & live feed
    └── dashboard.css - Responsive styling
```

### Integration with Backend
- **Read-only access** to `data/threat_defense.db`
- **Direct function call** to `src.response.unblock_ip()` for unblocking
- **No modifications** to existing backend code
- Separate auth database for dashboard users

---

## 🐛 Troubleshooting

### Server Won't Start
```powershell
# Check if port 5000 is in use
Get-NetTCPConnection -LocalPort 5000

# Kill the process if needed
Stop-Process -Id <PID> -Force

# Or use a different port
$env:FLASK_RUN_PORT = "5001"
python -m dashboard.app
```

### Can't Create Users
```powershell
# Verify database exists
Test-Path "data\dashboard_auth.db"

# Use the standalone script
python quick_create_user.py
```

### Login Fails with CSRF Error
- The `@csrf.exempt` decorator is on the login route
- Clear browser cookies and try again
- Hard refresh: Ctrl+F5

### Live Feed Not Updating
1. Check that the backend is running and writing to `flow_scores`
2. Verify dashboard can read `data/threat_defense.db`
3. Check browser console (F12) for JavaScript errors
4. Click "Resume" if feed is paused

### Unblock Button Returns 403
- Only users with `admin` role can unblock
- Verify your user role: check `data/dashboard_auth.db` → `users` table
- Re-login after role changes

---

## 🧪 Testing

### Run Tests
```powershell
pytest tests/test_auth_roles.py -v
```

**Test Coverage:**
- Admin can unblock IPs (200 response)
- Analyst cannot unblock IPs (403 forbidden)
- Authentication required for all endpoints
- RBAC enforcement

### Manual Testing Checklist
- [ ] Login with admin credentials
- [ ] Login with analyst credentials
- [ ] View live network feed (updates every 3s)
- [ ] Pause/resume live feed
- [ ] Clear live feed
- [ ] View network activity monitor (all flows)
- [ ] Admin: Unblock an IP
- [ ] Analyst: Try to unblock (should fail with 403)
- [ ] View audit log
- [ ] Logout

---

## 📝 Configuration

### Environment Variables
```powershell
# Required - Session secret key
$env:DASHBOARD_SECRET_KEY = "your-secret-key-here"

# Optional - Custom port
$env:FLASK_RUN_PORT = "5000"

# Optional - Debug mode (development only!)
$env:FLASK_DEBUG = "0"
```

### File Paths (configured in `dashboard/config.py`)
```python
THREAT_DB_PATH = "data/threat_defense.db"      # Backend database (read-only)
AUTH_DB_PATH = "data/dashboard_auth.db"        # Dashboard auth database
RESPONSE_MODULE = "src.response"                # Backend response module
```

---

## 🎓 University Project Notes

**Project Title:** AI-Powered Threat Detection & Response System  
**Institution:** Debre Berhan University, Department of IT  
**Academic Year:** 2026

### Key Features for Presentation
1. ✅ Real-time live network feed (Wireshark-style)
2. ✅ AI-powered threat classification with confidence scores
3. ✅ Role-based access control (Admin/Analyst)
4. ✅ Complete audit trail for compliance
5. ✅ Professional web interface with responsive design
6. ✅ Integration with existing ML backend (non-invasive)
7. ✅ Shows both benign and malicious traffic for analysis

### Demo Script
1. Start the dashboard: `.\start_dashboard.ps1`
2. Login as admin
3. Show live feed updating in real-time
4. Point out benign vs. malicious traffic color coding
5. Navigate to Network Activity Monitor (all flows)
6. Show an active block and demonstrate unblock
7. Review audit log to show traceability
8. Logout and login as analyst (read-only demo)

---

## 📚 Additional Documentation

- **Full Setup:** See `README-dashboard.md`
- **Backend Integration:** See `README.md` (main project)
- **API Reference:** See inline docstrings in `dashboard/api.py`
- **Security:** See `dashboard/auth.py` documentation

---

## 🆘 Support

If you encounter issues:
1. Check the terminal output for error messages
2. Review `DASHBOARD_USAGE.md` (this file)
3. Check browser console (F12) for frontend errors
4. Verify database paths and permissions
5. Ensure backend is running and populating `flow_scores` table

---

**Last Updated:** 2026-09-23  
**Dashboard Version:** 1.0  
**Python Version:** 3.10+  
**Flask Version:** 3.0+
