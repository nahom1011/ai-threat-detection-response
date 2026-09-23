# AI-Powered Threat Detection Dashboard

**Web Interface for Real-Time Network Threat Monitoring**

Debre Berhan University - Department of IT  
Final Year Project - 2024

---

## 📋 Overview

This dashboard provides a professional web interface for monitoring the AI-Powered Threat Detection & Response System. It visualizes real-time threat statistics, recent attacks, and response actions through a dark SOC-style interface.

**Key Features:**
- Real-time threat monitoring with 3-second refresh
- Role-based access control (Administrator & Security Analyst)
- Live statistics and alerts visualization
- Administrator-only IP unblock capability
- Complete audit trail of all actions
- Secure session-based authentication
- CSRF protection on all actions
- Windows-compatible (uses Waitress WSGI server)

---

## 🏗️ Architecture

The dashboard is a **visualization layer** that sits on top of the existing backend:

```
Suricata → Decision Engine → SQLite Database
                                    ↓
                           Dashboard Web Interface
                                    ↓
                              Browser (Users)
```

**Important:** The dashboard does NOT duplicate backend functionality. It:
- ✅ Reads from the existing `threat_defense.db` database
- ✅ Calls the existing `response.unblock_ip()` function
- ✅ Uses the existing audit logging system
- ❌ Does NOT run firewall commands directly
- ❌ Does NOT perform ML predictions
- ❌ Does NOT create a second database

---

## 📦 Requirements

### System Requirements
- Windows 10/11 or Windows Server 2019+
- Python 3.10+
- Existing backend already installed and configured

### Python Packages
See `requirements-dashboard.txt`:
- Flask >= 3.0.0
- Flask-Login >= 0.6.3
- Flask-WTF >= 1.2.1
- Werkzeug >= 3.0.0
- waitress >= 2.1.2

---

## 🚀 Installation

### Step 1: Install Dashboard Dependencies

Open PowerShell **as Administrator** and navigate to the project directory:

```powershell
cd "d:\aaaaaaaaaaa my"
```

Install dashboard requirements:

```powershell
pip install -r requirements-dashboard.txt
```

### Step 2: Set Secret Key

The dashboard requires a secure secret key for session management.

Generate a secure random key:

```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```

Set the environment variable (required):

```powershell
$env:DASHBOARD_SECRET_KEY="YOUR_GENERATED_KEY_HERE"
```

**For persistent configuration**, add to your PowerShell profile or set as a Machine-level environment variable:

```powershell
[Environment]::SetEnvironmentVariable("DASHBOARD_SECRET_KEY", "YOUR_KEY_HERE", "Machine")
```

### Step 3: Create Administrator Account

Create your first dashboard user (Administrator):

```powershell
python scripts\create_user.py
```

Follow the prompts:
- **Username**: Choose a username (min 3 chars)
- **Role**: Select `1` for Administrator
- **Password**: Enter a strong password (min 12 chars, uppercase, lowercase, digit, special char)
- **Confirm**: Re-enter password

Example output:
```
✓ User account created successfully!
  Username: admin
  Role: Administrator
```

### Step 4: Create Security Analyst Account (Optional)

Create a read-only analyst account:

```powershell
python scripts\create_user.py
```

Select **Role: 2** (Security Analyst) this time.

---

## 🎯 Usage

### Starting the System

You need **three terminals** running simultaneously:

#### Terminal 1: Start Suricata

```powershell
# Find your network interface GUID
Get-NetAdapter | Select-Object Name, InterfaceDescription, InterfaceGuid

# Start Suricata (replace {GUID} with your interface GUID)
& "C:\Program Files\Suricata\suricata.exe" `
  -c "C:\Program Files\Suricata\suricata.yaml" `
  -i "\Device\NPF_{YOUR-INTERFACE-GUID}" `
  -l "C:\Suricata\log"
```

#### Terminal 2: Start AI Detection Engine

```powershell
cd "d:\aaaaaaaaaaa my"
python src\decision_engine.py config.yaml
```

Wait for:
```
Starting detection loop... (Press Ctrl+C to stop)
```

#### Terminal 3: Start Dashboard

```powershell
cd "d:\aaaaaaaaaaa my"

# Set secret key if not already set
$env:DASHBOARD_SECRET_KEY="your-secret-key-here"

# Start dashboard
python -m dashboard.app
```

Output:
```
============================================================
AI-Powered Threat Detection & Response System - Dashboard
Debre Berhan University - Department of IT
============================================================
Starting dashboard server on http://127.0.0.1:5000
Press Ctrl+C to stop
============================================================
```

#### Step 4: Open Browser

Navigate to:
```
http://127.0.0.1:5000
```

Login with the credentials you created.

---

## 👥 User Roles

### Administrator
**Permissions:**
- ✅ View dashboard statistics
- ✅ View threat alerts
- ✅ View audit history
- ✅ **Unblock blocked IPs**

**Use Case:** Security team lead who can take response actions

### Security Analyst
**Permissions:**
- ✅ View dashboard statistics
- ✅ View threat alerts
- ✅ View audit history
- ❌ **Cannot unblock IPs**

**Use Case:** Junior security staff who monitor but don't take direct action

---

## 🔒 Security Features

### Authentication
- Secure password hashing (PBKDF2-SHA256)
- Session-based authentication (Flask-Login)
- Automatic session expiry (1 hour)
- Secure cookie settings

### Authorization
- Server-side role checking (not just UI hiding)
- Analysts receive HTTP 403 when calling unblock API
- All sensitive endpoints require login
- Admin-only decorator on unblock endpoint

### CSRF Protection
- All POST requests require CSRF token
- Token automatically included in forms
- JavaScript includes token in fetch requests

### Audit Trail
- Every unblock action logged with actor username
- All login attempts logged
- Failed authorization attempts logged
- Complete audit history visible in dashboard

### Password Policy
Strong passwords required:
- Minimum 12 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- At least one special character

---

## 📊 Dashboard Features

### Statistics Cards
- **Packets Analyzed**: Total flows processed by ML model
- **Active Threats**: Count of high-confidence detections (score ≥ 0.85)
- **Traffic Volume**: Estimated total traffic (derived from flow count)
- **Blocked IPs**: Currently active firewall blocks

### Recent Threats Table
Displays recent network flows with:
- Timestamp
- Source IP address
- Destination IP:Port
- Attack Type (derived from confidence score)
- Confidence percentage
- Status badge (Blocked/Logged/Low)
- **Unblock button** (administrators only)

Status colors:
- 🔴 **Blocked/Critical**: Red (score ≥ 0.85)
- 🟠 **Logged**: Amber (0.50 ≤ score < 0.85)
- 🔵 **Low**: Blue (score < 0.50)

### Response Action History
Complete audit log showing:
- Timestamp
- Action type (BLOCK/UNBLOCK)
- IP address
- Actor (who performed the action)
- Reason

### Real-Time Updates
- Dashboard auto-refreshes every 3 seconds
- No page reload required
- Updates pause when browser tab is hidden (saves resources)
- Connection status indicator shows backend health

---

## 🔧 Configuration

### Environment Variables

**Required:**
```powershell
$env:DASHBOARD_SECRET_KEY="your-secret-key-here"
```

**Optional:**
```powershell
# Override threat database path
$env:THREAT_DB_PATH="D:\custom\path\threat_defense.db"

# Override auth database path
$env:DASHBOARD_AUTH_DB_PATH="D:\custom\path\dashboard_auth.db"

# Change host/port
$env:DASHBOARD_HOST="0.0.0.0"  # Listen on all interfaces
$env:DASHBOARD_PORT="8080"

# Enable debug mode (DO NOT use in production)
$env:DASHBOARD_DEBUG="true"
```

### Database Paths

**Threat Database** (backend):
- Default: `data/threat_defense.db`
- Contains: `flow_scores`, `audit_log`, `active_blocks`
- Managed by: Backend decision engine
- Dashboard: Read-only access

**Auth Database** (dashboard):
- Default: `data/dashboard_auth.db`
- Contains: `users` table
- Managed by: Dashboard authentication module
- Isolated from threat detection database

---

## 🧪 Testing

### Run Test Suite

```powershell
cd "d:\aaaaaaaaaaa my"
pytest tests\test_auth_roles.py -v
```

### Expected Output

```
tests/test_auth_roles.py::TestAdministratorUnblock::test_admin_can_unblock PASSED
tests/test_auth_roles.py::TestAnalystCannotUnblock::test_analyst_unblock_returns_403 PASSED
tests/test_auth_roles.py::TestUnauthenticatedAccess::test_unauthenticated_unblock_returns_401 PASSED
tests/test_auth_roles.py::TestInvalidIPAddress::test_invalid_ip_returns_400 PASSED
tests/test_auth_roles.py::TestPasswordHashing::test_passwords_are_hashed PASSED
tests/test_auth_roles.py::TestRoleChecking::test_admin_role_check PASSED
tests/test_auth_roles.py::TestRoleChecking::test_analyst_role_check PASSED

======================== 7 passed in 0.45s ========================
```

### Key Test Cases

1. ✅ **Administrator can unblock**: Calls `response.unblock_ip()` with correct actor
2. ✅ **Analyst gets 403**: Returns forbidden, does NOT call unblock function
3. ✅ **Unauthenticated blocked**: Returns 401 or redirects to login
4. ✅ **Invalid IP rejected**: Returns 400, does NOT call backend
5. ✅ **Passwords hashed**: Never stored in plaintext
6. ✅ **Roles checked correctly**: Admin and analyst roles distinguished

**Important:** Tests use mocks and do NOT modify real firewall rules.

---

## 🔍 Troubleshooting

### Dashboard Won't Start

**Error: "DASHBOARD_SECRET_KEY environment variable must be set"**

Solution:
```powershell
$env:DASHBOARD_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python -m dashboard.app
```

**Error: "Configuration file not found: config.yaml"**

Solution: Dashboard needs backend configuration. Run from project root:
```powershell
cd "d:\aaaaaaaaaaa my"
python -m dashboard.app
```

### Cannot Login

**"Invalid username or password"**

Check:
1. User account was created: `python scripts\create_user.py`
2. Database exists: `data\dashboard_auth.db`
3. Check logs for authentication errors

### No Statistics Showing

**Dashboard shows zeros for all stats**

Check:
1. Backend decision engine is running
2. Suricata is running and generating flow events
3. Database exists: `data\threat_defense.db`
4. Database has data: `SELECT COUNT(*) FROM flow_scores`

### Connection Status Shows "Unavailable"

**Red indicator: "Connection to detection engine unavailable"**

Possible causes:
1. Backend decision engine not running
2. Database path mismatch (check `THREAT_DB_PATH`)
3. Database locked (backend writing during dashboard read)
4. Database permissions issue

Solution:
```powershell
# Verify backend is running
Get-Process python | Where-Object { $_.MainWindowTitle -like "*decision*" }

# Check database exists and is accessible
Test-Path "data\threat_defense.db"
```

### Unblock Button Not Visible

**Logged in but don't see unblock buttons**

Check:
1. You're logged in as **Administrator** (not Analyst)
2. Threats actually have status "Blocked" (only blocked IPs can be unblocked)
3. Check browser console for JavaScript errors

### Analyst Can Access Admin Features

**Security analyst shouldn't be able to unblock**

This should NEVER happen if implemented correctly. If it does:
1. Check server logs - should show 403 errors
2. Verify role in database: `SELECT username, role FROM users`
3. File a bug report - this is a critical security issue

---

## 📁 Project Structure

```
d:\aaaaaaaaaaa my\
│
├── dashboard/                      # Dashboard application
│   ├── __init__.py
│   ├── app.py                     # Main Flask application
│   ├── auth.py                    # Authentication & user management
│   ├── api.py                     # API endpoints & database queries
│   ├── config.py                  # Dashboard configuration
│   │
│   ├── templates/                 # HTML templates
│   │   ├── login.html             # Login page
│   │   └── dashboard.html         # Main dashboard
│   │
│   └── static/                    # Static assets
│       ├── dashboard.js           # JavaScript for live updates
│       └── dashboard.css          # Dark SOC-style CSS
│
├── scripts/                       # Utility scripts
│   └── create_user.py             # User creation script
│
├── tests/                         # Test suite
│   └── test_auth_roles.py         # Authentication & RBAC tests
│
├── data/                          # Databases (auto-created)
│   ├── threat_defense.db          # Backend database (existing)
│   └── dashboard_auth.db          # Dashboard auth database (new)
│
├── requirements-dashboard.txt     # Dashboard Python dependencies
└── README-dashboard.md            # This file
```

---

## 🎓 University Project Demo

### Demonstration Flow

For your final-year project defense:

1. **Show Architecture Diagram**
   - Explain separation of concerns (backend vs. dashboard)
   - Highlight security measures (RBAC, CSRF, password hashing)

2. **Start All Components**
   - Terminal 1: Suricata
   - Terminal 2: Detection Engine
   - Terminal 3: Dashboard

3. **Login as Security Analyst**
   - Show read-only dashboard
   - View statistics and alerts
   - Point out NO unblock button
   - Attempt to call API directly → Show 403 error

4. **Logout and Login as Administrator**
   - Show unblock button appears
   - Demonstrate unblocking an IP
   - Show action appears in audit history
   - Show backend log confirms the action

5. **Show Real-Time Updates**
   - Point out auto-refresh (no manual reload)
   - Show connection status indicator
   - Open browser developer tools → Show API calls

6. **Explain Security Controls**
   - Password requirements
   - Session management
   - CSRF protection
   - Audit logging
   - Role separation

### Key Points to Emphasize

✅ **Integration, not duplication**: Dashboard uses existing backend  
✅ **Security-first design**: RBAC enforced server-side, not just UI  
✅ **Production-ready**: CSRF protection, password hashing, audit trail  
✅ **Windows-compatible**: Uses Waitress, not Linux-only tools  
✅ **Real-time**: 3-second refresh, no page reloads  

---

## 🔐 Security Considerations

### Passwords
- ✅ Hashed using PBKDF2-SHA256
- ✅ Never stored in plaintext
- ✅ Never logged
- ✅ Strong password policy enforced

### Sessions
- ✅ Secure cookie settings
- ✅ HTTPOnly flag prevents JavaScript access
- ✅ 1-hour expiry
- ✅ Secret key from environment (not hardcoded)

### Authorization
- ✅ Server-side role checking
- ✅ Analysts get 403 on admin endpoints
- ✅ Every action logged with actor

### CSRF
- ✅ All POST requests protected
- ✅ Tokens automatically included
- ✅ Invalid tokens rejected

### Audit Trail
- ✅ Every unblock logged
- ✅ Login attempts logged
- ✅ Failed authorizations logged
- ✅ Actor always recorded

### What Dashboard CANNOT Do
- ❌ Run firewall commands directly
- ❌ Modify ML model
- ❌ Change detection threshold
- ❌ Bypass whitelist
- ❌ Delete audit logs

---

## 📝 API Reference

### Authentication Endpoints

#### POST /login
Login with username and password.

**Request:**
```
Form data:
- username: string
- password: string
```

**Response:**
- Success: Redirect to /dashboard
- Failure: Render login with error message

#### POST /logout
Logout current user.

**Response:**
- Redirect to /login

### Dashboard Endpoints

#### GET /
#### GET /dashboard
Main dashboard page (requires login).

**Response:**
- HTML dashboard template

### API Endpoints (JSON)

#### GET /api/stats
Get dashboard statistics.

**Response:**
```json
{
  "packets_analyzed": 1250,
  "active_threats": 7,
  "traffic_volume": 1875000,
  "blocked_ips": 3
}
```

#### GET /api/alerts
Get recent threat alerts.

**Query Parameters:**
- `limit`: Max alerts to return (default: 50, max: 50)

**Response:**
```json
[
  {
    "timestamp": "2024-01-15T10:30:15.123456",
    "source_ip": "203.0.113.45",
    "destination_ip": "192.168.1.10",
    "destination_port": 80,
    "protocol": "TCP",
    "score": 0.92,
    "status": "Blocked",
    "attack_type": "Network Anomaly",
    "action": "BLOCKED"
  }
]
```

#### GET /api/history
Get audit log history.

**Query Parameters:**
- `limit`: Max records to return (default: 100, max: 100)

**Response:**
```json
[
  {
    "timestamp": "2024-01-15T10:35:20.654321",
    "action": "UNBLOCK",
    "ip": "203.0.113.45",
    "actor": "admin",
    "reason": "Manual unblock",
    "score": null
  }
]
```

#### POST /api/unblock/<ip>
Unblock an IP address (Administrator only).

**Headers:**
- `X-CSRFToken`: CSRF token (required)

**Response (Success):**
```json
{
  "success": true,
  "message": "IP 203.0.113.45 unblocked successfully"
}
```

**Response (Forbidden - Analyst):**
```json
{
  "success": false,
  "message": "Administrator privileges required"
}
```
Status: 403

**Response (Invalid IP):**
```json
{
  "success": false,
  "message": "Invalid IP address format"
}
```
Status: 400

---

## 🆘 Support

For issues specific to the dashboard:

1. Check this README
2. Review dashboard logs (check console output)
3. Check browser developer console for JavaScript errors
4. Verify environment variables are set
5. Contact: Department of IT, Debre Berhan University

For issues with the backend (Suricata, ML model, firewall):
- See main project `README.md`

---

## 📄 License

This dashboard is part of the AI-Powered Threat Detection & Response System final year project at Debre Berhan University, Department of IT.

---

**Last Updated**: January 2024  
**Version**: 1.0.0  
**Author**: Debre Berhan University IT Department
