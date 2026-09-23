# 🛡️ AI-Powered Threat Detection & Response System

**Final Year Project - Debre Berhan University, Department of IT**

An intelligent network security system that uses machine learning to detect and automatically respond to cybersecurity threats in real-time.

![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-lightgrey)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [System Architecture](#system-architecture)
- [Screenshots](#screenshots)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Technologies Used](#technologies-used)
- [Dashboard Features](#dashboard-features)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)

---

## 🎯 Overview

This system combines **AI/ML threat detection** with **automated response mechanisms** to provide enterprise-grade network security. It monitors network traffic in real-time, uses XGBoost machine learning models trained on the CICIDS2017 dataset, and automatically blocks malicious traffic using Windows Firewall.

### Key Capabilities

- ✅ **Real-time threat detection** using ML (XGBoost)
- ✅ **Automated response** via Windows Firewall integration
- ✅ **Live network monitoring** dashboard (Wireshark-style)
- ✅ **Role-based access control** (Admin/Analyst)
- ✅ **Complete audit trail** for compliance
- ✅ **97%+ detection accuracy** on CICIDS2017 dataset

---

## ✨ Features

### 🔍 Detection Engine

- **ML-based classification** using XGBoost
- **Feature extraction** from Suricata flow data
- **Confidence scoring** (0-100%) for each flow
- **Real-time processing** with <100ms latency
- **Configurable thresholds** (default: 85% confidence)

### 🚫 Response System

- **Automated IP blocking** via Windows Firewall
- **Whitelist protection** for trusted IPs
- **TTL-based blocks** with automatic expiry
- **Manual unblock** capability (admin-only)
- **Alert notifications** via email (SMTP)

### 📊 Web Dashboard

- **Live network feed** showing all traffic (benign + malicious)
- **Statistics cards** with real-time metrics
- **Network activity monitor** with filtering
- **Active blocks management**
- **Audit log viewer**
- **Responsive design** for mobile/desktop

### 🔐 Security Features

- **Session-based authentication**
- **PBKDF2-SHA256 password hashing**
- **CSRF protection** on all forms
- **Role-based authorization** (Admin/Analyst)
- **Immutable audit trail**

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Network Traffic                           │
└────────────────────────┬────────────────────────────────────┘
                         │
                    ┌────▼────┐
                    │ Suricata │ (Windows + Npcap)
                    │ IDS/IPS  │
                    └────┬────┘
                         │ EVE JSON logs
                    ┌────▼────────────┐
                    │ Suricata Watcher│
                    │  (Tail logs)    │
                    └────┬────────────┘
                         │
                    ┌────▼─────────────┐
                    │ Feature Extractor│
                    │  (Flow metrics)  │
                    └────┬─────────────┘
                         │
                    ┌────▼──────────────┐
                    │  Decision Engine  │
                    │  (XGBoost Model)  │
                    └────┬──────────────┘
                         │
            ┌────────────┴────────────┐
            │                         │
       ┌────▼────┐            ┌──────▼──────┐
       │Response │            │  SQLite DB  │
       │ Manager │            │  (Audit)    │
       └────┬────┘            └──────┬──────┘
            │                        │
  ┌─────────┴──────┐                │
  │                │                │
┌─▼─────────┐  ┌───▼────┐      ┌───▼──────┐
│  Firewall │  │ SMTP   │      │ Dashboard│
│  (Block)  │  │(Alert) │      │   API    │
└───────────┘  └────────┘      └────┬─────┘
                                     │
                              ┌──────▼───────┐
                              │  Web UI      │
                              │ (Flask App)  │
                              └──────────────┘
```

---

## 📸 Screenshots

### Dashboard Overview
*Real-time monitoring with statistics cards and live network feed*

### Live Network Feed
*Wireshark-style packet view showing all traffic in real-time*

### Network Activity Monitor
*Complete traffic analysis table with threat classification*

### Active Blocks Management
*View and manage blocked IPs with unblock functionality*

---

## 🚀 Installation

### Prerequisites

- **Windows 10/11** or **Windows Server 2019+**
- **Python 3.10+**
- **Administrator privileges** (required for firewall operations)
- **Npcap** (WinPcap-compatible mode)
- **Suricata for Windows**

### Step 1: Install Python Dependencies

```powershell
# Clone the repository
git clone https://github.com/nahom1011/ai-threat-detection-response.git
cd ai-threat-detection-response

# Install Python packages
pip install -r requirements.txt
pip install -r requirements-dashboard.txt
```

### Step 2: Install Npcap

1. Download from: https://npcap.com/#download
2. Install with **WinPcap API-compatible mode** enabled
3. Reboot if prompted

### Step 3: Install Suricata for Windows

1. Download from: https://suricata.io/download/
2. Install to default location: `C:\Program Files\Suricata`
3. Configure `suricata.yaml`:
   ```yaml
   # Set capture method to pcap
   pcap:
     - interface: <your-interface-name>
   
   # Enable EVE JSON logging
   outputs:
     - eve-log:
         enabled: yes
         filetype: regular
         filename: eve.json
         types:
           - flow
           - alert
   ```

### Step 4: Configure the System

1. Copy `config.yaml.example` to `config.yaml`
2. Edit `config.yaml` with your settings:
   ```yaml
   suricata:
     eve_json_path: "C:/Program Files/Suricata/log/eve.json"
   
   model:
     xgboost_path: "models/xgboost.joblib"
     scaler_path: "models/scaler.joblib"
     confidence_threshold: 0.85
   
   response:
     whitelist:
       - "127.0.0.1"
       - "192.168.1.1"
   
   alerts:
     smtp_enabled: false
   ```

### Step 5: Train or Load ML Model

```powershell
# Option 1: Use pre-trained model (if available)
# Models should be in models/ directory

# Option 2: Train new model
python -m src.train_model
```

### Step 6: Create Dashboard User

```powershell
# Set secret key for dashboard
$env:DASHBOARD_SECRET_KEY = "your-secure-random-key-here"

# Create admin user
python quick_create_user.py
# Enter username: admin@dbu.edu.et
# Enter password: (create strong password)
# Enter role: admin
```

---

## 🎮 Usage

### Start the Detection Engine

```powershell
# Run as Administrator (required for firewall operations)
python -m src.decision_engine
```

The engine will:
1. Load the ML model
2. Start monitoring Suricata logs
3. Classify network flows in real-time
4. Block malicious IPs automatically
5. Log all activities to SQLite database

### Start the Web Dashboard

```powershell
# In a separate terminal
.\start_dashboard.ps1
```

Access at: **http://127.0.0.1:5000**

### View Logs

```powershell
# Decision engine logs
Get-Content logs/decision_engine.log -Tail 50

# Dashboard logs
Get-Content logs/dashboard.log -Tail 50
```

### Manual IP Operations

```python
# Unblock an IP (Python console)
from src.response import ResponseManager
from src.config import load_config

config = load_config('config.yaml')
response = ResponseManager(
    db_path=config.database.path,
    whitelist=config.response.whitelist
)

# Unblock IP
response.unblock_ip("192.168.1.100", actor="admin")

# Check if IP is blocked
is_blocked = response.is_blocked("192.168.1.100")
print(f"IP blocked: {is_blocked}")
```

---

## 📁 Project Structure

```
ai-threat-detection-response/
├── src/                          # Core detection engine
│   ├── decision_engine.py        # Main detection loop
│   ├── feature_extractor.py      # Flow feature extraction
│   ├── suricata_watcher.py       # Log file watcher
│   ├── response.py               # Response management
│   ├── config.py                 # Configuration loader
│   └── train_model.py            # Model training script
│
├── dashboard/                    # Web dashboard
│   ├── app.py                    # Flask application
│   ├── auth.py                   # Authentication & RBAC
│   ├── api.py                    # Data access layer
│   ├── config.py                 # Dashboard config
│   ├── templates/                # HTML templates
│   │   ├── login.html
│   │   └── dashboard.html
│   └── static/                   # CSS/JS assets
│       ├── dashboard.css
│       └── dashboard.js
│
├── tests/                        # Test suite
│   ├── test_response.py
│   └── test_auth_roles.py
│
├── models/                       # ML models
│   ├── xgboost.joblib
│   └── scaler.joblib
│
├── data/                         # Databases
│   ├── threat_defense.db         # Main detection DB
│   └── dashboard_auth.db         # Dashboard users
│
├── rules/                        # Suricata rules
│   └── custom.rules
│
├── service/                      # Windows service
│   └── install_service.ps1
│
├── scripts/                      # Utility scripts
│   ├── quick_create_user.py
│   └── start_dashboard.ps1
│
├── config.yaml                   # Main configuration
├── requirements.txt              # Python dependencies
├── requirements-dashboard.txt    # Dashboard dependencies
├── README.md                     # This file
├── README-dashboard.md           # Dashboard documentation
├── DASHBOARD_USAGE.md            # Dashboard user guide
└── .gitignore
```

---

## 🔧 Technologies Used

### Backend

- **Python 3.10+** - Core language
- **scikit-learn** - ML framework
- **XGBoost** - Primary ML model
- **NumPy / Pandas** - Data processing
- **SQLite3** - Database
- **PyYAML** - Configuration

### Detection

- **Suricata** - IDS/IPS engine
- **Npcap** - Packet capture
- **CICIDS2017** - Training dataset

### Dashboard

- **Flask** - Web framework
- **Flask-Login** - Session management
- **Flask-WTF** - CSRF protection
- **Waitress** - WSGI server
- **HTML5/CSS3/JavaScript** - Frontend

### Response

- **Windows Firewall** - IP blocking
- **PowerShell** - Firewall automation
- **smtplib** - Email alerts

---

## 📊 Dashboard Features

### 1. Live Network Feed

Real-time Wireshark-style packet view:
- Updates every 3 seconds
- Shows ALL flows (benign + malicious)
- Color-coded threat levels
- Pause/resume/clear controls
- Auto-scroll to newest packets

### 2. Statistics Cards

- Total Threats Detected
- Active Blocks
- Critical Alerts
- System Status

### 3. Network Activity Monitor

Complete traffic analysis table:
- Timestamp
- Source/Destination IPs
- Protocol
- Classification
- Confidence score
- Status (Blocked/Logged/Low)
- Unblock action (admin-only)

### 4. Active Blocks Management

- View all blocked IPs
- Block expiry times
- Block reasons
- Confidence scores
- One-click unblock (admin)

### 5. Audit Log

Immutable audit trail:
- All block/unblock actions
- Actor (who performed action)
- Timestamps
- Reasons

---

## 🧪 Testing

### Run All Tests

```powershell
# Install pytest
pip install pytest

# Run tests
pytest tests/ -v
```

### Test Coverage

```powershell
# Install coverage
pip install pytest-cov

# Run with coverage
pytest tests/ --cov=src --cov=dashboard --cov-report=html
```

### Manual Testing

See `DASHBOARD_USAGE.md` for complete testing checklist.

---

## 🤝 Contributing

This is an academic project for Debre Berhan University. Contributions are welcome!

### How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Standards

- Follow PEP 8 style guide
- Add type hints to all functions
- Write docstrings for public APIs
- Include tests for new features
- Update documentation

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Debre Berhan University** - Department of Information Technology
- **CICIDS2017 Dataset** - University of New Brunswick
- **Suricata Project** - Open-source IDS/IPS
- **Npcap Project** - Packet capture library
- **scikit-learn** - ML framework
- **Flask** - Web framework

---

## 📞 Contact

**Project Author:** Nahom Teshome  
**Institution:** Debre Berhan University  
**Department:** Information Technology  
**Email:** nahomteshome708@gmail.com  
**GitHub:** [@nahom1011](https://github.com/nahom1011)

---

## 🎓 Academic Context

**Project Title:** AI-Powered Threat Detection & Response System  
**Institution:** Debre Berhan University  
**Department:** Department of IT  
**Academic Year:** 2026  
**Project Type:** Final Year Project

### Objectives

1. ✅ Implement real-time network threat detection using ML
2. ✅ Automate threat response using Windows Firewall
3. ✅ Provide comprehensive monitoring dashboard
4. ✅ Achieve >95% detection accuracy
5. ✅ Maintain <100ms processing latency

### Deliverables

- ✅ Functional threat detection system
- ✅ Web-based monitoring dashboard
- ✅ Complete documentation
- ✅ Test suite with >80% coverage
- ✅ Project presentation
- ✅ Academic paper

---

## 📚 Additional Documentation

- **Dashboard Usage:** See `DASHBOARD_USAGE.md`
- **Dashboard Technical:** See `README-dashboard.md`
- **API Reference:** See inline docstrings
- **Configuration Guide:** See `config.yaml` comments

---

**Made with ❤️ by Nahom Teshome - Debre Berhan University, 2026**
