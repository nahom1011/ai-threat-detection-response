# Windows Service Installation Guide

This directory contains scripts to install the AI-Powered Threat Detection system as a Windows Service.

## Quick Start

### Install Service

```powershell
# Run PowerShell as Administrator, then:
cd service
.\install_service.ps1 -Action Install
```

### Start Service

```powershell
.\install_service.ps1 -Action Start
```

### Check Status

```powershell
.\install_service.ps1 -Action Status
```

### Stop Service

```powershell
.\install_service.ps1 -Action Stop
```

### Restart Service

```powershell
.\install_service.ps1 -Action Restart
```

### Uninstall Service

```powershell
.\install_service.ps1 -Action Uninstall
```

## How It Works

The script uses Windows Task Scheduler to run the threat detection engine as a system service with the following configuration:

- **Runs as:** SYSTEM account with highest privileges
- **Starts:** Automatically at system boot
- **Restart policy:** Automatically restarts on failure (up to 3 times, 1-minute intervals)
- **Logging:** All output is logged to `logs/threat_defense.log`

## Custom Configuration

### Custom Python Path

If Python is not in your PATH, specify the full path:

```powershell
.\install_service.ps1 -Action Install -PythonPath "C:\Python310\python.exe"
```

### Custom Project Location

If running from outside the project directory:

```powershell
.\install_service.ps1 -Action Install -ProjectRoot "D:\MyProject"
```

### Custom Service Name

To use a different service name:

```powershell
.\install_service.ps1 -Action Install -ServiceName "MyThreatDefense"
```

## Troubleshooting

### Service won't start

1. Check that you have Administrator privileges
2. Verify Python and dependencies are installed:
   ```powershell
   python --version
   pip list | Select-String "xgboost|scikit-learn|joblib"
   ```
3. Check the log file: `logs/threat_defense.log`
4. Verify Suricata is running and eve.json path is correct in `config.yaml`

### Service starts but doesn't block threats

1. Verify the ML model files exist:
   - `models/xgboost.joblib`
   - `models/scaler.joblib`
2. Check that Suricata is generating flow events in eve.json
3. Review the audit log in the SQLite database: `data/threat_defense.db`

### View scheduled task details

```powershell
Get-ScheduledTask -TaskName "AIThreatDefense" | Format-List *
Get-ScheduledTaskInfo -TaskName "AIThreatDefense"
```

### Manually run for testing

To run the service manually for debugging:

```powershell
cd ..
python src\decision_engine.py config.yaml
```

Press Ctrl+C to stop.

## Service Logs

- **Application logs:** `logs/threat_defense.log` (rotated at 10MB, keeps 5 backups)
- **Audit logs:** `data/threat_defense.db` (SQLite database)
- **Windows Event Log:** Task Scheduler logs (Event Viewer → Task Scheduler)

## Uninstallation

To completely remove the service:

```powershell
# Stop and uninstall service
.\install_service.ps1 -Action Uninstall

# Optionally, remove all firewall rules created by the service
netsh advfirewall firewall delete rule name=all | Select-String "AIThreatDefense"

# Or remove them one by one
Get-NetFirewallRule -DisplayName "AIThreatDefense*" | Remove-NetFirewallRule
```

## Notes

- The service requires **Administrator privileges** to modify Windows Firewall rules
- All blocked IPs are automatically unblocked after their TTL expires (default: 1 hour)
- The service runs with elevated privileges and should be secured appropriately
- Logs are rotated automatically to prevent disk space issues
