# AI-Powered Threat Detection & Response System
**Internal Engineering Wiki & Technical Reference**

## Table of Contents
1. [System Overview](#1-system-overview)
2. [Suricata](#2-suricata)
3. [Feature Extraction](#3-feature-extraction)
4. [The Machine Learning Pipeline](#4-the-machine-learning-pipeline)
5. [The Response Module](#5-the-response-module)
6. [The Database](#6-the-database)
7. [The Dashboard](#7-the-dashboard)
8. [Deployment & Operations](#8-deployment--operations)
9. [Known Limitations & Troubleshooting Log](#9-known-limitations--troubleshooting-log)

---

## 1. SYSTEM OVERVIEW

The system passively sniffs raw network packets from the host machine's network interface using Suricata. Instead of dropping malicious traffic inline, Suricata just parses these packets into structured "flow" events, writing them out to a JSON file (`eve.json`). A custom Python background service (the Decision Engine) continually tails this JSON file in real-time. For each network flow, it extracts seven specific statistical features (like flow duration, bytes per second, etc.) and scales them. These features are fed into a Machine Learning model (Random Forest primary, XGBoost for comparison) trained on the CICIDS2017 dataset, which predicts whether the flow is benign or malicious. If the flow's malicious probability score exceeds a defined confidence threshold (e.g., 85%), the Response Module activates. It logs the event to a local SQLite database, dispatches an email alert, and automatically creates a Windows Defender Firewall rule to block the offending IP address. Everything—from network statistics to active blocks—can be managed via a Flask web dashboard featuring Role-Based Access Control (RBAC) and an integrated AI assistant.

---

## 2. SURICATA

**What it is and why IDS mode?**
Suricata is a high-performance Network Security Monitoring (NSM) engine. We run it exclusively in **IDS (Intrusion Detection System)** mode rather than IPS (Intrusion Prevention System) mode. In IPS mode, Suricata sits directly inline with the traffic (using tools like NFQ) and has the power to drop packets itself. However, that requires complex routing and can cause major network bottlenecks. By running in IDS mode, Suricata just sniffs copies of the packets via promiscuous mode (using the NPF/Npcap driver on Windows), leaving the actual blocking to our Python Response Module via Windows Firewall. It's safer and less intrusive.

**Config File (`suricata.yaml`)**
The configuration file dictates what Suricata listens to and how it logs data. 
Key parts of my config:
```yaml
# We tell Suricata to output to EVE JSON format (crucial for our Python engine)
outputs:
  - eve-log:
      enabled: yes
      filetype: regular # Output to a regular file
      filename: C:\Suricata\log\eve.json
      types:
        - flow # We ONLY care about flow events, not individual packet alerts

# Windows-specific capture settings
af-packet: # Not used on Windows
pcap:
  - interface: "Ethernet" # Or the UUID of the Npcap adapter
    promisc: yes
```

**Understanding `eve.json`**
When a network connection ends, Suricata dumps a JSON object. Here’s a walkthrough:
```json
{
  "timestamp": "2026-09-24T10:05:12.123456+0300", 
  "event_type": "flow", // Identifies this as a summary of a connection
  "src_ip": "192.168.1.100", // The attacker's IP
  "src_port": 54321,
  "dest_ip": "10.0.0.50", // Our server
  "dest_port": 443,
  "proto": "TCP",
  "flow": {
    "pkts_toserver": 1500, // Total packets sent by attacker
    "pkts_toclient": 12,   // Total packets we replied with
    "bytes_toserver": 1200000,
    "bytes_toclient": 5000,
    "start": "2026-09-24T10:05:10.000000+0300",
    "end": "2026-09-24T10:05:12.000000+0300",
    "age": 2 // Duration in seconds
  }
}
```

**Managing the Service**
- Start: `net start suricata` (from Admin PowerShell) or just running `suricata.exe -c suricata.yaml -i "Ethernet"`
- Stop: `net stop suricata`

**The Sept 2026 Startup Error**
*Issue:* Suricata was failing to start with a fatal error regarding device capture (often `WSAStartup error` or `Unable to find NPF device`). 
*Root Cause:* Windows relies on the Npcap (NPF) service for packet capture. A Windows update or a reboot caused the `npcap` service to not start automatically, meaning Suricata couldn't bind to the interface. Also, on Windows, specifying the friendly name (like "Ethernet") sometimes fails; it requires the UUID of the adapter.
*Fix:* 
1. Run `net start npcap` in an elevated prompt.
2. Use `Get-NetAdapter` to find the correct interface, and run `suricata.exe --list-interfaces` to get the UUID string, then update `suricata.yaml` to use that UUID.

---

## 3. FEATURE EXTRACTION

The Machine Learning model expects numeric features matching the exact CICIDS2017 schema, but `eve.json` provides raw packet/byte counts. The `FeatureExtractor` (`src/feature_extractor.py`) bridges this gap.

It extracts the 7 required features:
1. `Flow Duration`: Calculated as `end - start` timestamp, or using the `age` field.
2. `Total Fwd Packets`: Mapped to `pkts_toserver`.
3. `Total Backward Packets`: Mapped to `pkts_toclient`.
4. `Total Length of Fwd Packets`: Mapped to `bytes_toserver`.
5. `Total Length of Bwd Packets`: Mapped to `bytes_toclient`.
6. `Flow Bytes/s`: `(bytes_toserver + bytes_toclient) / duration`.
7. `Flow Packets/s`: `(pkts_toserver + pkts_toclient) / duration`.

*Code Snippet:*
```python
# Calculating derived features from the raw Suricata flow dictionary
fwd_bytes = float(flow.get("bytes_toserver", 0))
bwd_bytes = float(flow.get("bytes_toclient", 0))
duration = float(flow.get("age", 0.001)) # Avoid division by zero

total_bytes = fwd_bytes + bwd_bytes
bytes_per_s = total_bytes / duration

features = FlowFeatures(
    flow_duration=duration,
    total_fwd_packets=int(flow.get("pkts_toserver", 0)),
    # ...
    flow_bytes_per_s=bytes_per_s,
    # ...
)
```

---

## 4. THE MACHINE LEARNING PIPELINE

**Data Preprocessing**
I loaded the CICIDS2017 Monday (benign), Tuesday (brute-force), and Wednesday (DoS) CSVs. 
- *Cleaning:* Stripped whitespace from headers. Replaced `Infinity` and `-Infinity` (caused by zero-duration flows in the dataset) with `NaN`, and subsequently dropped all `NaN` rows. 
- *Binarization:* Labels were mapped to a simple binary target: `0` for BENIGN, `1` for anything else.

**Feature Scaling (`StandardScaler`)**
I used `sklearn.preprocessing.StandardScaler`. Why? Some features, like `Flow Duration`, are massive numbers (millions of microseconds), while `Total Fwd Packets` might be just `3`. Without scaling, a model might assume the feature with the largest raw number is the most important. The scaler standardizes all features to have a mean of 0 and standard deviation of 1.

**Why Random Forest (Primary)**
Random Forest was chosen as the deployed model because it handles non-linear data exceptionally well, is highly resistant to overfitting, and requires very little hyperparameter tuning to achieve >95% accuracy on tabular network data. It operates by building hundreds of decision trees and taking a majority vote. 

**Why XGBoost (Comparison)**
XGBoost (`train_model.py`) was trained to compare gradient boosting against bagging (Random Forest). XGBoost builds trees sequentially to correct the errors of previous trees. While it can sometimes squeeze out 1-2% higher accuracy, it is more sensitive to outliers and requires much more careful tuning (learning rate, depth) than Random Forest.

**Metrics Explained for an IDS**
- *Accuracy:* Overall correctness. (Warning: high accuracy is easy to achieve if 99% of traffic is benign).
- *Precision:* When the model says "This is an attack!", how often is it right? Critical for avoiding false positives (blocking legitimate users).
- *Recall:* Out of all actual attacks, how many did the model catch? Critical for not missing threats.
- *Confidence Score:* `model.predict_proba()` returns a percentage (e.g., 92%). If a flow looks somewhat weird, it might score 60%. We only block if it crosses our strict 85% threshold.

**The Real Confusion Matrix**
For the CICIDS2017 subset:
```text
[[ 150234     142 ]   <-- True Negatives (150,234 Benign), False Positives (142 blocked by accident)
 [    512   42105 ]]  <-- False Negatives (512 threats missed), True Positives (42,105 attacks blocked)
```
- **False Positives (142):** The model mistakenly blocked legitimate traffic. This usually happens when a user streams a heavy video or runs a large download that mimics the packet-per-second rate of a slow DoS.
- **False Negatives (512):** The model missed real attacks. Usually, these are "low and slow" brute-force attempts that blend in perfectly with normal traffic.

**Retraining**
To retrain, replace the `.csv` files in `MachineLearningCVE/`, run `python train_model.py`. This drops the new `model.joblib` and `scaler.joblib` into the `models/` directory, which the Decision Engine picks up on its next restart.

---

## 5. THE RESPONSE MODULE

When a flow scores above the `confidence_threshold` (e.g., 0.85):

1. **Whitelist Check:** The system checks `config.yaml` to ensure the IP isn't our own gateway or admin machine.
2. **Firewall Blocking:** We bypass complex Python firewall libraries and drop straight down to the OS level using `netsh` via `subprocess.run()`. It executes:
   ```powershell
   netsh advfirewall firewall add rule name="AIThreatDefense_Block_192_168_1_50_IN" dir=in action=block remoteip=192.168.1.50 enable=yes
   ```
3. **Alerting:** If SMTP is enabled, an email payload is constructed using `email.mime.text` and dispatched via `smtplib.SMTP`, containing the score, IP, and flow statistics.
4. **Database Logging:** The block is recorded in the `active_blocks` table with an expiration time (`ttl`, default 3600s). A background thread loops every 5 minutes to automatically run `netsh ... delete rule` for expired blocks.

---

## 6. THE DATABASE

Stored in `data/threat_defense.db` using SQLite.

**Schema:**
- `audit_log`: Every major action. 
  *(Columns: id, timestamp, action, ip, actor, reason, score, details)*
- `active_blocks`: Used by the cleanup thread to track TTLs.
  *(Columns: ip, blocked_at, expires_at, reason, actor, score)*
- `flow_scores`: The most critical table for analysis. Every scored flow is recorded here.
  *(Columns: id, timestamp, src_ip, dest_ip, src_port, dest_port, proto, score, prediction, action_taken, process_name, pid)*

**Example Row (`flow_scores`):**
| id | timestamp | src_ip | dest_ip | dest_port | score | prediction | action_taken | process_name |
|----|-----------|--------|---------|-----------|-------|------------|--------------|--------------|
| 1 | 2026-09-24T10:05:12 | 192.168.1.55 | 10.0.0.50 | 443 | 0.941 | MALICIOUS | BLOCKED | python.exe |
| 2 | 2026-09-24T10:05:15 | 192.168.1.10 | 10.0.0.50 | 80 | 0.021 | BENIGN | NONE | chrome.exe |

---

## 7. THE DASHBOARD

The UI is a Flask web app (`dashboard/app.py`) served by Waitress (since Flask's built-in server isn't meant for production on Windows). 

**Route Structure:**
- `/login`, `/logout`: Session management.
- `/dashboard`: Renders `dashboard.html` with Jinja2.
- `/api/stats`, `/api/alerts`, `/api/history`: Read-only endpoints polled by the frontend JavaScript to update charts dynamically.
- `/api/unblock/<ip>`: Calls `netsh` to delete a firewall rule.
- `/api/ai-chat`: Connects to Groq for ultra-fast LLM inference (Qwen/Llama 3), feeding it context from the database to answer security queries.

**RBAC (Role-Based Access Control):**
Managed in `auth.py`. 
- `Analyst` (`analyst@dbu.edu.et`): Can view the dashboard, chat with AI, and see stats.
- `Administrator` (`admin@dbu.edu.et`): Has the `@admin_required` decorator access. Only admins can trigger the `/api/unblock` endpoint.

---

## 8. DEPLOYMENT & OPERATIONS

**Cold Boot Sequence (Current Windows Machine):**
1. Run PowerShell as Administrator.
2. Start Suricata: `net start suricata`
3. Run the ML decision engine: `python src/decision_engine.py` (Must be running as Admin to edit firewall).
4. Run the Flask dashboard: `python dashboard/app.py`
*(Note: I have wrapper scripts `run_engine.ps1` and `start_dashboard_server.ps1` for convenience).*

**Migration to Dedicated Windows Server:**
1. **Network Promiscuity:** Ensure the hypervisor (Hyper-V / VMware) allows promiscuous mode on the vSwitch, otherwise Suricata will only see broadcast traffic and traffic directed at the server itself.
2. **Service Installation:** Wrap the Python scripts into Windows Services using NSSM (Non-Sucking Service Manager) so they auto-start on boot.
3. **Database Concurrency:** If scaling, SQLite might lock up under heavy dashboard loads. Consider moving to PostgreSQL if traffic exceeds a few hundred flows per second.

---

## 9. KNOWN LIMITATIONS & TROUBLESHOOTING LOG

**Limitation: Model Drift**
The ML model was trained on CICIDS2017. As attack signatures evolve, the model will slowly lose accuracy (concept drift) and require retraining on modern datasets (e.g., CICIDS2019 or CSE-CIC-IDS2018).

**Limitation: SQLite Write Locks**
When a heavy DDoS hits, the Decision Engine attempts to log thousands of rows per second to `flow_scores`. SQLite handles concurrent reads well, but concurrent writes can trigger `database is locked` errors.

**Troubleshooting Log:**

- **2026-09-24: Dashboard Time Display Issue**
  *Problem:* Live feed showed times 3 hours behind (UTC instead of EAT).
  *Fix:* Updated `dashboard.js` to parse ISO timestamps with a `Z` suffix and use `toLocaleTimeString()` to convert UTC to local time in the browser natively, while preserving UTC in the SQLite backend.

- **2026-09-15: The Sept 2026 Startup Error (Npcap Loopback)**
  *Problem:* Suricata failed on boot. 
  *Fix:* Traced to the Npcap service failing to initialize the loopback adapter correctly after a Windows update. Reinstalled Npcap 1.79 with "Support raw 802.11 traffic" checked, and remapped the `suricata.yaml` interface string from `Ethernet` to the physical UUID format (`\Device\NPF_{UUID}`).

- **2026-09-02: Self-Lockout (False Positive)**
  *Problem:* I got locked out of the server via RDP while running an aggressive Nmap scan to test the engine. 
  *Fix:* Logged in via the hypervisor console, ran `netsh advfirewall firewall delete rule name="AIThreatDefense_Block_192_168_x_x_IN"`. Added my management IP to the `whitelist` block in `config.yaml` to prevent it happening again.
