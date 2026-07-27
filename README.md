# Threat Intelligence Investigation & Big Data Security System

**Course**: DSA 4030 - Big Data Security  
**Project**: End of Semester Practical Group Project (Weight: 30%)  
**Assigned Group**: Group 13  
**GitHub Repository**: [https://github.com/Weldesenbet-Zeray/Threat_Intelligence_System_Project.git](https://github.com/Weldesenbet-Zeray/Threat_Intelligence_System_Project.git)

---

## 📌 Project Overview

This system processes, analyzes, and hardens a Big Data web log environment against automated cyber attacks. Acting as a cybersecurity consulting team for Group 13, our pipeline:
1. Ingests and parses **100,000+ web access log records** into an **SQLite Data Warehouse** (`threat_intelligence.db`).
2. Detects malicious multi-vector attack patterns (**SQL Injection**, **Brute Force**, **Directory Traversal**).
3. Enriches suspicious IP indicators with external Threat Intelligence APIs (**AbuseIPDB v2** and **VirusTotal v3**).
4. Implements **Part C Security Hardening Controls** (Salted `bcrypt` RBAC, Fernet AES-256 encryption at rest, SHA-256 integrity verification, timestamped database backups, and rotating audit logging).
5. Provides a **Real-Time Kafka Streaming Simulation Engine** (`kafka_stream_demo.py`) for sub-second threat detection.

---

## 🛠️ System Architecture

```
[Web Server Access Logs (100k+ Rows)] ──> [SQLite Data Warehouse] ──> [Rule-Based Detection Engine]
                                                                              │
                                                                              ▼
[Security Controls & Audit Logs] <── [Threat Intel APIs] <── [Suspicious IP Aggregator]
 (RBAC, Fernet AES, Hashing)         (AbuseIPDB & VirusTotal)
```

---

## 📋 Prerequisites & Installation

### Requirements
- **Python 3.10+**
- Git

### Installation Steps

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Weldesenbet-Zeray/Threat_Intelligence_System_Project.git
   cd Threat_Intelligence_System_Project
   ```

2. **Install Python Dependencies**:
   ```bash
   pip install cryptography bcrypt python-dotenv requests pandas matplotlib
   ```

3. **Configure Environment Variables (API Keys)**:
   Copy the example environment template to `.env`:
   ```bash
   cp security_addon/.env.example security_addon/.env
   ```
   *(Optional: Edit `security_addon/.env` to insert your VirusTotal or AbuseIPDB API keys).*

---

## 🚀 How to Run the Project (Step-by-Step)

### Step 1: Run the Automated Master Security Pipeline
To execute log generation ($100,000$ records), SQLite database creation, threat detection, database backup, and SHA-256 integrity baseline in one command:

```bash
python run_security_pipeline.py
```

**Expected Console Output**:
```
2026-07-28 00:21:08 | INFO | STARTING MASTER BIG DATA SECURITY PIPELINE EXECUTION
2026-07-28 00:21:09 | INFO | RBAC users 'admin1' and 'analyst1' initialized.
2026-07-28 00:21:12 | INFO | Saved 100000 log records to server_logs_sample.csv
2026-07-28 00:21:13 | INFO | Database loaded cleanly at threat_intelligence.db
2026-07-28 00:21:15 | INFO | Threat Detection Completed: 3,733 threat events, 5 unique attacker IPs flagged.
2026-07-28 00:21:15 | INFO | Backup created: threat_intelligence.db.20260728_002115.bak
2026-07-28 00:21:15 | INFO | Integrity check result: PASSED
```

---

### Step 2: Launch Interactive Streamlit SOC Web Dashboard
To launch the interactive Security Operations Center (SOC) web application UI:

```bash
streamlit run streamlit_dashboard.py
```
*Access the interactive web dashboard in your browser at `http://localhost:8501` to explore 100,000 logs, query threat intelligence APIs, run RBAC logins, and trigger real-time Kafka streams.*

---

### Step 3: Test Real-Time Apache Kafka Streaming Engine
To demonstrate real-time topic streaming (`web-access-logs` $\rightarrow$ `security-alerts`):

```bash
python kafka_stream_demo.py
```

**Expected Console Output**:
```
======================================================================
APACHE KAFKA REAL-TIME LOG STREAMING DEMO
======================================================================
Mode             : Real-Time Event Stream Engine (Kafka Topic Simulator)
Topic Subscribed : 'web-access-logs'
Alert Topic Output: 'security-alerts'
======================================================================
[PRODUCER] -> Sent log event to topic 'web-access-logs' (IP: 192.168.1.10, URI: /index.html)
[PRODUCER] -> Sent log event to topic 'web-access-logs' (IP: 103.37.227.77, URI: /login.php?user=admin' OR '1'='1)
 [KAFKA STREAM DETECTOR ALERT] CRITICAL threat event generated for IP 103.37.227.77!
```

---

### Step 3: Run Individual Part C Security Controls

#### 1. Authentication & Role-Based Access Control (RBAC)
```bash
# Add a new user with 'analyst' or 'admin' role
python security_addon/access_control.py adduser analyst1 analyst

# Test authentication login
python security_addon/access_control.py login analyst1
```

#### 2. SHA-256 Integrity Baseline & Verification
```bash
# Create SHA-256 hash manifest for project databases and logs
python security_addon/integrity_check.py baseline

# Verify system integrity against manifest
python security_addon/integrity_check.py verify
```

#### 3. Database Backup & Disaster Recovery
```bash
# Take immediate timestamped database snapshot
python security_addon/backup_recovery.py backup

# List all available database backups
python security_addon/backup_recovery.py list

# Restore database from latest backup
python security_addon/backup_recovery.py restore
```

#### 4. Fernet AES-256 Encryption Self-Test
```bash
python security_addon/secrets_manager.py
```

---

## 🎤 10-Minute Presentation & Live Demo Quick Reference

During your live presentation, follow this 3-command live demo sequence during Slide 8:

1. **Demonstrate Batch Ingestion & Threat Detection**:
   ```bash
   python run_security_pipeline.py
   ```
2. **Demonstrate Salted bcrypt RBAC & Audit Logs**:
   ```bash
   python security_addon/access_control.py login analyst1
   ```
3. **Demonstrate Real-Time Event Streaming**:
   ```bash
   python kafka_stream_demo.py
   ```

---

## 📂 Project Directory Structure

```
.
├── README.md                            # Comprehensive Setup & Execution Guide
├── BDS_TI_Project.ipynb                 # Research Jupyter Notebook
├── DSA4030_Group_Project.txt            # Project Instructions & Requirements Specification
├── run_security_pipeline.py             # Master Security Pipeline Execution Script
├── kafka_stream_demo.py                 # Real-Time Event Streaming Engine
├── server_logs_sample.csv               # Big Data Web Access Log Dataset (100,000+ records)
├── threat_intelligence.db               # SQLite Big Data Warehouse
├── security_addon/                      # Part C Security Hardening Controls
│   ├── .env                             # Environment Variables & API Secrets
│   ├── .env.example                     # Environment Variables Template
│   ├── access_control.py                # Salted bcrypt Authentication & RBAC
│   ├── audit_logger.py                  # Rotating Audit File Logger (logs/audit.log)
│   ├── backup_recovery.py               # Timestamped Database Snapshot & Restore
│   ├── integrity_check.py               # Cryptographic SHA-256 Manifest & Verifier
│   ├── secrets_manager.py               # Fernet AES-256 Encryption & PBKDF2 Key Vault
│   ├── manifest.json                    # Cryptographic Hash Manifest
│   └── users.json                       # User Authentication Hash Store
└── deliverables/                        # All 8 Project Submission Documents
    ├── 01_Executive_Summary.md
    ├── 02_System_Architecture.md
    ├── 03_Implementation_Report.md
    ├── 04_Security_Testing_Matrix.md    # 6 Mandatory Security Test Cases
    ├── 05_Evidence_Portfolio.md
    ├── 06_Risk_Assessment_Table.md      # ISO 27001 / NIST SP 800-30 Risk Matrix
    ├── 07_Conclusion_and_Recommendations.md
    ├── 08_Appendices.md
    ├── Complete_Project_Submission_Report.md  # Master Single-File Report
    └── Presentation_Deck_and_Script.md        # 10-Min Presentation & Live Demo Script
```

---

## 📄 License & Attribution

Developed by **Cybersecurity Consulting Team (Group 13)** for **DSA 4030: Big Data Security**.  
Open-source license under MIT.
