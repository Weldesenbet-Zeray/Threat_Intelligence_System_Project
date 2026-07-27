# Deliverable 3: Implementation & Configuration Report

**Project Title**: Threat Intelligence Investigation and Big Data Security Hardening  
**Course**: DSA 4030 - Big Data Security (Group 13)  

---

## 1. Environment Setup & Tool Configuration (Part A)

The project environment was constructed using Python 3.10 and open-source software libraries. The core components are configured as follows:

- **Storage Platform**: SQLite (`threat_intelligence.db`) storing 100,000+ access logs and detection results.
- **Log Source**: Synthesized HTTP access logs saved to `server_logs_sample.csv`.
- **Security Tools**:
  - `secrets_manager.py`: Fernet AES-256 encryption & PBKDF2 HMAC-SHA256 key derivation.
  - `access_control.py`: Salted `bcrypt` user authentication and RBAC permissions module.
  - `audit_logger.py`: Rotating file logger tracking all execution events to `security_addon/logs/audit.log`.
  - `integrity_check.py`: SHA-256 hash manifest baseline generator and integrity verifier.
  - `backup_recovery.py`: Automated database snapshot utility producing timestamped `.bak` files.
  - **Threat Intelligence APIs**: AbuseIPDB REST API v2 & VirusTotal v3 REST API.

---

## 2. Dataset Synthesis & Ingestion (Part B)

A big data dataset of **100,000 HTTP access log records** was generated using weighted probabilistic distributions across normal user profiles and simulated malicious attacker profiles.

```sql
-- SQLite Database Schema Definition
CREATE TABLE server_logs (
    log_id INTEGER PRIMARY KEY,
    timestamp TEXT,
    ip_address TEXT,
    request_uri TEXT,
    status_code INTEGER,
    response_bytes INTEGER,
    user_agent TEXT
);

CREATE TABLE detected_threats (
    log_id INTEGER,
    ip_address TEXT,
    threat_type TEXT,
    severity TEXT
);

CREATE TABLE incident_summary (
    ip_address TEXT PRIMARY KEY,
    threat_count INTEGER,
    threat_types TEXT
);
```

---

## 3. Security Controls Setup (Part C)

### 3.1 Authentication & Role-Based Access Control (RBAC)
User passwords are never stored in plain text. Passwords are hashed with salted `bcrypt` ($12$ rounds of salt).
Roles define granular permission matrices:
- `analyst`: Read-only access to detection tables and reports (`read_reports`, `read_logs`).
- `admin`: Full administrative access (`read_reports`, `read_logs`, `run_enrichment`, `export_report`, `manage_users`).

### 3.2 Confidentiality & Encryption at Rest
API keys are decoupled from code and stored in `.env` (`secrets_manager.py`). Files and sensitive outputs are encrypted using Fernet AES-256 derived from a master passphrase using 390,000 iterations of PBKDF2-HMAC-SHA256.

### 3.3 Data Integrity & Anti-Tampering
`integrity_check.py` generates a cryptographic SHA-256 checksum manifest (`manifest.json`) for the SQLite database and raw log files. Running `python integrity_check.py verify` compares current file hashes against the baseline, flagging unauthorized alterations.

### 3.4 Backup & Recovery Control
`backup_recovery.py` creates timestamped backups in `security_addon/backups/`. In the event of corruption or ransomware simulation, `python backup_recovery.py restore` restores the system to the last verified clean baseline.

### 3.5 Centralized Audit Logging
All security operations emit formatted log lines (`TIMESTAMP | SEVERITY | MODULE | MESSAGE`) saved to `security_addon/logs/audit.log` via `RotatingFileHandler` ($2$ MB limit per file, $5$ backup rotations).
