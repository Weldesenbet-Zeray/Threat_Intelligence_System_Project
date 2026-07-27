# System Architecture

See the interactive diagram artifact for the polished version. Text/mermaid
version below for the written report and appendices.

```mermaid
flowchart TB
    subgraph GEN["Part B - Dataset Generation (Python / Faker)"]
        A1[User Pool Generator] --> A2[Session Generator]
        A2 --> A3[Request Generator]
        A4[Attack Session Generator] --> A3
        A3 --> A5["final_logs (135k+ records)"]
    end

    subgraph STORE["Part A - Storage Platform"]
        A5 --> B1[(SQLite\nthreat_intelligence.db)]
        B1 --> B1a[server_logs]
        B1 --> B1b[detected_threats]
        B1 --> B1c[incident_summary]
        B1 --> B1d[threat_intelligence]
        B1 --> B1e[final_threat_report]
    end

    subgraph DETECT["Threat Detection Engine (SQL rules)"]
        B1a --> C1[Brute Force Rule]
        B1a --> C2[SQL Injection Rule]
        B1a --> C3[Directory Traversal Rule]
        B1a --> C4[Port Scan Rule]
        B1a --> C5["404 Enumeration Rule"]
        B1a --> C6[High Request Rate Rule]
        C1 & C2 & C3 & C4 & C5 & C6 --> B1b
    end

    subgraph TI["Threat Intelligence Enrichment"]
        B1b --> D1[Suspicious IP Extraction]
        D1 --> D2[AbuseIPDB API]
        D1 --> D3[VirusTotal API]
        D2 & D3 --> D4[Risk Scoring Engine]
        D4 --> B1d
    end

    subgraph CTRL["Part C - Security Controls (security_addon/)"]
        E1[secrets_manager.py\nEncryption + env-based API keys]
        E2[access_control.py\nAuthentication + RBAC]
        E3[integrity_check.py\nSHA-256 manifest]
        E4[audit_logger.py\nPersistent logging]
        E5[backup_recovery.py\nBackup + restore]
        E1 -.protects.-> D2
        E1 -.protects.-> D3
        E2 -.gates access to.-> B1
        E3 -.hashes.-> B1
        E3 -.hashes.-> A5
        E4 -.logs actions of.-> E1 & E2 & E3 & E5
        E5 -.backs up.-> B1
    end

    subgraph TEST["Part D - Security Testing (security_tests.py)"]
        F1["6 automated tests:\ndetection accuracy x2, tamper\ndetection, RBAC enforcement,\nsecrets scan, backup/recovery"]
    end

    B1b --> F1
    E2 --> F1
    E3 --> F1
    E5 --> F1

    D4 --> G[Executive Dashboard\n+ final_threat_report.csv]
```

## Component Summary

| Layer | Component | Tool/Tech |
|---|---|---|
| Data source | Synthetic web server logs | Python, Faker, NumPy |
| Storage | Relational store | SQLite 3 |
| Detection | Rule-based engine | SQL queries over `server_logs` |
| Threat intel | External enrichment | AbuseIPDB API, VirusTotal API |
| Security - Encryption | Secrets/data at rest | `cryptography.Fernet`, PBKDF2 |
| Security - AuthN/RBAC | Access control | `bcrypt`, JSON-backed role store |
| Security - Integrity | Tamper detection | SHA-256 manifest |
| Security - Logging | Audit trail | Python `logging`, rotating file handler |
| Security - Backup | Disaster recovery | Timestamped SQLite file copies |
| Testing | Automated test suite | Custom `security_tests.py` |
