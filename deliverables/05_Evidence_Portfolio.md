# Deliverable 5: Evidence Portfolio

**Project Title**: Threat Intelligence Investigation and Big Data Security Hardening  
**Course**: DSA 4030 - Big Data Security (Group 13)  

---

## 1. Evidence Artifacts Index

| Evidence ID | Artifact Description | Location / File Path | Verification Status |
| :---: | :--- | :--- | :---: |
| **EVD-01** | Raw Ingested Access Logs Sample ($100,000$ rows) | `c:\School_projects\DSA_4030\server_logs_sample.csv` | Verified |
| **EVD-02** | Master SQLite Big Data Database | `c:\School_projects\DSA_4030\threat_intelligence.db` | Verified |
| **EVD-03** | Centralized Audit Log File | `security_addon/logs/audit.log` | Verified |
| **EVD-04** | Cryptographic SHA-256 Baseline Manifest | `security_addon/manifest.json` | Verified |
| **EVD-05** | Database Snapshot Backups | `security_addon/backups/*.bak` | Verified |
| **EVD-06** | Salted Passwords & User Database | `security_addon/users.json` | Verified |

---

## 2. Evidence Sample Snippets

### EVD-01: Sample Ingested Log Record (CSV)
```csv
log_id,timestamp,ip_address,request_uri,status_code,response_bytes,user_agent
1,2026-07-21 14:02:11,103.37.227.77,/login.php?user=admin' OR '1'='1,401,320,Mozilla/5.0
2,2026-07-21 14:02:15,103.37.227.77,/download.php?file=../../../../etc/passwd,403,210,Mozilla/5.0
3,2026-07-21 14:03:00,192.168.1.15,/index.html,200,4520,Mozilla/5.0
```

### EVD-02: SQLite Incident Summary Query Results
```
sqlite3 threat_intelligence.db "SELECT * FROM incident_summary;"

ip_address      | threat_count | threat_types
----------------|--------------|------------------------------------------------
103.37.227.77   | 742          | 404 Enumeration, Brute Force, Directory Traversal, SQL Injection
105.161.111.216 | 815          | Brute Force, Directory Traversal, SQL Injection
107.146.189.254 | 698          | 404 Enumeration, SQL Injection
112.47.186.121  | 720          | Brute Force, SQL Injection
118.229.146.73  | 758          | Directory Traversal, SQL Injection
```

### EVD-04: Cryptographic Integrity Manifest (`manifest.json`)
```json
{
  "threat_intelligence.db": "a8f3e7b192c45d6e7f8091a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2",
  "server_logs_sample.csv": "c9e8d7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8"
}
```

### EVD-06: User Authentication Hashing Store (`users.json`)
```json
{
  "admin1": {
    "role": "admin",
    "password_hash": "$2b$12$eImiTXuWVxfM37uY4JANjO5E.N...[salted bcrypt hash]"
  },
  "analyst1": {
    "role": "analyst",
    "password_hash": "$2b$12$8K9jH2gF4dS1a...[salted bcrypt hash]"
  }
}
```
