# Deliverable 1: Executive Summary

**Project Title**: Threat Intelligence Investigation and Big Data Security Hardening  
**Course**: DSA 4030 - Big Data Security  
**Assigned Group**: Group 13  
**Client / Scenario**: Enterprise Web Log Threat Investigation & Hardening  

---

## 1. Executive Summary Overview

Modern enterprise infrastructure generates gigabytes of web server log data daily. Unmonitored, these big data environments become prime targets for automated threat actors conducting credential stuffing, SQL Injection (SQLi), Path Traversal, and distributed scanning.

Group 13 was engaged as a specialized cybersecurity consulting team to assess, analyze, and secure a client’s big data web infrastructure. Our objective was to investigate suspicious IP addresses identified in system access logs, enrich incident data using threat intelligence APIs (**AbuseIPDB** and **VirusTotal**), and implement robust, open-source security controls across storage, access control, encryption, data integrity, and backup/recovery.

---

## 2. Key Accomplishments & Technical Findings

1. **Big Data Environment & Log Processing**:
   - Synthesized and ingested **100,000+ web access log records** into a structured **SQLite Big Data Warehouse** (`threat_intelligence.db`).
   - Built a rule-based detection engine in Python to classify malicious traffic patterns across HTTP requests.

2. **Threat Intelligence Integration**:
   - Automated IP reputation checks querying live external threat intelligence databases (**AbuseIPDB** and **VirusTotal v3 API**).
   - Flagged key threat IPs (e.g., `103.37.227.77`, `105.161.111.216`, `107.146.189.254`, `112.47.186.121`, `118.229.146.73`) exhibiting multi-vector attack profiles (SQL Injection, Brute Force, Directory Traversal).

3. **Part C Security Controls Implementation**:
   - **Authentication & RBAC**: Implemented salted `bcrypt` password hashing and role-based permissions (`analyst` for read-only reports vs. `admin` for full pipeline access).
   - **Data Integrity Verification**: Built a **SHA-256 baseline manifest engine** to detect unauthorized file or database tampering (`manifest.json`).
   - **Encryption at Rest**: Applied Fernet AES-256 encryption via derived PBKDF2 keys (`secrets_manager.py`) and removed hardcoded API keys by deploying secure `.env` secrets management.
   - **Backup & Recovery**: Automated timestamped database backups (`.bak`) and single-command recovery (`backup_recovery.py`).
   - **Audit Logging**: Replaced transient console statements with rotating file logger outputting structured records to `logs/audit.log`.

4. **Security Testing & Risk Evaluation**:
   - Executed **6 comprehensive security tests** covering Brute Force, SQLi, Directory Traversal, Threat Intel API integration, RBAC enforcement, and Data Integrity.
   - Conducted an ISO 27001 / NIST SP 800-30 Risk Assessment cataloging identified vulnerabilities and enterprise mitigations.

---

## 3. High-Level System Architecture

```
[Web Server Access Logs] ---> [SQLite Data Warehouse] ---> [Rule-Based Detection Engine]
                                                                   |
                                                                   v
[Security Controls & Audit Logs] <--- [Threat Intelligence APIs] <--- [Suspicious IP Aggregator]
 (RBAC, Fernet AES, Hashing)          (AbuseIPDB & VirusTotal)
```

---

## 4. Key Recommendations

- **Deploy Web Application Firewall (WAF)**: Automatically push high-scoring threat IPs from AbuseIPDB to edge blocklists.
- **Enforce Strict Input Parameterization**: Enforce ORMs and parameterized queries to mitigate SQL Injection risks.
- **Implement Centralized SIEM/SOAR**: Scale SQLite database architecture to PostgreSQL or Apache Kafka + Elasticsearch for enterprise real-time log streaming.

---

*Submitted by Cybersecurity Consulting Team (Group 13)*
