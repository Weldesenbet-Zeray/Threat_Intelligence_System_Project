# Deliverable 6: Risk Assessment Table (ISO 27001 / NIST SP 800-30 Framework)

**Project Title**: Threat Intelligence Investigation and Big Data Security Hardening  
**Course**: DSA 4030 - Big Data Security (Group 13)  

---

## Risk Assessment Matrix

The risk assessment below evaluates threats identified during the Threat Intelligence Investigation according to Likelihood (1-5), Impact (1-5), and Composite Risk Rating (Critical, High, Medium, Low).

| Threat ID | Identified Threat Vector | Vulnerability Description | Likelihood | Impact | Risk Rating | Recommended Security Controls |
| :---: | :--- | :--- | :---: | :---: | :---: | :--- |
| **RSK-01** | **SQL Injection (SQLi)** | Unsanitized input strings in HTTP query parameters allowing database extraction or modification. | High (4) | Critical (5) | **CRITICAL (20)** | Implement parameterized queries/ORMs, Web Application Firewall (WAF) SQLi rules, and DB least privilege. |
| **RSK-02** | **Credential Stuffing / Brute Force** | Lack of login attempt rate limits allowing automated credential enumeration. | High (4) | High (4) | **HIGH (16)** | Enforce Multi-Factor Authentication (MFA), CAPTCHA on login endpoints, and IP-based rate limiting. |
| **RSK-03** | **Directory Traversal** | Path parameters allowing path escape (`../`) to access system configuration files (`/etc/passwd`). | Medium (3) | High (4) | **HIGH (12)** | Enforce strict file path whitelist validation, containerization, and non-root execution permissions. |
| **RSK-04** | **Unauthenticated Database Access** | Raw SQLite database file accessible without identity validation or permission checks. | High (4) | High (4) | **HIGH (16)** | Deployed `access_control.py` (bcrypt RBAC permissions: `analyst` vs `admin`). |
| **RSK-05** | **Data Tampering & Log Corruption** | Threat logs modified by adversaries to erase malicious footprint. | Medium (3) | High (4) | **HIGH (12)** | Deployed `integrity_check.py` (SHA-256 hash manifest verification) and append-only write permissions. |
| **RSK-06** | **API Key Hardcoding & Exposure** | Plaintext Threat Intel API keys committed in notebook source code. | Medium (3) | Medium (3) | **MEDIUM (9)** | Deployed `secrets_manager.py` (.env environment variable loading and Fernet AES-256 key vault). |
| **RSK-07** | **Data Loss / Ransomware Outage** | Storage corruption leading to loss of security audit trail. | Low (2) | High (4) | **MEDIUM (8)** | Deployed `backup_recovery.py` (automated timestamped database snapshots and restoration utility). |

---

## Likelihood & Impact Scoring Key
- **Likelihood Scale**: 1 = Rare, 2 = Unlikely, 3 = Possible, 4 = Likely, 5 = Almost Certain
- **Impact Scale**: 1 = Insignificant, 2 = Minor, 3 = Moderate, 4 = Major, 5 = Critical
- **Risk Score Matrix**:
  - **15 - 25**: **CRITICAL** (Requires immediate mitigation)
  - **10 - 14**: **HIGH** (Priority resolution within deployment cycle)
  - **5 - 9**: **MEDIUM** (Managed through routine security controls)
  - **1 - 4**: **LOW** (Acceptable residual risk)
