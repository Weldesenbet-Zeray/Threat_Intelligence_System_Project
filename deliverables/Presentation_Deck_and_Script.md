# 10-Minute Presentation Deck & Live Demo Script

**Course**: DSA 4030 - Big Data Security  
**Project**: End of Semester Practical Group Project  
**Group Number**: Group 13 – Threat Intelligence Investigation  
**Presentation Duration**: 10 Minutes Total (7 Mins Presentation + 3 Mins Mandatory Live Demo)  

---

## Slide Deck Outline & Speaker Script

```
Slide 1: Title & Consulting Team Introduction
Slide 2: Client Problem & Threat Landscape
Slide 3: System Architecture & Tech Stack
Slide 4: Big Data Log Synthesis (100,000+ Records)
Slide 5: Rule-Based Threat Detection Engine
Slide 6: Threat Intelligence API Enrichment (AbuseIPDB & VirusTotal)
Slide 7: Part C Security Controls (RBAC, AES Encryption, Integrity, Backup)
Slide 8: LIVE DEMONSTRATION (Mandatory Component Presentation)
Slide 9: Risk Assessment & Recommendations
Slide 10: Conclusion & Q&A
```

---

### Slide 1: Title & Team Introduction (0:45 mins)
- **Visual**: Group 13 Logo, Team Member Names, Project Title.
- **Speaker Script**:  
  > *"Good morning Professor and classmates. We are Group 13, serving as cybersecurity consultants for our client's Big Data environment. Today, we present our Threat Intelligence Investigation and Security Hardening System."*

---

### Slide 2: Client Problem & Threat Landscape (0:45 mins)
- **Visual**: Bullet points of unmonitored web server logs under attack.
- **Speaker Script**:  
  > *"Our client processes high-volume web traffic daily. However, their unmonitored logs hid active cyber attacks—including brute force logins, SQL injections, and directory traversals. Our mission was to analyze 100,000+ records, identify malicious IPs, query global threat intelligence databases, and harden the environment against future attacks."*

---

### Slide 3: System Architecture & Tech Stack (1:00 min)
- **Visual**: Architecture Diagram showing Web Logs -> SQLite DB -> Python Threat Engine -> Threat Intel APIs -> Security Controls.
- **Speaker Script**:  
  > *"Our solution features a multi-tiered security architecture. Data flows into an SQLite Big Data warehouse. A rule-based detection engine flags attacker candidates, which are enriched live via AbuseIPDB and VirusTotal APIs. We layered Part C controls—including bcrypt RBAC, SHA-256 integrity checks, Fernet AES encryption, and rotating audit logs."*

---

### Slide 4: Big Data Log Generation & Ingestion (1:00 min)
- **Visual**: Log synthesis stats (100,000 records, 5 attacker IPs, 200/401/403/404 HTTP status distributions).
- **Speaker Script**:  
  > *"To satisfy Part B requirements, we synthesized a dataset of 100,000 HTTP access logs containing realistic traffic patterns and multi-vector attacks. This was ingested into SQLite database tables designed for high-performance SQL querying."*

---

### Slide 5: Rule-Based Threat Detection Engine (1:00 min)
- **Visual**: SQL queries for SQLi detection, Directory Traversal regex, and Brute Force group-by thresholds.
- **Speaker Script**:  
  > *"Our Python engine scans log URIs and status codes using parameterized SQL queries. It automatically detected 3,733 threat events and isolated 5 primary malicious IPs conducting credential stuffing, database exfiltration attempts, and system file escape scans."*

---

### Slide 6: Threat Intelligence API Enrichment (1:00 min)
- **Visual**: AbuseIPDB confidence score charts and VirusTotal antivirus engine verdicts.
- **Speaker Script**:  
  > *"Once suspicious IPs were isolated, our system queried AbuseIPDB and VirusTotal REST APIs over HTTPS. The response data enriched our incident database with live reputation scores (e.g., 100% Abuse Confidence), ISP ownership, and country of origin."*

---

### Slide 7: Security Controls & Hardening (1:00 min)
- **Visual**: Highlights of `access_control.py`, `secrets_manager.py`, `integrity_check.py`, and `backup_recovery.py`.
- **Speaker Script**:  
  > *"To satisfy Part C, we implemented five open-source security modules: salted bcrypt password hashing and RBAC permissions; Fernet AES-256 file encryption at rest; SHA-256 cryptographic integrity manifests; timestamped database backup snapshots; and rotating audit file logging."*

---

### Slide 8: MANDATORY LIVE DEMONSTRATION (3:00 mins)

> [!IMPORTANT]
> **Assessment Rule**: Marks will NOT be awarded for screenshots alone. Each group member must perform a live demonstration of their configured component.

#### Live Demo Step-by-Step Execution Script:

1. **Member 1 (Pipeline Execution & Log Storage)**:
   - Open terminal and run: `python run_security_pipeline.py`
   - Point out: The terminal generating logs, running detection rules, and populating SQLite database `threat_intelligence.db`.

2. **Member 2 (RBAC & Audit Logging)**:
   - Run: `python security_addon/access_control.py login analyst1`
   - Point out: `analyst1` login succeeds with read permissions, but attempting admin tasks raises `PermissionError`, logged directly to `security_addon/logs/audit.log`.

3. **Member 3 (Integrity Verification & Backup Restore)**:
   - Run: `python security_addon/integrity_check.py verify`
   - Point out: `OK threat_intelligence.db matches baseline hash`.
   - Run: `python security_addon/backup_recovery.py list`
   - Point out: Timestamped database backups created in `security_addon/backups/`.

---

### Slide 9: Risk Assessment & Recommendations (1:00 min)
- **Visual**: Risk Assessment Table highlighting SQLi (Critical) and Brute Force (High) mitigations.
- **Speaker Script**:  
  > *"Our risk assessment evaluated identified vulnerabilities using the NIST framework. We recommend deploying Web Application Firewalls (WAF) with automated SOAR blocking rules, migrating SQLite to distributed cloud datastores (BigQuery/PostgreSQL), and managing keys with cloud KMS."*

---

### Slide 10: Conclusion & Q&A (0:30 mins)
- **Visual**: Key Achievements Summary & "Thank You / Questions?" prompt.
- **Speaker Script**:  
  > *"In summary, Group 13 delivered a complete Big Data Threat Intelligence and Security Hardening platform. Thank you for your time, and we welcome any questions!"*
