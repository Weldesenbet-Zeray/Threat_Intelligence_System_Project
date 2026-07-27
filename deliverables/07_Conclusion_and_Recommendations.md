# Deliverable 7: Conclusion & Recommendations (Part E Requirement)

**Project Title**: Threat Intelligence Investigation and Big Data Security Hardening  
**Course**: DSA 4030 - Big Data Security (Group 13)  

---

## 1. Project Conclusion & Key Findings

Group 13 successfully designed, implemented, and security-tested an automated Big Data Threat Intelligence pipeline handling over 100,000 access log records.

Through rule-based detection and Threat Intelligence enrichment via AbuseIPDB and VirusTotal, our team identified 5 primary malicious IP addresses conducting coordinated multi-vector attacks (SQL Injection, Path Traversal, Brute Force, and Directory Enumeration).

By deploying Part C Security Controls (`access_control.py`, `secrets_manager.py`, `integrity_check.py`, `backup_recovery.py`, and `audit_logger.py`), we transformed an unhardened research script into an enterprise-ready security system with encrypted secrets, salted bcrypt RBAC, SHA-256 integrity verification, automated backups, and persistent rotating audit trails.

---

## 2. Identified Vulnerabilities & Remaining Risks

While the core big data environment has been hardened, several residual risks remain inherent to localized architecture:

1. **Local File-Based SQLite Database**:
   - *Limitation*: SQLite lacks native network-level concurrent authentication and fine-grained column-level encryption.
   - *Residual Risk*: File-system level access to `threat_intelligence.db` permits file deletion if operating system permissions are misconfigured.

2. **API Rate Limits on Free-Tier Threat Intelligence**:
   - *Limitation*: Free API tiers for VirusTotal (4 requests/min) and AbuseIPDB (1,000 requests/day) limit real-time enrichment scale during massive DDoS events.
   - *Residual Risk*: Enrichment backlogs during high-volume log spikes.

---

## 3. Enterprise Recommendations & Next Steps

To scale this prototype to a multi-terabyte production environment, we recommend the following strategic enhancements:

1. **Migrate Data Storage to Distributed Enterprise Platforms**:
   - Transition from SQLite to PostgreSQL with RLS (Row-Level Security) or a distributed big data lakehouse architecture (Apache Iceberg / BigQuery / Elasticsearch).

2. **Deploy Web Application Firewall (WAF) & SOAR Automation**:
   - Integrate automated Security Orchestration, Automation, and Response (SOAR) playbooks. High-risk IPs identified by AbuseIPDB ($\text{Abuse Score} > 80\%$) should trigger automated block rules on Cloudflare or AWS WAF within seconds.

3. **Deploy Centralized SIEM Ingestion (Elasticsearch / Splunk)**:
   - Stream raw web logs using Apache Kafka and Vector into an Elastic SIEM cluster for real-time visualization dashboards and anomaly detection.

4. **Implement Key Management Services (KMS)**:
   - Replace local `.env` file management with AWS KMS, HashiCorp Vault, or Google Cloud Secret Manager for automated key rotation and HSM hardware security.
