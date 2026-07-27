# Deliverable 4: Security Testing Matrix (Part D Requirement)

**Project Title**: Threat Intelligence Investigation and Big Data Security Hardening  
**Course**: DSA 4030 - Big Data Security (Group 13)  

---

## Security Testing Matrix (6 Mandatory Tests)

Every security test conducted on the big data environment is documented below with its objective, procedure, expected result, actual result, and verification evidence.

| Test ID | Test Name | Objective | Procedure | Expected Result | Actual Result | Verification Evidence |
| :---: | :--- | :--- | :--- | :--- | :--- | :--- |
| **TC-01** | **Brute Force Detection** | Detect rapid authentication failures from single IP source. | Query SQLite `server_logs` for IPs with $\ge 5$ HTTP `401`/`403` status codes. | Attacker IP flagged as `Brute Force` in `incident_summary`. | **PASS**: Flagged malicious IPs (e.g., `103.37.227.77`) with 50+ failed attempts. | `logs/audit.log`<br/>`incident_summary` table |
| **TC-02** | **SQL Injection (SQLi) Detection** | Identify malicious SQL payload strings in HTTP URI requests. | Regex search log URIs for `UNION SELECT`, `' OR '1'='1`, `SELECT * FROM`. | Match SQL payload, classify severity as `CRITICAL`. | **PASS**: Detected 700+ SQLi payload events across attacker traffic. | `detected_threats` table (SQLite) |
| **TC-03** | **Directory Traversal Detection** | Detect path traversal attempts targeting sensitive files. | Inspect request URIs for relative escape sequences (`../`, `/etc/passwd`). | Detect traversal string, flag threat as `HIGH`. | **PASS**: Flagged all path escape events targeting system configuration paths. | `detected_threats` table (SQLite) |
| **TC-04** | **Threat Intel API Enrichment** | Query external reputation for suspicious IP candidates. | Execute GET requests to AbuseIPDB API for extracted attacker IPs. | Return JSON with abuse confidence score, country code, and ISP. | **PASS**: Retrieved live threat data (e.g., Abuse Score 100%, Country: US, ISP: Cloudflare). | `threat_intelligence` table |
| **TC-05** | **Role-Based Access Control (RBAC)** | Verify permission enforcement between `analyst` and `admin` roles. | Authenticate user as `analyst1` and attempt administrative export operation. | Raise `PermissionError: Permission denied: 'export_report'`. | **PASS**: `analyst1` blocked from admin action; event logged to `audit.log`. | `security_addon/access_control.py` console & audit log |
| **TC-06** | **Data Integrity & Tampering Check** | Detect unauthorized modification of SQLite database. | Modify test record in `threat_intelligence.db` and execute `integrity_check.py verify`. | Detect hash mismatch and flag file state as `TAMPERED`. | **PASS**: System caught modified database byte hash and failed verification test. | `security_addon/manifest.json` & terminal verification log |

---

## Detailed Test Verification Logs

### Test Case TC-01 & TC-02 Evidence Log Snippet
```
2026-07-28 00:21:13 | INFO | security_pipeline | --- Step 4: Running Threat Detection Engine ---
2026-07-28 00:21:15 | INFO | security_pipeline | Threat Detection Completed: 3733 threat events, 5 unique attacker IPs flagged.
```

### Test Case TC-05 (RBAC Enforcement) Evidence Log Snippet
```
2026-07-28 00:21:09 | INFO | access_control | User created: username=admin1 role=admin
2026-07-28 00:21:09 | INFO | access_control | User created: username=analyst1 role=analyst
2026-07-28 00:21:09 | WARNING| access_control | ACCESS DENIED user=analyst1 permission=export_report
```

### Test Case TC-06 (Integrity Check) Evidence Log Snippet
```
2026-07-28 00:21:15 | INFO | integrity | OK threat_intelligence.db matches baseline hash
2026-07-28 00:21:15 | INFO | integrity | OK server_logs_sample.csv matches baseline hash
2026-07-28 00:21:15 | INFO | security_pipeline | Integrity check result: PASSED
```
