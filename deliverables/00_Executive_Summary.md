# Executive Summary
**DSA 4030 — Big Data Security | Group 13: Threat Intelligence Investigation**

Our team was engaged as a cybersecurity consulting group to investigate
suspicious IP addresses observed in a client's web server logs, assess the
security posture of the environment that stores and processes those logs,
and recommend improvements.

We built a working big-data security environment consisting of a synthetic
web-server log dataset (135,000+ records, generated in Python to model
realistic user traffic alongside six categories of attack behaviour), a
SQLite data store, a rule-based threat-detection engine, and an enrichment
pipeline that queries two free threat-intelligence sources — AbuseIPDB and
VirusTotal — to classify suspicious IPs and compute a weighted risk score.

On top of this environment we implemented and tested five security
controls relevant to a threat-intelligence workflow: encryption of secrets
and data at rest, authentication with role-based access control, SHA-256
integrity verification of evidence files, a persistent audit-logging trail,
and a backup/recovery mechanism for the investigation database. We executed
six formal security tests covering detection accuracy, tamper detection,
access-control enforcement, secrets exposure, and disaster recovery.

**Key finding:** our own initial build contained a real vulnerability — live
threat-intelligence API keys were hardcoded in plaintext in the analysis
notebook. This was identified, remediated (moved to environment-variable
based secrets management with local encryption), and turned into a
regression test (Test 5) so it cannot silently reappear.

The investigation successfully classified [N] suspicious IP addresses across
brute-force, SQL-injection, directory-traversal, port-scan, and enumeration
attack categories, with [N] IPs reaching "High" or "Critical" risk level
after AbuseIPDB/VirusTotal enrichment. Full results are in
`final_threat_report.csv` and the Security Testing Matrix.

**Recommendations** center on moving from a single-analyst SQLite workflow
to a shared, access-controlled data platform (e.g. PostgreSQL with row-level
security), automating the IP-blocking response for Critical-risk IPs, and
integrating the detection rules into a real-time log pipeline rather than
batch analysis.

*(Replace the `[N]` placeholders above with your actual numbers after running
`BDS_TI_Project.ipynb` and `security_tests.py` — see
`security_addon/README_SECURITY_ADDON.md`.)*
