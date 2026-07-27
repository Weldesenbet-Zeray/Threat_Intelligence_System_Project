# Implementation Report

## 1. Scenario
Group 13 — Threat Intelligence Investigation. Objective: investigate
suspicious IPs in server logs, check them against free threat-intelligence
sources, classify malicious activity, and produce an investigation report
with response recommendations.

## 2. Environment Setup (Part A)

| Requirement | Implementation |
|---|---|
| Data source | Synthetic HTTP access logs generated with Python + Faker (`BDS_TI_Project.ipynb`, Sections 1-9) |
| Storage platform | SQLite (`threat_intelligence.db`) |
| Security tool(s) | AbuseIPDB + VirusTotal (threat intel); custom rule-based detection engine; `security_addon/` control suite |
| Logging capability | Python `logging` with `RotatingFileHandler` writing to `security_addon/logs/audit.log` |

No Docker/VirtualBox was used — the entire environment runs natively in
Python/Jupyter, which keeps the setup reproducible on any teammate's machine
with a single `pip install`.

## 3. Dataset (Part B)

Generated via `generate_user_pool`, `generate_session`, and the per-profile
request generator (Sections 5-7), then merged with a dedicated
`ATTACK_ENDPOINTS`-driven attack-session generator (Section 8) covering:
Brute Force, SQL Injection, Directory Traversal, Port Scan, and 404
Enumeration. Final merged dataset exceeds the 100,000-record minimum
(~130,000-140,000 rows depending on random seed) and is validated in
Section 10 (dtypes, duplicates, null counts, time range, session-length
statistics) before being loaded into SQLite in Section 11.

## 4. Security Controls (Part C)

Implemented in `security_addon/` as five standalone, independently
demonstrable modules (see `security_addon/README_SECURITY_ADDON.md` for
exact run commands):

- **Encryption** (`secrets_manager.py`) — API keys are read from a
  local `.env` file (never hardcoded) via `python-dotenv`; a
  passphrase-derived Fernet key (PBKDF2-HMAC-SHA256, 390,000 iterations)
  is available to encrypt any file at rest, e.g. the exported CSV reports.
- **Authentication + RBAC** (`access_control.py`) — bcrypt-hashed
  credentials in `users.json`; two roles (`analyst`: read-only,
  `admin`: read-write + user management), enforced via
  `require_permission()`.
- **Integrity verification** (`integrity_check.py`) — SHA-256 manifest
  of the DB and CSV exports (`manifest.json`); `verify()` detects any
  post-baseline modification.
- **Logging** (`audit_logger.py`) — every control above writes
  timestamped entries to a single rotating audit log, giving a single
  source of truth for "who did what, when."
- **Backup and recovery** (`backup_recovery.py`) — timestamped copies
  of `threat_intelligence.db` in `security_addon/backups/`, with a
  one-command restore path.

These five were chosen (over e.g. malware scanning or network monitoring)
because they map directly onto the actual attack surface of a
threat-intelligence investigation workflow: leaked API credentials, an
unprotected shared database, and undetectable tampering with evidence are
the realistic risks here — not endpoint malware.

## 5. Threat Detection Engine

Six SQL-based detectors run against `server_logs` (Sections 22-29):
Brute Force (>=5 failed `/login` attempts), SQL Injection (payload pattern
matching), Directory Traversal (`../`, `.env`, `passwd` patterns), Port Scan
(>=5 distinct sensitive endpoints from one IP), 404 Enumeration (>=10 404s),
and High Request Rate (>=100 requests from one IP). Detections are merged
into `incident_summary` per IP with a `highest_severity` field.

## 6. Threat Intelligence Enrichment & Risk Scoring

Every IP in `incident_summary` is queried against AbuseIPDB (`abuse_score`,
ISP, report count) and VirusTotal (`malicious`/`suspicious`/`harmless`
detection counts). A weighted risk score
(`0.40*severity + 0.40*abuse_score + 0.20*min(vt_malicious*10,100)`) is
computed and bucketed into Low/Medium/High/Critical risk levels
(Sections 41-42).

## 7. Security Testing (Part D)

Six automated tests in `security_addon/security_tests.py` (see the
Security Testing Matrix deliverable for full Objective/Procedure/Expected/
Actual/Evidence write-ups):

1. Brute-force detector accuracy (false-negative check)
2. SQL-injection detector coverage
3. Log/evidence integrity tamper detection
4. RBAC enforcement (analyst denied admin action)
5. Hardcoded-secrets regression scan
6. Backup & recovery validation (simulated DB corruption)

## 8. Limitations Encountered

- Free-tier AbuseIPDB/VirusTotal rate limits (VT: ~4 req/min) mean full
  enrichment of all suspicious IPs takes several minutes with the required
  `time.sleep(2)` throttle - not viable for real-time use at scale.
- SQLite has no native user/role system, which is why access control had to
  be implemented at the application layer rather than the database layer -
  an enterprise deployment should move this into PostgreSQL with actual
  database roles and row-level security.
- The dataset is synthetic; detection thresholds (e.g. ">=5 failed logins")
  were tuned to this generator's attack parameters and would need
  recalibration against real traffic to avoid false positives.
