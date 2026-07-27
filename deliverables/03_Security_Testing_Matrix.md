# Security Testing Matrix

All six tests are automated in `security_addon/security_tests.py`. Run it
with `python security_tests.py` after completing Steps 0-8 in
`security_addon/README_SECURITY_ADDON.md`, then paste your console output /
`test_results.json` values into the **Actual Result** and **Evidence**
columns below (placeholders shown in *italics*).

---

### Test 1 — Brute Force Detector Accuracy
- **Objective:** Confirm the brute-force detector flags every IP with ≥5 failed `/login` attempts (no false negatives).
- **Procedure:** Recompute failed-login counts per IP directly from `server_logs`; compare against `detected_threats` rows where `threat_type='Brute Force'`.
- **Expected Result:** Zero missed IPs — every qualifying IP is flagged.
- **Actual Result:** *paste `T1` actual value from `test_results.json`*
- **Evidence:** *console output screenshot + `logs/audit.log` line `TEST T1 -> PASS`*

### Test 2 — SQL Injection Detector Coverage
- **Objective:** Confirm the SQLi detector catches 100% of synthetically injected SQL-injection attack sessions.
- **Procedure:** Compare IPs labelled `attack_type='SQL Injection'` in `server_logs` against IPs captured by the SQLi rule in `detected_threats`.
- **Expected Result:** Zero missed IPs.
- **Actual Result:** *paste `T2` actual value*
- **Evidence:** *screenshot of test output*

### Test 3 — Log/Evidence Integrity Tamper Detection
- **Objective:** Confirm that modifying an evidence file after baselining is detected via SHA-256 mismatch.
- **Procedure:** Baseline hashes → append a byte to `server_logs_sample.csv` → re-run `verify()` → restore the file → re-run `verify()`.
- **Expected Result:** `verify()` returns `False` while tampered, `True` after restore.
- **Actual Result:** *paste `T3` actual value*
- **Evidence:** *`manifest.json` + `TAMPERED` log line + restored `PASSED` log line*

### Test 4 — RBAC Enforcement
- **Objective:** Confirm an `analyst`-role account cannot perform admin-only actions.
- **Procedure:** Authenticate as a temporary analyst; attempt `run_enrichment` (admin-only) and `read_reports` (allowed).
- **Expected Result:** Admin-only action denied (`PermissionError`); read-only action allowed.
- **Actual Result:** *paste `T4` actual value*
- **Evidence:** *`ACCESS DENIED` / `ACCESS GRANTED` log lines*

### Test 5 — Hardcoded Secrets Regression Scan
- **Objective:** Confirm no plaintext API keys/secrets remain hardcoded anywhere in the project source.
- **Procedure:** Regex-scan all `.py`/`.ipynb` files for `*_API_KEY = "<long literal>"` style patterns.
- **Expected Result:** Zero hardcoded secrets found (this test fails against the *original*, unfixed notebook — that's the point).
- **Actual Result:** *paste `T5` actual value*
- **Evidence:** *before/after: run once before applying Step 0's fix (should FAIL), once after (should PASS)*

### Test 6 — Backup & Recovery Validation
- **Objective:** Confirm the investigation database can be fully recovered after simulated corruption.
- **Procedure:** Record row count → back up DB → overwrite DB with garbage bytes → restore latest backup → re-check row count.
- **Expected Result:** Row count after restore equals row count before corruption.
- **Actual Result:** *paste `T6` actual value*
- **Evidence:** *backup filename + before/after row counts from console output*

---

## Optional 7th test (manual, not automated — good bonus for the demo)

**Threat Intelligence Accuracy Spot-Check**
- **Objective:** Sanity-check that the AbuseIPDB/VirusTotal enrichment correctly distinguishes a known-clean IP from a known-suspicious one.
- **Procedure:** Manually call `check_abuseipdb()`/`check_virustotal()` on a well-known clean IP (e.g. `8.8.8.8`) and compare its score to one of your flagged attacker IPs.
- **Expected Result:** Clean IP scores near 0; flagged attacker IP scores meaningfully higher.
- **Evidence:** side-by-side printed comparison.
