"""
security_tests.py
Part D: Security Testing (minimum six tests required by the rubric).

Run AFTER:
  1. You have executed BDS_TI_Project.ipynb at least once, so
     threat_intelligence.db / server_logs_sample.csv exist in the project root.
  2. You have created security_addon/.env from .env.example.
  3. You have run:  python access_control.py adduser analyst1 analyst
                     python access_control.py adduser admin1 admin

Each test prints Objective / Procedure / Expected / Actual / Result, and
appends a row to security_addon/logs/audit.log (your evidence trail).
Results are also written to security_addon/test_results.json so you can
paste them straight into the Security Testing Matrix deliverable.

Usage:
    python security_tests.py
"""

import json
import os
import re
import sqlite3
import sys
import time

from audit_logger import get_logger
from access_control import add_user, authenticate, require_permission, USERS_PATH
from integrity_check import save_baseline, verify as verify_integrity, MANIFEST_PATH
import backup_recovery as br

log = get_logger("security_tests")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "threat_intelligence.db")

results = []


def record(test_id, objective, procedure, expected, actual, passed, evidence):
    entry = {
        "test_id": test_id,
        "objective": objective,
        "procedure": procedure,
        "expected": expected,
        "actual": actual,
        "result": "PASS" if passed else "FAIL",
        "evidence": evidence,
    }
    results.append(entry)
    log.info("TEST %s -> %s | %s", test_id, entry["result"], objective)
    print("\n" + "=" * 70)
    print(f"TEST {test_id}: {objective}")
    print("-" * 70)
    print(f"Procedure : {procedure}")
    print(f"Expected  : {expected}")
    print(f"Actual    : {actual}")
    print(f"Result    : {entry['result']}")
    print(f"Evidence  : {evidence}")


def need_db():
    if not os.path.exists(DB_PATH):
        raise FileNotFoundError(
            "threat_intelligence.db not found. Run BDS_TI_Project.ipynb first."
        )
    return sqlite3.connect(DB_PATH)


# ------------------------------------------------------------
# TEST 1 - Brute Force Detector Accuracy
# ------------------------------------------------------------
def test_1_brute_force_accuracy():
    objective = "Confirm the brute-force detector flags only IPs with >=5 failed /login attempts."
    procedure = ("Recompute failed-login counts per IP directly from server_logs "
                 "and compare against the detected_threats table's 'Brute Force' rows.")
    try:
        conn = need_db()
        raw = conn.execute("""
            SELECT ip_address, COUNT(*) AS failed
            FROM server_logs
            WHERE endpoint='/login' AND status_code=401
            GROUP BY ip_address
            HAVING COUNT(*) >= 5
        """).fetchall()
        raw_ips = {row[0] for row in raw}

        detected = conn.execute("""
            SELECT ip_address FROM detected_threats WHERE threat_type='Brute Force'
        """).fetchall()
        detected_ips = {row[0] for row in detected}
        conn.close()

        missing = raw_ips - detected_ips
        passed = len(missing) == 0 and len(raw_ips) > 0
        actual = (f"{len(raw_ips)} IPs qualify by raw count, "
                  f"{len(detected_ips)} were flagged, {len(missing)} missed.")
        evidence = f"Missed IPs (should be empty): {sorted(missing)[:5]}"
        record("T1", objective, procedure,
               "Zero false negatives - every qualifying IP is flagged.",
               actual, passed, evidence)
    except Exception as exc:
        record("T1", objective, procedure, "Detector matches raw counts.",
               f"SKIPPED - {exc}", False, "N/A")


# ------------------------------------------------------------
# TEST 2 - SQL Injection Detector Coverage
# ------------------------------------------------------------
def test_2_sqli_detection_coverage():
    objective = "Confirm the SQLi detector catches all synthetic SQL-injection attack sessions."
    procedure = ("Compare IPs labelled attack_type='SQL Injection' in server_logs "
                 "against IPs captured by the SQLi rule in detected_threats.")
    try:
        conn = need_db()
        injected = conn.execute("""
            SELECT DISTINCT ip_address FROM server_logs WHERE attack_type='SQL Injection'
        """).fetchall()
        injected_ips = {row[0] for row in injected}

        detected = conn.execute("""
            SELECT DISTINCT ip_address FROM detected_threats WHERE threat_type='SQL Injection'
        """).fetchall()
        detected_ips = {row[0] for row in detected}
        conn.close()

        missing = injected_ips - detected_ips
        passed = len(missing) == 0 and len(injected_ips) > 0
        actual = f"{len(injected_ips)} injected, {len(detected_ips)} detected, {len(missing)} missed."
        evidence = f"Missed IPs: {sorted(missing)[:5]}"
        record("T2", objective, procedure,
               "100% of injected SQLi sessions are detected.",
               actual, passed, evidence)
    except Exception as exc:
        record("T2", objective, procedure, "Detector matches injected attacks.",
               f"SKIPPED - {exc}", False, "N/A")


# ------------------------------------------------------------
# TEST 3 - Log/Evidence Integrity Tamper Detection
# ------------------------------------------------------------
def test_3_integrity_tamper_detection():
    objective = "Confirm tampering with an evidence file is detected via SHA-256 manifest mismatch."
    procedure = ("Baseline current file hashes, append a byte to server_logs_sample.csv, "
                 "re-run verification, then restore the file to its original content.")
    csv_path = os.path.join(BASE_DIR, "server_logs_sample.csv")
    try:
        if not os.path.exists(csv_path):
            raise FileNotFoundError("server_logs_sample.csv not found - run the notebook first.")

        save_baseline()
        clean_before = verify_integrity()

        with open(csv_path, "a", encoding="utf-8") as f:
            f.write("tamper-test-row\n")

        tampered_result = verify_integrity()

        # restore original content
        with open(csv_path, encoding="utf-8") as f:
            lines = f.readlines()
        with open(csv_path, "w", encoding="utf-8") as f:
            f.writelines(lines[:-1])

        restored_ok = verify_integrity()

        passed = clean_before and (not tampered_result) and restored_ok
        actual = (f"clean_baseline={clean_before}, after_tamper={tampered_result} "
                  f"(should be False), after_restore={restored_ok}")
        evidence = f"Manifest: {MANIFEST_PATH}; see audit.log for TAMPERED entries."
        record("T3", objective, procedure,
               "Tamper is detected (verify()==False) then resolved after restore.",
               actual, passed, evidence)
    except Exception as exc:
        record("T3", objective, procedure, "Tamper is detected.",
               f"SKIPPED - {exc}", False, "N/A")


# ------------------------------------------------------------
# TEST 4 - RBAC Enforcement
# ------------------------------------------------------------
def test_4_rbac_enforcement():
    objective = "Confirm an 'analyst' account cannot perform admin-only actions (RBAC)."
    procedure = ("Create/authenticate a temporary analyst user, then attempt an "
                 "admin-only permission ('run_enrichment') and expect a denial.")
    try:
        add_user("_test_analyst", "analyst", password="TestPass123!")
        session = authenticate("_test_analyst", password="TestPass123!")

        denied = False
        try:
            require_permission(session, "run_enrichment")
        except PermissionError:
            denied = True

        allowed_read = False
        try:
            require_permission(session, "read_reports")
            allowed_read = True
        except PermissionError:
            pass

        passed = denied and allowed_read
        actual = f"admin-only action denied={denied}, read-only action allowed={allowed_read}"
        evidence = "See 'ACCESS DENIED' / 'ACCESS GRANTED' entries in logs/audit.log"
        record("T4", objective, procedure,
               "Admin-only action is denied; read-only action is allowed.",
               actual, passed, evidence)

        # cleanup temp user
        if os.path.exists(USERS_PATH):
            with open(USERS_PATH, encoding="utf-8") as f:
                users = json.load(f)
            users.pop("_test_analyst", None)
            with open(USERS_PATH, "w", encoding="utf-8") as f:
                json.dump(users, f, indent=2)
    except Exception as exc:
        record("T4", objective, procedure, "RBAC blocks unauthorized action.",
               f"SKIPPED - {exc}", False, "N/A")


# ------------------------------------------------------------
# TEST 5 - Hardcoded Secrets Regression Scan
# ------------------------------------------------------------
def test_5_secrets_exposure_scan():
    objective = "Confirm no plaintext API keys remain hardcoded in project source files."
    procedure = ("Scan .py and .ipynb files for variable assignments named like "
                 "*API_KEY* / *SECRET* / *PASSWORD* followed by a long literal string.")
    pattern = re.compile(
        r'(API_KEY|SECRET|PASSWORD|TOKEN)\s*=\s*["\'][A-Za-z0-9_\-]{16,}["\']'
    )
    hits = []
    try:
        for root, _, files in os.walk(BASE_DIR):
            if "security_addon" in root or ".git" in root:
                continue
            for fname in files:
                if fname.endswith((".py", ".ipynb")):
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                    except Exception:
                        continue
                    for match in pattern.finditer(content):
                        hits.append((fname, match.group(0)[:40] + "..."))

        passed = len(hits) == 0
        actual = f"{len(hits)} hardcoded-looking secret(s) found."
        evidence = str(hits[:5]) if hits else "None found."
        record("T5", objective, procedure,
               "Zero hardcoded secrets in source files.",
               actual, passed, evidence)
    except Exception as exc:
        record("T5", objective, procedure, "No hardcoded secrets.",
               f"SKIPPED - {exc}", False, "N/A")


# ------------------------------------------------------------
# TEST 6 - Backup & Recovery Validation
# ------------------------------------------------------------
def test_6_backup_recovery():
    objective = "Confirm the database can be fully recovered after simulated loss/corruption."
    procedure = ("Record the row count, take a backup, corrupt the live DB file, "
                 "restore from backup, then re-check the row count matches.")
    try:
        if not os.path.exists(DB_PATH):
            raise FileNotFoundError("threat_intelligence.db not found - run the notebook first.")

        conn = sqlite3.connect(DB_PATH)
        before_count = conn.execute("SELECT COUNT(*) FROM server_logs").fetchone()[0]
        conn.close()

        backup_path = br.backup()

        # simulate corruption
        with open(DB_PATH, "wb") as f:
            f.write(b"CORRUPTED_FOR_TEST")

        br.restore(os.path.basename(backup_path))

        conn = sqlite3.connect(DB_PATH)
        after_count = conn.execute("SELECT COUNT(*) FROM server_logs").fetchone()[0]
        conn.close()

        passed = before_count == after_count and before_count > 0
        actual = f"before={before_count:,} rows, after_restore={after_count:,} rows"
        evidence = f"Backup used: {backup_path}"
        record("T6", objective, procedure,
               "Row count after restore equals row count before corruption.",
               actual, passed, evidence)
    except Exception as exc:
        record("T6", objective, procedure, "Full recovery after corruption.",
               f"SKIPPED - {exc}", False, "N/A")


if __name__ == "__main__":
    print("=" * 70)
    print("RUNNING SECURITY TEST SUITE (Part D - 6 required tests)")
    print("=" * 70)

    test_1_brute_force_accuracy()
    test_2_sqli_detection_coverage()
    test_3_integrity_tamper_detection()
    test_4_rbac_enforcement()
    test_5_secrets_exposure_scan()
    test_6_backup_recovery()

    out_path = os.path.join(os.path.dirname(__file__), "test_results.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    passed_count = sum(1 for r in results if r["result"] == "PASS")
    print("\n" + "=" * 70)
    print(f"SUMMARY: {passed_count}/{len(results)} tests passed")
    print(f"Full results written to: {out_path}")
    print("=" * 70)
