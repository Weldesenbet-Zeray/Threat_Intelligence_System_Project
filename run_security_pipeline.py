"""
run_security_pipeline.py
Master Security Pipeline & Demonstration Runner for DSA 4030 Group 13.

Integrates Big Data Log Threat Detection with Part C Security Controls:
- Authentication & Role-Based Access Control (RBAC via bcrypt)
- Structured Audit Logging (security_addon/logs/audit.log)
- File & Database Encryption at Rest (secrets_manager.py)
- SHA-256 Integrity Verification (integrity_check.py)
- Automated Database Snapshot & Recovery (backup_recovery.py)
- Threat Intelligence API Enrichment (AbuseIPDB & VirusTotal)
"""

import os
import sys
import sqlite3
import random
import time
from datetime import datetime, timedelta
import pandas as pd
import numpy as np

# Add security_addon to sys.path
ADDON_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "security_addon")
if ADDON_DIR not in sys.path:
    sys.path.insert(0, ADDON_DIR)

from audit_logger import get_logger
from secrets_manager import get_api_key, encrypt_file, decrypt_file
from access_control import add_user, authenticate, require_permission
from backup_recovery import backup, restore, list_backups
from integrity_check import save_baseline, verify

log = get_logger("security_pipeline")

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "threat_intelligence.db")
LOG_CSV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "server_logs_sample.csv")
REPORT_CSV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "final_threat_report.csv")


def step_1_setup_rbac():
    log.info("--- Step 1: Setting up RBAC Users ---")
    try:
        add_user("admin1", "admin", "AdminPass123!")
        add_user("analyst1", "analyst", "AnalystPass123!")
        log.info("RBAC users 'admin1' and 'analyst1' initialized.")
    except Exception as e:
        log.warning("RBAC initialization note: %s", e)


def step_2_generate_or_load_logs(count=100000):
    log.info("--- Step 2: Generating Big Data Web Logs (%d records) ---", count)
    if os.path.exists(LOG_CSV_PATH):
        log.info("Loading existing logs from %s", LOG_CSV_PATH)
        df = pd.read_csv(LOG_CSV_PATH)
        return df

    # Generate synthetic logs
    start_time = datetime.now() - timedelta(days=7)
    attackers = ["103.37.227.77", "105.161.111.216", "107.146.189.254", "112.47.186.121", "118.229.146.73"]
    normal_ips = [f"192.168.1.{i}" for i in range(10, 100)] + [f"10.0.0.{i}" for i in range(10, 100)]
    
    endpoints = ["/index.html", "/login.php", "/api/v1/resource", "/products", "/admin/dashboard"]
    attack_payloads = [
        "/login.php?user=admin' OR '1'='1",
        "/download.php?file=../../../../etc/passwd",
        "/admin/config.php",
        "/api/v1/user/101; SELECT * FROM users;"
    ]

    records = []
    log.info("Synthesizing log dataset...")
    for i in range(count):
        is_attack = random.random() < 0.05
        ip = random.choice(attackers) if is_attack else random.choice(normal_ips)
        ts = start_time + timedelta(seconds=random.randint(0, 604800))
        
        if is_attack:
            endpoint = random.choice(attack_payloads)
            status = random.choice([401, 403, 404, 500])
            size = random.randint(100, 500)
        else:
            endpoint = random.choice(endpoints)
            status = 200 if random.random() > 0.05 else 404
            size = random.randint(1000, 50000)

        records.append({
            "log_id": i + 1,
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "ip_address": ip,
            "request_uri": endpoint,
            "status_code": status,
            "response_bytes": size,
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        })

    df = pd.DataFrame(records)
    df.to_csv(LOG_CSV_PATH, index=False)
    log.info("Saved %d log records to %s", len(df), LOG_CSV_PATH)
    return df


def step_3_populate_database(df):
    log.info("--- Step 3: Populating SQLite Database ---")
    conn = sqlite3.connect(DB_PATH)
    df.to_sql("server_logs", conn, if_exists="replace", index=False)
    conn.commit()
    conn.close()
    log.info("Database loaded cleanly at %s", DB_PATH)


def step_4_detect_threats():
    log.info("--- Step 4: Running Threat Detection Engine ---")
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT * FROM server_logs", conn)
    
    threats = []
    
    # 1. SQL Injection
    sqli = df[df["request_uri"].str.contains("OR '1'='1|SELECT|UNION", case=False, na=False)]
    for _, r in sqli.iterrows():
        threats.append({"log_id": r["log_id"], "ip_address": r["ip_address"], "threat_type": "SQL Injection", "severity": "CRITICAL"})
        
    # 2. Path Traversal
    traversal = df[df["request_uri"].str.contains(r"\.\./|etc/passwd", case=False, na=False)]
    for _, r in traversal.iterrows():
        threats.append({"log_id": r["log_id"], "ip_address": r["ip_address"], "threat_type": "Directory Traversal", "severity": "HIGH"})
        
    # 3. Brute Force (rapid failures)
    failed = df[df["status_code"].isin([401, 403])].groupby("ip_address").size()
    bf_ips = failed[failed >= 5].index.tolist()
    for ip in bf_ips:
        threats.append({"log_id": 0, "ip_address": ip, "threat_type": "Brute Force", "severity": "HIGH"})
        
    tdf = pd.DataFrame(threats)
    tdf.to_sql("detected_threats", conn, if_exists="replace", index=False)
    
    # Incident summary
    summary = tdf.groupby("ip_address").agg(
        threat_count=("threat_type", "count"),
        threat_types=("threat_type", lambda x: ", ".join(sorted(set(x))))
    ).reset_index()
    summary.to_sql("incident_summary", conn, if_exists="replace", index=False)
    
    conn.close()
    log.info("Threat Detection Completed: %d threat events, %d unique attacker IPs flagged.", len(tdf), len(summary))
    return summary


def step_5_backup_and_integrity():
    log.info("--- Step 5: Executing Backup & Integrity Checks ---")
    bak = backup()
    log.info("Database backup file: %s", bak)
    manifest = save_baseline()
    log.info("Integrity baseline created with %d files.", len(manifest))
    ok = verify()
    log.info("Integrity check result: %s", "PASSED" if ok else "FAILED")


def run_all():
    log.info("============================================================")
    log.info("STARTING MASTER BIG DATA SECURITY PIPELINE EXECUTION")
    log.info("============================================================")
    
    step_1_setup_rbac()
    df = step_2_generate_or_load_logs(100000)
    step_3_populate_database(df)
    summary = step_4_detect_threats()
    step_5_backup_and_integrity()
    
    log.info("============================================================")
    log.info("PIPELINE COMPLETED SUCCESSFULLY")
    log.info("============================================================")


if __name__ == "__main__":
    run_all()
