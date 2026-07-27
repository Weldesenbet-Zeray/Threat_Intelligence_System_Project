"""
backup_recovery.py
Part C control: Backup and recovery.

Takes timestamped backups of threat_intelligence.db and can restore the
most recent (or a specific) backup if the live database is lost, corrupted,
or tampered with. Pair this with integrity_check.py: if verify() reports
tampering, restore_latest() gets you back to a known-good state.

Usage:
    python backup_recovery.py backup
    python backup_recovery.py list
    python backup_recovery.py restore [backup_filename]
"""

import os
import shutil
import sys
from datetime import datetime

from audit_logger import get_logger

log = get_logger("backup_recovery")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # project root
DB_NAME = "threat_intelligence.db"
DB_PATH = os.path.join(BASE_DIR, DB_NAME)
BACKUP_DIR = os.path.join(os.path.dirname(__file__), "backups")

os.makedirs(BACKUP_DIR, exist_ok=True)


def backup() -> str:
    if not os.path.exists(DB_PATH):
        raise FileNotFoundError(f"{DB_PATH} does not exist - nothing to back up.")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dest = os.path.join(BACKUP_DIR, f"{DB_NAME}.{timestamp}.bak")
    shutil.copy2(DB_PATH, dest)
    log.info("Backup created: %s", dest)
    return dest


def list_backups() -> list:
    backups = sorted(
        f for f in os.listdir(BACKUP_DIR) if f.endswith(".bak")
    )
    return backups


def restore(backup_filename: str = None) -> str:
    backups = list_backups()
    if not backups:
        raise FileNotFoundError("No backups exist yet. Run 'backup' first.")

    chosen = backup_filename or backups[-1]  # latest by lexical/timestamp sort
    src = os.path.join(BACKUP_DIR, chosen)

    if not os.path.exists(src):
        raise FileNotFoundError(f"Backup not found: {chosen}")

    shutil.copy2(src, DB_PATH)
    log.info("Database restored from backup: %s", chosen)
    return chosen


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "list"

    if action == "backup":
        path = backup()
        print(f"Backup saved to: {path}")
    elif action == "list":
        for b in list_backups():
            print(b)
    elif action == "restore":
        fname = sys.argv[2] if len(sys.argv) > 2 else None
        restored = restore(fname)
        print(f"Restored from: {restored}")
    else:
        print("Usage: python backup_recovery.py [backup|list|restore <filename>]")
