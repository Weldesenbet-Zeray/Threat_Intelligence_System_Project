"""
integrity_check.py
Part C control: Integrity verification.

Generates a SHA-256 manifest for the project's critical evidence files
(the SQLite DB, the CSV exports) and later verifies that none of them have
been altered since the manifest was created. This is what proves your logs
and reports weren't tampered with between generation and grading.

Usage:
    python integrity_check.py baseline   # create manifest.json
    python integrity_check.py verify     # compare current hashes vs manifest
"""

import hashlib
import json
import os
import sys

from audit_logger import get_logger

log = get_logger("integrity")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # project root
MANIFEST_PATH = os.path.join(os.path.dirname(__file__), "manifest.json")

WATCHED_FILES = [
    "threat_intelligence.db",
    "server_logs_sample.csv",
    "final_threat_report.csv",
    "users_pool.csv",
]


def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def build_manifest() -> dict:
    manifest = {}
    for fname in WATCHED_FILES:
        path = os.path.join(BASE_DIR, fname)
        if os.path.exists(path):
            manifest[fname] = sha256_of(path)
        else:
            log.warning("File not found while baselining: %s", fname)
    return manifest


def save_baseline():
    manifest = build_manifest()
    with open(MANIFEST_PATH, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    log.info("Baseline manifest written for %d files -> %s", len(manifest), MANIFEST_PATH)
    return manifest


def verify() -> bool:
    if not os.path.exists(MANIFEST_PATH):
        log.error("No manifest found. Run 'baseline' first.")
        return False

    with open(MANIFEST_PATH, encoding="utf-8") as f:
        baseline = json.load(f)

    all_ok = True
    for fname, expected_hash in baseline.items():
        path = os.path.join(BASE_DIR, fname)
        if not os.path.exists(path):
            log.error("MISSING file that was in baseline: %s", fname)
            all_ok = False
            continue

        actual_hash = sha256_of(path)
        if actual_hash == expected_hash:
            log.info("OK    %s matches baseline hash", fname)
        else:
            log.error("TAMPERED %s hash changed! expected=%s actual=%s",
                       fname, expected_hash[:12], actual_hash[:12])
            all_ok = False

    return all_ok


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "verify"

    if action == "baseline":
        save_baseline()
    elif action == "verify":
        ok = verify()
        print("\nIntegrity check:", "PASSED" if ok else "FAILED - see log above")
    else:
        print("Usage: python integrity_check.py [baseline|verify]")
