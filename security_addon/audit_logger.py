"""
audit_logger.py
Part C control: Logging capability.

The original notebook only used print() statements, which disappear once the
kernel closes and prove nothing to an auditor. This module writes a real,
timestamped, rotating audit trail to disk (security_addon/logs/audit.log)
and is what the "Logging" row of the Risk Assessment Table / Testing Matrix
should point to as evidence.

Usage:
    from audit_logger import get_logger
    log = get_logger("threat_intel")
    log.info("Started IP enrichment run")
    log.warning("AbuseIPDB returned rate-limit (429) for 1.2.3.4")
"""

import logging
import os
from logging.handlers import RotatingFileHandler

LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
LOG_FILE = os.path.join(LOG_DIR, "audit.log")

os.makedirs(LOG_DIR, exist_ok=True)


def get_logger(name: str = "app") -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger  # avoid duplicate handlers on repeated calls

    logger.setLevel(logging.INFO)

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = RotatingFileHandler(
        LOG_FILE, maxBytes=2_000_000, backupCount=5, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger


if __name__ == "__main__":
    log = get_logger("selftest")
    log.info("Audit logger self-test entry")
    print(f"\nWrote a test entry to: {LOG_FILE}")
    print("Open that file to confirm the entry was persisted.")
