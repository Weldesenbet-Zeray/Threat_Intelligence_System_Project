"""
access_control.py
Part C controls: Authentication + Role-Based Access Control (RBAC).

The raw threat_intelligence.db (server_logs, threat_intelligence,
final_threat_report tables) currently has no access control at all - anyone
who opens the file can read or edit anything. This module puts a thin,
role-aware gate in front of it:

  - "analyst" role : read-only access to detection/report tables.
  - "admin"    role : read-write access, including running the enrichment
                      and exporting the final report.

Passwords are stored as salted bcrypt hashes (users.json), never plaintext.

Usage:
    python access_control.py adduser analyst1 analyst
    python access_control.py adduser admin1 admin
    python access_control.py login analyst1
"""

import getpass
import json
import os
import sys

import bcrypt

from audit_logger import get_logger

log = get_logger("access_control")

USERS_PATH = os.path.join(os.path.dirname(__file__), "users.json")

ROLE_PERMISSIONS = {
    "analyst": {"read_reports", "read_logs"},
    "admin": {"read_reports", "read_logs", "run_enrichment", "export_report", "manage_users"},
}


def _load_users() -> dict:
    if not os.path.exists(USERS_PATH):
        return {}
    with open(USERS_PATH, encoding="utf-8") as f:
        return json.load(f)


def _save_users(users: dict):
    with open(USERS_PATH, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)


def add_user(username: str, role: str, password: str = None):
    if role not in ROLE_PERMISSIONS:
        raise ValueError(f"Unknown role '{role}'. Valid roles: {list(ROLE_PERMISSIONS)}")

    password = password or getpass.getpass(f"Set password for {username}: ")
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    users = _load_users()
    users[username] = {"role": role, "password_hash": hashed}
    _save_users(users)

    log.info("User created: username=%s role=%s", username, role)
    print(f"User '{username}' created with role '{role}'.")


def authenticate(username: str, password: str = None) -> dict | None:
    """Return {'username':..., 'role':..., 'permissions':...} or None on failure."""
    users = _load_users()
    record = users.get(username)

    password = password or getpass.getpass(f"Password for {username}: ")

    if not record or not bcrypt.checkpw(password.encode(), record["password_hash"].encode()):
        log.warning("AUTH FAILED for username=%s", username)
        return None

    log.info("AUTH SUCCESS for username=%s role=%s", username, record["role"])
    return {
        "username": username,
        "role": record["role"],
        "permissions": ROLE_PERMISSIONS[record["role"]],
    }


def require_permission(session: dict, permission: str):
    """Raise PermissionError if the authenticated session lacks `permission`."""
    if not session or permission not in session.get("permissions", set()):
        log.warning(
            "ACCESS DENIED user=%s permission=%s",
            session.get("username") if session else "anonymous",
            permission,
        )
        raise PermissionError(f"Permission denied: '{permission}' requires a higher role.")
    log.info("ACCESS GRANTED user=%s permission=%s", session["username"], permission)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:\n  python access_control.py adduser <username> <role>\n  python access_control.py login <username>")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "adduser":
        add_user(sys.argv[2], sys.argv[3])
    elif cmd == "login":
        session = authenticate(sys.argv[2])
        if session:
            print(f"Login OK. Role={session['role']} Permissions={sorted(session['permissions'])}")
        else:
            print("Login failed.")
    else:
        print(f"Unknown command: {cmd}")
