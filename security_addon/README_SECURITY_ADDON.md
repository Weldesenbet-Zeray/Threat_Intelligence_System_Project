# Security Add-On — Step-by-Step Guide

This folder adds everything your `BDS_TI_Project.ipynb` notebook was missing
against the DSA 4030 rubric (Group 13 — Threat Intelligence Investigation):
**Part C (Security Controls)** and **Part D (Security Testing)**. Your
notebook is untouched — this is a separate, importable add-on that operates
on the same `threat_intelligence.db` your notebook produces.

Do the steps **in this exact order**. Each step maps to a rubric requirement,
noted in brackets.

---

## Step 0 — Fix the leaked API keys first [urgent, do this before anything else]

Your notebook (Section 13, cell ~37) currently has:

```python
VT_API_KEY = "771bbc71647e34875c684078dddad24faffbaccfb25f46757be53a79ddeed140"
ABUSE_API_KEY = "92bc6d9e1f79b9c0b9da90bda48d7be9f3cf21696b80a6b5c195a68474069e507bbf3f4f69d4e555"
```

Anyone who receives this notebook (your lecturer, a grader, a classmate,
anything you upload to GitHub/Colab) gets your live keys. Treat both keys as
already compromised: **rotate/regenerate them now** at
virustotal.com/gui/my-apikey and abuseipdb.com/account/api, then replace the
cell above with:

```python
import sys
sys.path.append("../security_addon")   # adjust path if your notebook lives elsewhere
from secrets_manager import get_api_key

VT_API_KEY = get_api_key("VT_API_KEY")
ABUSE_API_KEY = get_api_key("ABUSE_API_KEY")
```

This is the only edit needed inside your notebook. Everything else below
lives in `security_addon/` and stays separate.

---

## Step 1 — Install dependencies

```bash
pip install -r security_addon/requirements.txt
```

## Step 2 — Configure your secrets

```bash
cd security_addon
cp .env.example .env
```

Open `.env` and fill in your **new, rotated** VT/AbuseIPDB keys plus a
`VAULT_PASSPHRASE` of your choosing (this passphrase encrypts things locally
— it never gets sent anywhere).

## Step 3 — Run your notebook

Run `BDS_TI_Project.ipynb` top to bottom as normal (with Step 0's fix
applied). Confirm `threat_intelligence.db`, `server_logs_sample.csv`,
`final_threat_report.csv`, and `users_pool.csv` now exist in the project
root (`c:\School_projects\DSA_4030\`).

## Step 4 — Prove encryption works [Part C: Encryption]

```bash
python secrets_manager.py
```

This self-encrypts/decrypts a throwaway file and verifies the round trip.
Take a screenshot of the "Round-trip verified: OK" line for your Evidence
Portfolio.

## Step 5 — Set up authentication + RBAC [Part C: Authentication, RBAC]

```bash
python access_control.py adduser admin1 admin
python access_control.py adduser analyst1 analyst
```

You'll be prompted to set a password for each. This creates
`security_addon/users.json` (bcrypt-hashed passwords only — never
plaintext). Try logging in as each:

```bash
python access_control.py login admin1
python access_control.py login analyst1
```

## Step 6 — Baseline file integrity [Part C: Integrity Verification]

```bash
python integrity_check.py baseline
python integrity_check.py verify
```

Second command should print `Integrity check: PASSED`. This is your
tamper-detection control — anyone who edits the DB or CSV exports after this
point will cause `verify` to fail.

## Step 7 — Take a backup [Part C: Backup and Recovery]

```bash
python backup_recovery.py backup
python backup_recovery.py list
```

## Step 8 — Run the audit logger once directly [Part C: Logging]

```bash
python audit_logger.py
```

Then open `security_addon/logs/audit.log` — this is your persisted,
timestamped audit trail (every module above writes to this same file).

## Step 9 — Run the 6 required security tests [Part D]

```bash
python security_tests.py
```

This runs all 6 tests end-to-end (brute-force accuracy, SQLi detection
coverage, tamper detection, RBAC enforcement, hardcoded-secrets regression
scan, backup/recovery). Results print to console **and** get saved to
`security_addon/test_results.json` — copy those straight into
`deliverables/03_Security_Testing_Matrix.md`.

> Test 5 (secrets scan) will only pass once Step 0's edit is actually applied
> to your notebook. If it fails, that's it correctly catching the original
> vulnerability — fix the notebook and re-run.

---

## What each file is, if a teammate needs to "own" and demo one piece

| File | Rubric control | What to demo live |
|---|---|---|
| `secrets_manager.py` | Encryption | Run it, show the round-trip, show `.env` is gitignored |
| `audit_logger.py` | Logging | Show `logs/audit.log` growing as other scripts run |
| `integrity_check.py` | Integrity verification | Baseline, tamper a file by hand, show `verify` catch it |
| `access_control.py` | Authentication + RBAC | Log in as analyst vs admin, show different permissions |
| `backup_recovery.py` | Backup and recovery | Corrupt the DB on camera, restore it, show data's back |
| `security_tests.py` | All of Part D | Run the full suite live, walk through 2-3 results |

Each teammate can independently run and narrate one row of this table during
the presentation, satisfying the "every member demonstrates a component
they personally configured or tested" rule.
