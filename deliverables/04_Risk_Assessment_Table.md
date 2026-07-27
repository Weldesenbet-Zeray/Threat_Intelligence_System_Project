# Risk Assessment Table

| # | Risk | Impact | Likelihood | Current Control | Residual Risk | Recommended Improvement |
|---|---|---|---|---|---|---|
| 1 | API keys hardcoded in notebook source (found in original build) | High — credential leak, quota abuse, potential pivot to attacker's own VT/AbuseIPDB account | Was Certain (already occurred) | Fixed: `.env` + `python-dotenv`, keys rotated | Low | Add a pre-commit secret-scanner (e.g. `gitleaks`) to prevent recurrence |
| 2 | Unauthorized read/write access to `threat_intelligence.db` | High — tampering with detection results or the investigation report | Medium (any local user/process can open the SQLite file) | Application-layer RBAC (`access_control.py`) | Medium — SQLite has no OS-level enforcement of this | Migrate to PostgreSQL with real DB roles + row-level security |
| 3 | Undetected tampering with logs/evidence between generation and grading/audit | Medium — undermines evidentiary integrity of the whole investigation | Low-Medium | SHA-256 manifest + `integrity_check.py` | Low | Sign the manifest with a keypair (not just a passphrase) for non-repudiation |
| 4 | Loss/corruption of the investigation database | Medium — loses detection history and enrichment work | Low | Timestamped backups (`backup_recovery.py`) | Low | Automate backups on a schedule; store off-machine (S3/MinIO) |
| 5 | Free-tier threat-intel API rate limits block timely enrichment during an active incident | Medium — delays classification of new suspicious IPs | Medium (hit constantly on free tier) | `time.sleep(2)` throttling, error handling returns `None` | Medium | Cache results, use a paid tier or a local threat-intel feed (e.g. MISP) for production use |
| 6 | Detection rules are static thresholds tuned to synthetic data | Medium — false negatives/positives against real traffic patterns | Medium | Six rule-based SQL detectors, manually validated (Tests 1-2) | Medium | Add anomaly-based/ML detection to complement static rules |
| 7 | No encryption of the SQLite file itself at rest (only ad-hoc file encryption available) | Medium — DB readable if the host is compromised | Medium | `secrets_manager.py` can encrypt exported files on demand, but the live `.db` is not encrypted at rest | Medium | Use SQLCipher (encrypted SQLite) or full-disk encryption on the host |
| 8 | Synthetic dataset may not represent real attacker behaviour / evasion techniques | Low-Medium — findings may not generalize | Certain (by design) | Documented as a limitation | Medium | Validate detectors against a real or well-known public log dataset before production use |

*Impact/Likelihood scale: Low / Medium / High. Fill in your own judgement calls for #5-8 based on your specific deployment context if presenting to a real client.*
