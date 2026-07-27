# Conclusion and Recommendations

## Vulnerabilities Identified
1. Hardcoded, plaintext threat-intelligence API keys in the analysis
   notebook — a genuine credential-leak vulnerability discovered during our
   own build, remediated via environment-variable secrets management, and
   now guarded by an automated regression test (Test 5).
2. No access control on the investigation database — any process with file
   access could read or modify detection results and the final report.
3. No integrity guarantee on exported evidence files — modification between
   generation and review would have gone unnoticed.
4. No backup/recovery path — a corrupted or deleted database would have
   meant re-running the entire multi-stage pipeline (dataset generation →
   detection → enrichment → scoring) from scratch.

## Remaining Risks
- Application-layer RBAC is not a substitute for real database-level access
  control; a sufficiently privileged local process can still bypass it.
- Free-tier API rate limits constrain how quickly new suspicious IPs can be
  enriched during a live incident.
- Detection thresholds are tuned to this synthetic dataset's attack
  parameters and have not been validated against real-world traffic.
- The live SQLite database file itself is not encrypted at rest (only
  exported copies can be encrypted on demand).

## Improvements Recommended for an Enterprise Deployment
1. **Move from SQLite to PostgreSQL** with native roles, row-level security,
   and TLS connections, so access control is enforced at the database layer
   rather than only in application code.
2. **Automate the response loop**: IPs reaching "Critical" risk score should
   trigger an automated firewall/WAF block rule rather than requiring a
   human to read the dashboard.
3. **Replace static SQL thresholds with a hybrid detection approach**
   (rule-based + anomaly/ML-based) to reduce both false positives and false
   negatives as attacker behaviour evolves.
4. **Adopt a paid or self-hosted threat-intelligence feed** (e.g. MISP, a
   paid AbuseIPDB/VirusTotal tier) to remove the rate-limit bottleneck
   during active incident response.
5. **Encrypt the database at rest** (SQLCipher or full-disk encryption) in
   addition to the current file-level encryption utility.
6. **Add a secret-scanning pre-commit hook** (e.g. `gitleaks` or
   `truffleHog`) so hardcoded credentials like the one we found cannot be
   reintroduced and pushed to a shared repository.
7. **Automate and off-host backups** (e.g. to MinIO/S3) instead of local
   timestamped copies, and schedule them rather than triggering manually.

## Lessons Learned
Building the environment ourselves surfaced a real security failure (the
hardcoded API keys) that a purely theoretical assignment would not have —
reinforcing that even a "just get the data pipeline working" prototype needs
secrets hygiene from the first line of code, not as an afterthought bolted
on before submission.
