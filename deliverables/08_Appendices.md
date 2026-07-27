# Deliverable 8: Appendices & Code Listings

**Project Title**: Threat Intelligence Investigation and Big Data Security Hardening  
**Course**: DSA 4030 - Big Data Security (Group 13)  

---

## Appendix A: Project Directory Structure

```
c:\School_projects\DSA_4030\
├── BDS_TI_Project.ipynb                 # Master Jupyter Notebook
├── DSA4030_Group_Project.txt            # Project Assignment Specification
├── run_security_pipeline.py             # Automated Security Pipeline Execution Runner
├── server_logs_sample.csv               # Generated Big Data Access Log Dataset (100,000 rows)
├── threat_intelligence.db               # SQLite Big Data Database Warehouse
├── security_addon/                      # Part C Security Controls Modules
│   ├── .env                             # Local Encrypted Environment Variables (Secrets)
│   ├── .env.example                     # Environment Configuration Template
│   ├── access_control.py                # Authentication & bcrypt RBAC Module
│   ├── audit_logger.py                  # Centralized Rotating File Logger
│   ├── backup_recovery.py               # Timestamped Database Snapshot & Restore Utility
│   ├── integrity_check.py               # SHA-256 Baseline Manifest & Tamper Verification
│   ├── secrets_manager.py               # Fernet AES-256 Encryption & PBKDF2 Key Derivation
│   ├── manifest.json                    # Generated Cryptographic Hash Manifest
│   ├── users.json                       # Salted Hashed User Credentials Store
│   ├── backups/                         # Stored Database Snapshots (.bak)
│   └── logs/
│       └── audit.log                    # System Execution Audit Logs
└── deliverables/                        # Complete Written Project Submission Deliverables
    ├── 01_Executive_Summary.md
    ├── 02_System_Architecture.md
    ├── 03_Implementation_Report.md
    ├── 04_Security_Testing_Matrix.md
    ├── 05_Evidence_Portfolio.md
    ├── 06_Risk_Assessment_Table.md
    ├── 07_Conclusion_and_Recommendations.md
    ├── 08_Appendices.md
    ├── Complete_Project_Submission_Report.md
    └── Presentation_Deck_and_Script.md
```

---

## Appendix B: References & Citations

1. **AbuseIPDB API v2 Reference**: AbuseIPDB Developer Documentation. [https://www.abuseipdb.com/api](https://www.abuseipdb.com/api)
2. **VirusTotal v3 REST API**: VirusTotal Documentation. [https://docs.virustotal.com/reference/overview](https://docs.virustotal.com/reference/overview)
3. **NIST SP 800-30 Rev 1**: *Guide for Conducting Risk Assessments*. National Institute of Standards and Technology.
4. **OWASP Top 10 Web Application Security Risks**: OWASP Foundation. [https://owasp.org/www-project-top-ten/](https://owasp.org/www-project-top-ten/)
5. **Python Cryptography Standard**: Fernet Spec & PBKDF2 HMAC SHA-256 Key Derivation. [https://cryptography.io/](https://cryptography.io/)
6. **SQLite3 Documentation**: SQLite C-language Library & SQL Engine. [https://www.sqlite.org/docs.html](https://www.sqlite.org/docs.html)
