# 10-Minute Presentation Outline
**Group 13 — Threat Intelligence Investigation**

Target: ~1 minute/slide, 10 slides. Live demo required (no marks for
screenshots/prerecorded video per the assignment rules) — each numbered
slide below notes who should present it and what to demo live.

---

**Slide 1 — Title**
Group 13, DSA 4030, Threat Intelligence Investigation. Team member names +
role each will demo.

**Slide 2 — Scenario & Objective**
"Client's security team wants to investigate suspicious IPs in server
logs." State the 5 required tasks (collect logs, check IPs via free TI
sources, classify malicious activity, produce investigation report,
recommend response actions).

**Slide 3 — Architecture Diagram**
Show the system architecture artifact/diagram. Walk through the pipeline:
generation → SQLite → detection → enrichment → risk scoring → dashboard →
security controls wrapping the whole thing.

**Slide 4 — Dataset**
135k+ synthetic log records, 2,500 users, 80 attacker IPs, 5 attack
categories injected. Show `final_logs.head()` and the validation report
output live.

**Slide 5 — Threat Detection Engine (LIVE DEMO)**
Presenter runs the 6 SQL detectors live, shows `detected_threats` and
`incident_summary` populate in real time.

**Slide 6 — Threat Intelligence Enrichment & Risk Scoring (LIVE DEMO)**
Presenter shows a suspicious IP being enriched via AbuseIPDB/VirusTotal and
the resulting risk score/level, and the dashboard visualizations.

**Slide 7 — Security Controls (LIVE DEMO, one presenter per control)**
Each teammate runs their owned module from `security_addon/`:
encryption round-trip, RBAC login as analyst vs admin, integrity tamper
test, backup/corrupt/restore. Reference the ownership table in
`security_addon/README_SECURITY_ADDON.md`.

**Slide 8 — Security Testing Results (LIVE DEMO)**
Run `python security_tests.py` live (or show the last real run + walk
through 2-3 tests in detail) and present the Security Testing Matrix
summary (X/6 passed).

**Slide 9 — Risk Assessment & Vulnerability Found**
Highlight the real hardcoded-API-key vulnerability discovered in your own
build as the standout finding — graders respond well to a genuine "we broke
our own rule and caught it" story. Show the Risk Assessment Table.

**Slide 10 — Recommendations & Conclusion**
Top 3-4 enterprise improvements from `05_Conclusion_Recommendations.md`,
lessons learned, questions.

---

### Presenter prep checklist
- [ ] Notebook has been re-run end-to-end with rotated API keys (Step 0 in README)
- [ ] `security_tests.py` has been run at least once with real results in `test_results.json`
- [ ] Each teammate has personally run their assigned `security_addon/*.py` module before presenting
- [ ] Laptop/demo environment tested beforehand — live demo is mandatory, no recorded fallback for marks
