# 🛡️ Cyber Threat Intelligence Investigation System

> **DSA 4030 – Big Data Security**  
> **End-of-Semester Practical Group Project**  
> **Group 13 – Threat Intelligence Investigation**  
> **USIU-Africa**


Group    Members
1) Weldesenbet Zeray    670553    
2)  Lesala Monaheng     669218                                                                                                                          3)Branton Maungu Mumbua 668926    

---

# 📖 Project Overview

The **Cyber Threat Intelligence Investigation System** is an end-to-end cybersecurity solution designed to analyze web server logs, identify suspicious IP addresses, classify malicious activities, enrich detected threats using external threat intelligence platforms, calculate risk scores, and generate investigation reports for security analysts.

The project simulates a realistic web server environment by generating synthetic HTTP logs containing both normal user activity and multiple cyberattack scenarios.

---

# 🎯 Project Objectives

The objectives of this project are to:

- Generate realistic synthetic web server logs.
- Store logs in a SQLite database.
- Detect suspicious activities using rule-based threat detection.
- Investigate suspicious IP addresses using external Threat Intelligence APIs.
- Calculate risk scores for detected threats.
- Generate dashboards and investigation reports.
- Recommend security response actions based on identified threats.

---

# 🏗️ System Architecture

```text
                     Synthetic Web Logs
                             │
                             ▼
                  SQLite Database Storage
                             │
                             ▼
               Rule-Based Threat Detection
                             │
                             ▼
               Suspicious IP Identification
                             │
              ┌──────────────┴──────────────┐
              ▼                             ▼
        VirusTotal API               AbuseIPDB API
              │                             │
              └──────────────┬──────────────┘
                             ▼
                Threat Intelligence Enrichment
                             │
                             ▼
                  Risk Score Calculation
                             │
                             ▼
          Dashboard & Investigation Report
```

---

# 🛠️ Technologies Used

| Technology | Purpose |
|------------|---------|
| Python | Core implementation |
| Pandas | Data processing |
| NumPy | Numerical computation |
| SQLite | Log storage |
| Faker | Synthetic data generation |
| Matplotlib | Dashboard visualization |
| Requests | REST API communication |
| VirusTotal API | Threat intelligence enrichment |
| AbuseIPDB API | IP reputation lookup |

---

# 📂 Dataset

The dataset was generated synthetically using Python to simulate realistic web server activity.

## Dataset Summary

| Metric | Value |
|---------|------:|
| Total Log Records | **135,096** |
| Simulated Users | **2,500** |
| Simulated Attackers | **80** |
| Time Period | January – March 2026 |

---

# 🚨 Simulated Attack Types

The generated dataset contains the following cyberattack scenarios:

- Brute Force
- SQL Injection
- Directory Traversal
- Port Scan
- 404 Enumeration
- High Request Rate

These attacks are mixed with normal user traffic to simulate a realistic enterprise web server environment.

---

# 🔐 Security Controls Implemented

The project implements the following security controls:

- Web Server Logging
- SQLite Log Storage
- Rule-Based Threat Detection
- Threat Intelligence Enrichment
- Risk Scoring
- Investigation Reporting

---

# 🔍 Threat Detection Rules

The system detects six attack categories using predefined security rules.

| Attack Type | Detection Rule |
|--------------|----------------|
| Brute Force | Multiple failed login attempts |
| SQL Injection | SQL keywords detected in URLs |
| Directory Traversal | "../", ".env", "/etc/passwd" patterns |
| Port Scan | Multiple sensitive endpoint requests |
| 404 Enumeration | Excessive HTTP 404 responses |
| High Request Rate | Large number of requests within a short period |

---

# 🌍 Threat Intelligence Integration

## VirusTotal

VirusTotal is used to validate suspicious IP addresses using global cybersecurity intelligence.

Information collected includes:

- Malicious detections
- Suspicious detections
- Harmless detections
- Undetected status

---

## AbuseIPDB

AbuseIPDB provides reputation information about suspicious IP addresses.

Information collected includes:

- Abuse Confidence Score
- Country
- ISP
- Domain
- Number of abuse reports

---

# 📊 Risk Scoring

Each suspicious IP address is assigned a final risk score based on:

- Attack severity
- Number of suspicious events
- VirusTotal reputation
- AbuseIPDB reputation

The calculated score is used to prioritize security investigations.

---

# 📈 Project Results

## Dataset Statistics

| Metric | Value |
|---------|------:|
| Total Log Records | **135,096** |
| Simulated Users | **2,500** |
| Simulated Attackers | **80** |

---

## Threat Detection Summary

| Attack Type | Incidents | Events |
|--------------|----------:|-------:|
| 404 Enumeration | 48 | 931 |
| SQL Injection | 38 | 579 |
| Directory Traversal | 33 | 445 |
| Brute Force | 29 | 480 |
| Port Scan | 29 | 164 |
| High Request Rate | 1 | 105 |

---

## Threat Intelligence Summary

| Metric | Value |
|---------|------:|
| Detected Threat Events | **178** |
| Unique Incidents | **74** |
| Investigated IP Addresses | **74** |
| Highest Risk Score | **30.40** |
| Average Risk Score | **27.84** |

---

# ✅ Security Testing

The following security tests were successfully completed.

| Test | Status |
|------|--------|
| Dataset Generation | ✅ Passed |
| SQLite Database Storage | ✅ Passed |
| Rule-Based Threat Detection | ✅ Passed |
| VirusTotal Integration | ✅ Passed |
| AbuseIPDB Integration | ✅ Passed |
| Risk Scoring | ✅ Passed |
| Dashboard Generation | ✅ Passed |

---

# 📁 Project Structure

```text
Cyber-Threat-Intelligence/
│
├── notebooks/
│   └── Cyber_Threat_Intelligence.ipynb
│
├── data/
│   ├── synthetic_logs.csv
│   ├── threat_report.csv
│   └── cyber_logs.db
│
├── reports/
│   ├── investigation_report.csv
│   ├── dashboard.png
│   └── figures/
│
├── presentation/
│   └── Group13_Presentation.pptx
│
├── requirements.txt
├── README.md
└── LICENSE
```

---

# 🚀 Installation

## Clone the repository

```bash
git clone https://github.com/Weldesenbet-Zeray/Threat_Intelligence_System_Project.git
cd Threat_Intelligence_System_Project
```

## Install dependencies

```bash
pip install -r requirements.txt
```

---

# 🔑 Configure API Keys

Create a configuration file or define your API keys:

```python
VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_API_KEY"
```

---

# ▶️ Run the Project

Launch Jupyter Notebook:

```bash
jupyter notebook
```

Open the notebook and execute all cells from top to bottom.

---

# 🔮 Future Improvements

Possible future enhancements include:

- Interactive Streamlit dashboard
- Docker deployment
- Machine learning–based anomaly detection
- Real-time log streaming
- SIEM integration
- Additional Threat Intelligence sources
- Automated email and Slack alerts

---

# 📝 Conclusion

This project demonstrates a complete **Cyber Threat Intelligence Investigation System** that combines synthetic web server log generation, rule-based threat detection, external threat intelligence enrichment, risk assessment, and reporting.

By integrating **VirusTotal** and **AbuseIPDB**, the system enhances suspicious IP investigations with real-world threat intelligence, enabling more informed cybersecurity decision-making.

The modular design also provides a strong foundation for future extensions such as real-time monitoring, machine learning–based detection, and containerized deployment.

---

# 👨‍💻 Authors

**DSA 4030 – Big Data Security**  
**Group 13 – Threat Intelligence Investigation**  
**USIU-Africa**

---

# 📄 License

This project was developed for **academic purposes** as part of the DSA 4030 Big Data Security course at **USIU-Africa**.
