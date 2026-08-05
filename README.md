# 🛡️ Cyber Threat Intelligence Investigation System

> **DSA 4030 – Big Data Security**
> **End-of-Semester Practical Group Project**
> **Group 13 – Threat Intelligence Investigation**
> **USIU-Africa**

---

# 📖 Project Overview

The **Cyber Threat Intelligence Investigation System** is an end-to-end cybersecurity solution for investigating suspicious activities from web server logs.

The system simulates realistic enterprise web traffic, detects malicious behavior using rule-based techniques, enriches suspicious IP addresses with external Threat Intelligence services, calculates risk scores, and generates investigation reports for security analysts.

---

# 🎯 Project Objectives

* Generate realistic synthetic web server logs
* Store logs in SQLite
* Detect suspicious activities using rule-based analytics
* Investigate suspicious IPs using VirusTotal and AbuseIPDB
* Calculate investigation risk scores
* Produce dashboards and investigation reports
* Recommend appropriate security responses

---

# 🏗️ System Architecture

```text
Synthetic Web Logs
        │
        ▼
SQLite Database
        │
        ▼
Rule-Based Threat Detection
        │
        ▼
Suspicious IP Identification
        │
 ┌──────┴──────┐
 ▼             ▼
VirusTotal   AbuseIPDB
 └──────┬──────┘
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

| Technology     | Purpose                   |
| -------------- | ------------------------- |
| Python         | Core implementation       |
| Pandas         | Data processing           |
| NumPy          | Numerical computing       |
| SQLite         | Database storage          |
| Faker          | Synthetic data generation |
| Matplotlib     | Data visualization        |
| Requests       | REST API communication    |
| VirusTotal API | Threat intelligence       |
| AbuseIPDB API  | IP reputation lookup      |

---

# 📂 Repository Structure

```text
Threat_Intelligence_System_Project
├── data/
│   ├── server_logs_sample.csv
│   └── users_pool.csv
│
├── deliverable/
│   ├── BDS_Group13_Project_Report.pdf
│   └── Group13_Cyber_Threat_Intelligence_Presentation.pptx
│
├── BDS_TI_Project.ipynb
└── README.md
```

### Repository Contents

| Path                                                                                                                                   | Description                                                  |
| -------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| [`data/`](./data/)                                                                                                                     | Project datasets used during the investigation               |
| [`data/server_logs_sample.csv`](./data/server_logs_sample.csv)                                                                         | Sample synthetic web server logs                             |
| [`data/users_pool.csv`](./data/users_pool.csv)                                                                                         | Simulated user information                                   |
| [`deliverable/`](./deliverable/)                                                                                                       | Final project deliverables                                   |
| [`deliverable/BDS_Group13_Project_Report.pdf`](./deliverable/BDS_Group13_Project_Report.pdf)                                           | Final written report                                         |
| [`deliverable/Group13_Cyber_Threat_Intelligence_Presentation.pptx`](./deliverable/Group13_Cyber_Threat_Intelligence_Presentation.pptx) | Project presentation slides                                  |
| [`BDS_TI_Project.ipynb`](./BDS_TI_Project.ipynb)                                                                                       | Main Jupyter Notebook containing the complete implementation |
| [`README.md`](./README.md)                                                                                                             | Project documentation                                        |

---

# 📊 Dataset Summary

| Metric              |                Value |
| ------------------- | -------------------: |
| Total Log Records   |          **135,096** |
| Simulated Users     |            **2,500** |
| Simulated Attackers |               **80** |
| Time Period         | January – March 2026 |

---

# 🚨 Simulated Attack Types

The dataset contains multiple cyberattack scenarios mixed with normal web traffic.

* Brute Force
* SQL Injection
* Directory Traversal
* Port Scan
* HTTP 404 Enumeration
* High Request Rate

---

# 🔐 Security Controls

* Web Server Logging
* SQLite Log Storage
* Rule-Based Threat Detection
* Threat Intelligence Enrichment
* Risk Scoring
* Investigation Reporting

---

# 🔍 Threat Detection Rules

| Attack               | Detection Logic                          |
| -------------------- | ---------------------------------------- |
| Brute Force          | Multiple failed login attempts           |
| SQL Injection        | SQL keywords detected in request URLs    |
| Directory Traversal  | "../", ".env", "/etc/passwd" patterns    |
| Port Scan            | Multiple requests to sensitive endpoints |
| HTTP 404 Enumeration | Excessive HTTP 404 responses             |
| High Request Rate    | Abnormally high request volume           |

---

# 🌍 Threat Intelligence Sources

## VirusTotal

Information collected includes:

* Malicious detections
* Suspicious detections
* Harmless detections
* Undetected status

## AbuseIPDB

Information collected includes:

* Abuse Confidence Score
* Country
* ISP
* Domain
* Number of abuse reports

---

# 📈 Results

## Threat Detection Summary

| Attack Type          | Incidents | Events |
| -------------------- | --------: | -----: |
| HTTP 404 Enumeration |        48 |    931 |
| SQL Injection        |        38 |    579 |
| Directory Traversal  |        33 |    445 |
| Brute Force          |        29 |    480 |
| Port Scan            |        29 |    164 |
| High Request Rate    |         1 |    105 |

---

## Threat Intelligence Summary

| Metric             |     Value |
| ------------------ | --------: |
| Threat Events      |   **178** |
| Unique Incidents   |    **74** |
| Investigated IPs   |    **74** |
| Highest Risk Score | **30.40** |
| Average Risk Score | **27.84** |

---

# 🚀 Getting Started

## Clone the Repository

```bash
git clone https://github.com/Weldesenbet-Zeray/Threat_Intelligence_System_Project.git
cd Threat_Intelligence_System_Project
```

## Install Dependencies

```bash
pip install -r requirements.txt
```

## Configure API Keys

```python
VIRUSTOTAL_API_KEY = "YOUR_API_KEY"
ABUSEIPDB_API_KEY = "YOUR_API_KEY"
```

## Run the Project

Launch Jupyter Notebook:

```bash
jupyter notebook
```

Open:

```text
BDS_TI_Project.ipynb
```

and execute all cells sequentially.

---

# 🔮 Future Enhancements

* Streamlit dashboard
* Docker deployment
* Machine Learning anomaly detection
* Real-time log streaming
* SIEM integration
* Additional Threat Intelligence feeds
* Automated email notifications

---

# 📝 Conclusion

This project demonstrates an end-to-end Cyber Threat Intelligence Investigation workflow by combining synthetic web log generation, rule-based attack detection, external threat intelligence enrichment, risk scoring, and reporting.

Its modular architecture provides a solid foundation for future work involving real-time monitoring, machine learning, and enterprise-scale security analytics.

---

# 📄 License

This repository was developed for academic purposes as part of the **DSA 4030 – Big Data Security** course at **USIU-Africa**.
