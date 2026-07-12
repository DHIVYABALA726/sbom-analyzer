# SBOM Risk Scorer
## Software Supply Chain Security Analyzer

## Project Overview

SBOM Risk Scorer is an enterprise security platform that analyzes Software Bill of Materials (SBOM) data to identify vulnerable dependencies, calculate risk scores, monitor compliance risks, and generate security insights.

The platform helps security teams gain visibility into software components and prioritize remediation of high-risk dependencies.

---

#  Problem Statement

Modern applications depend on hundreds of open-source libraries. Vulnerable, outdated, or non-compliant dependencies can introduce software supply chain attacks and security risks.

Organizations need a solution to:

- Identify risky dependencies
- Detect vulnerabilities
- Analyze compliance issues
- Prioritize security threats
- Generate security reports

---

#  Solution

SBOM Risk Scorer provides automated software supply chain analysis through:

- SBOM processing
- Dependency risk scoring
- Vulnerability detection
- License compliance monitoring
- Application risk ranking
- Executive security reporting

---

#  Features

## 📊 Security Dashboard
- Total applications overview
- Dependency statistics
- Risk distribution chart
- Security posture summary

## 🏢 Application Security Ranking
- Application-wise risk scoring
- Critical application identification
- Severity classification

## 📦 Dependency Explorer
- Dependency analysis
- Library and version details
- Risk score display

## 🛡 Vulnerability Explorer
- Vulnerable component detection
- Severity classification
- Search functionality

## ⚖ Compliance Dashboard
- License risk monitoring
- Compliance recommendations

## 📄 Executive Security Report
- Top risk applications
- Security summary
- Recommended actions

---

# 🏗 Architecture

SBOM Data

↓

SBOM Processing

↓

Risk Analysis Engine

↓

Vulnerability Analysis + Compliance Analysis + Risk Scoring

↓

Flask Backend

↓

Security Dashboard


---

# 🛠 Technology Stack

Frontend:
- HTML
- CSS
- Bootstrap
- JavaScript

Backend:
- Python Flask

Visualization:
- Chart.js

Data:
- JSON
- CSV SBOM Data

Version Control:
- GitHub


---

# 📈 Risk Analysis Algorithm

Risk score is calculated using:

1. Vulnerability Factors
- CVSS score
- Exploit availability
- Security impact

2. License Factors
- License compatibility
- Compliance conflicts

3. Maintenance Factors
- Dependency update status
- Unmaintained packages

4. Application Criticality

Risk Levels:

CRITICAL - Immediate action required

HIGH - Priority remediation

MEDIUM - Review required

LOW - Low impact


---

# 📂 Project Structure

sbom-analyzer/

backend/
- risk_engine.py
- evaluate.py
- generate_sbom.py
- generate_vulns.py

data/
- applications.json
- vulnerability_db.json
- sbom_dependencies.csv
- license_rules.json

templates/
- base.html
- index.html
- vulnerabilities.html
- compliance.html
- reports.html

app.py

requirements.txt


---

# ⚙ Installation

Clone repository:

git clone https://github.com/DHIVYABALA726/sbom-analyzer.git


Install dependencies:

pip install -r requirements.txt


Run application:

python app.py


Open:

http://127.0.0.1:5000


---

# 👥 Team Contributions

## Member 1 — Data & Risk Engine

Responsibilities:

- SBOM data generation
- Vulnerability database creation
- Risk scoring algorithm
- Dependency evaluation engine


## Member 2 — Backend Integration & Dashboard

Responsibilities:

- Flask backend integration
- Security dashboard development
- Vulnerability explorer
- Compliance dashboard
- Executive security reports
- UI improvements


---

# 🚀 Future Enhancements

- Real-time CVE database integration
- Automated remediation suggestions
- CI/CD security integration
- AI-based risk prediction
- Cloud SBOM monitoring


---

# 🏆 Hackathon Project

Software Supply Chain Risk Scorer (SBOM Analyzer)

Developed for:

Societe Generale Hackathon 2026
