# 🛡️ Software Supply Chain Risk Scorer (SBOM Analyzer)

**🔗 Live Demo:** [https://sbom-analyzer.onrender.com/](https://sbom-analyzer.onrender.com/)



A live risk-visibility and incident-response simulation tool for enterprise software supply chains — built for the Societe Generale Hackathon 2026 (Track: Third-Party & Software Risk).

---

## 🧩 Problem

When a critical vulnerability like Log4j (CVE-2021-44228) is disclosed, security teams have no fast way to answer:

- Which applications use the vulnerable library — directly or transitively?
- What's the actual blast radius if this CVE is exploited?
- Are there license compliance risks (GPL in proprietary code)?
- Which libraries are unmaintained and quietly accumulating risk?

Manual dependency tracing typically takes **40+ hours per incident**. This tool automates that entire workflow.

---

## 💡 What Makes This Different

Most SBOM scanners stop at a static table of flagged libraries. This project adds a **Blast Radius Simulator** — pick any library, simulate a new CVE, and watch a live animated graph show exactly how the vulnerability propagates from that library to every affected application, direct or transitive. It turns a compliance report into an incident-response rehearsal tool.

---

## ✨ Key Features

| Feature | Description |
|---|---|
| 📊 **Risk Dashboard** | Real-time summary of applications, dependencies, risky vs. clean counts, animated charts |
| 🕸️ **Dependency Graph** | Interactive network graph of Applications → Libraries, color-coded by risk |
| 💥 **Blast Radius Simulator** | Simulates a CVE on any library and animates the propagation path to affected apps in real time |
| 🏢 **Application Risk Ranking** | Applications ranked by cumulative supply-chain risk score |
| 📦 **Dependency Explorer** | Searchable, filterable table of all 500 dependencies with severity badges |
| 🛡 **Vulnerability Explorer** | Critical / High / Medium CVE breakdown per library |
| ⚖ **License Compliance Dashboard** | Flags GPL-in-proprietary and other license conflicts |
| 📄 **Executive Reports** | Auto-generated summary + remediation recommendations |
| ⬇ **PDF / CSV Export** | One-click export of the full risk report |

---

## 🏗️ Architecture

```
sbom-analyzer/
│
├── app.py                     → Flask routes (dashboard, graph, exports, APIs)
├── requirements.txt
├── .gitignore
│
├── backend/
│   ├── risk_engine.py         → Core scoring engine (vulnerability + license + maintenance)
│   ├── generate_vulns.py      → Simulated NVD vulnerability database generator
│   ├── generate_sbom.py       → Synthetic SBOM dependency generator
│   ├── generate_labels.py     → Ground-truth labels for self-evaluation
│   └── evaluate.py            → Precision / recall self-test against ground truth
│
├── data/
│   ├── applications.json      → 10 applications with business criticality
│   ├── license_rules.json     → License compatibility matrix
│   ├── vulnerability_db.json  → Simulated CVE database
│   ├── sbom_dependencies.csv  → 500 dependencies across 10 apps
│   └── dependency_labels.csv  → Ground truth for self-evaluation
│
├── templates/                 → Jinja2 HTML pages (dashboard, graph, reports, etc.)
└── static/
    ├── css/style.css          → Dark "Cyber Slate" theme, animations
    └── images/
```

### Risk Scoring Model

Each dependency is scored across three risk dimensions, then weighted by the owning application's business criticality:

1. **Vulnerability risk** — CVSS score, with an added penalty if no patch is available or the vulnerability is known-exploited
2. **License risk** — GPL/AGPL-style licenses flagged when used in externally-distributed applications; MIT/Apache treated as low-risk
3. **Maintenance risk** — libraries with no updates in 2+ years are flagged as unmaintained

Final application-level risk aggregates all dependency scores, multiplied by a criticality factor (High = 1.3×, Medium = 1.0×, Low = 0.8×).

---

## 🚀 Getting Started

### 1. Clone the repository
```bash
git clone https://github.com/<your-username>/sbom-analyzer.git
cd sbom-analyzer
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Generate the dataset (first run only)
```bash
cd backend
python generate_vulns.py
python generate_sbom.py
python generate_labels.py
cd ..
```

### 4. Run the self-evaluation (optional — verifies engine accuracy)
```bash
cd backend
python evaluate.py
cd ..
```

### 5. Start the app
```bash
python app.py
```

Then open **http://127.0.0.1:5000** in your browser.

---

## 📈 Self-Evaluation Results

| Metric | Result | Target |
|---|---|---|
| Precision | 100% | — |
| Recall | 100% | — |
| False Positive Rate | 0% | < 20% |
| Transitive Resolution | 100% | 100% |

*(Run on synthetic labeled data — validates the engine's internal detection logic is bug-free and consistent with the ground truth generator.)*

---

## 🛠️ Tech Stack

- **Backend:** Python, Flask
- **Frontend:** Jinja2, Bootstrap 5, custom CSS animations
- **Visualization:** Chart.js (risk distribution charts), vis-network (dependency graph)
- **Reporting:** ReportLab (PDF export), CSV export
- **Data:** Synthetic SBOM + simulated NVD vulnerability database (500 dependencies, 10 applications)

---

## 🎯 Framework Alignment

- **NIST Cybersecurity Framework** — SC-2 (supplier assessment), DS-6 (integrity checking), CM-8 (vulnerability scans)
- **OWASP** — A06:2021 Vulnerable and Outdated Components
- **Executive Order 14028** — SBOM requirements, software supply chain security
- **OpenSSF Scorecard** — Dependency risk assessment, maintenance indicators

---

## 📌 Future Enhancements

- LLM-generated natural-language incident narratives per simulated CVE
- Real-time alerting via webhook/Slack integration
- Integration with real SBOM sources (Syft, CycloneDX) instead of synthetic data
