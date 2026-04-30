# 🛡️ CyberShield Canada — Multi-Sector SOC Platform

> A live Security Operations Centre platform built for Government of Canada, Banking, Healthcare, and IT sectors — with automated Canadian compliance mapping across PHIPA · PIPEDA · OSFI B-10 · ITSG-33

<div align="center">

**[🔴 Live Demo → cybershield-canada.streamlit.app](https://cybershield-canada.streamlit.app)**  &nbsp;&nbsp;|&nbsp;&nbsp;  **[💻 GitHub → Siman-Gill/cybershield-canada](https://github.com/Siman-Gill/cybershield-canada)**

![Python](https://img.shields.io/badge/Python-3.12-blue?style=flat-square&logo=python)
![Streamlit](https://img.shields.io/badge/Streamlit-Live-red?style=flat-square&logo=streamlit)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Sectors](https://img.shields.io/badge/Sectors-4%20Canadian-orange?style=flat-square)

</div>

---

## What This Project Does

CyberShield Canada is a **full-stack Security Operations Centre platform** that simulates what a real enterprise SOC team delivers to Canadian regulated-industry clients. It:

- Ingests **live threat intelligence** from AlienVault OTX — real IOCs updated in real time
- **Automatically classifies** every threat to one of four Canadian sectors: Government, Banking, Healthcare, or IT
- **Maps threats to Canadian law** and calculates which regulator must be notified, and within what statutory deadline
- **Generates incident response playbooks** per sector with Canadian regulatory notification steps built in
- Displays everything in a **live Streamlit dashboard** with sector charts, severity metrics, and compliance status

---

## Live Dashboard Preview

| Metric | Live Value |
|--------|-----------|
| Threat feed | AlienVault OTX (real IOCs) |
| Sectors covered | Government 🍁 · Banking 🏦 · Healthcare 🏥 · IT 💻 |
| Compliance laws | PHIPA · PIPEDA · OSFI B-10 · ITSG-33 |
| IR Playbooks | 5 scenarios with regulatory deadlines |

---

## Canadian Regulatory Compliance Engine

This is the core differentiator — every detected threat is automatically mapped to applicable Canadian law:

| Sector | Applicable Laws | Notification Deadline | Notify |
|---|---|---|---|
| 🏥 Healthcare | PHIPA, PIPEDA | **72 hours** | Information and Privacy Commissioner of Ontario |
| 🏦 Banking | OSFI B-10, PIPEDA, PCI-DSS | **24 hours** | Office of the Superintendent of Financial Institutions |
| 🍁 Government | ITSG-33, Privacy Act, PIPEDA | **1 hour** | Canadian Centre for Cyber Security (CCCS) |
| 💻 IT | PIPEDA | **72 hours** | Office of the Privacy Commissioner of Canada |

---

## Architecture

```
cybershield-canada/
│
├── collectors/
│   └── threat_feed.py        # Live AlienVault OTX threat ingestion + sector tagging
│
├── compliance/
│   └── sector_mapper.py      # Maps threats → Canadian laws → notification deadlines
│
├── playbooks/
│   └── ransomware.py         # Automated IR playbooks with PHIPA/OSFI/ITSG-33 steps
│
├── dashboard/
│   └── app.py                # Streamlit live dashboard (auto-creates DB on startup)
│
├── data/
│   └── database.py           # SQLAlchemy models: ThreatEvents, ComplianceRecords, PlaybookRuns
│
└── requirements.txt
```

### Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.12 |
| Dashboard | Streamlit (deployed on Streamlit Cloud) |
| Database | SQLAlchemy + SQLite |
| Threat Intel | AlienVault OTX REST API |
| API Layer | FastAPI |
| PDF Reports | ReportLab |
| Deployment | Streamlit Community Cloud (free tier) |

---

## How to Run Locally

```bash
# 1. Clone the repo
git clone https://github.com/Siman-Gill/cybershield-canada.git
cd cybershield-canada

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Add your API key
echo "OTX_API_KEY=your_key_here" > .env
echo "DATABASE_URL=sqlite:///./data/cybershield.db" >> .env
# Get a free key at: otx.alienvault.com → Settings → API Key

# 5. Create database and pull live threats
python data/database.py
python collectors/threat_feed.py

# 6. Launch dashboard
streamlit run dashboard/app.py
# Open http://localhost:8501
```

> **No OTX key?** The app automatically seeds sample Canadian threat data on first run — no setup required.

---

## Sector-Specific Features

| Feature | Gov 🍁 | Banking 🏦 | Healthcare 🏥 | IT 💻 |
|---|:---:|:---:|:---:|:---:|
| Live threat feed | ✅ | ✅ | ✅ | ✅ |
| Compliance mapping | ITSG-33 | OSFI B-10 | PHIPA | PIPEDA |
| Notification deadline | 1 hour | 24 hours | 72 hours | 72 hours |
| IR Playbook | ✅ | ✅ | ✅ | ✅ |
| Regulatory body | CCCS / TBS | OSFI | IPC Ontario | OPC Canada |

---

## Incident Response Playbooks

The platform auto-generates full IR playbooks with sector-specific regulatory obligations:

**Healthcare Ransomware Playbook** includes:
- Standard IR steps (isolate → assess → preserve → eradicate → recover)
- `PHIPA s.12(1)` — PHI breach assessment within 4 hours
- `PHIPA s.12(2)` — IPC Ontario notification within **72 hours** (hard deadline)
- `PHIPA s.12(3)` — Individual notification after IPC filing

**Banking Phishing Playbook** includes:
- `OSFI B-10 s.7` — Regulatory notification within **24 hours**
- `PIPEDA s.10.1` — Privacy Commissioner notification if financial data breached
- Payment card network notification if cardholder data affected

---

## Why I Built This

Most cybersecurity portfolio projects demonstrate generic technical skills. Canadian employers — especially Government of Canada departments, Big 5 banks, and Ontario healthcare networks — need professionals who understand **Canadian compliance law**, not just frameworks borrowed from US or EU contexts.

This project proves hands-on knowledge of PHIPA, PIPEDA, OSFI B-10, and ITSG-33 that most applicants can only claim to have read about.

---

## Disclaimer

This is a portfolio project built for educational and demonstration purposes. All fictional organization names in sample data are invented. Live threat data is sourced from public AlienVault OTX feeds. No real personal health information, financial data, or government data is used or processed.

---

## Author

**Siman Gill** — Cybersecurity Professional  
📍 Open to Toronto · Ottawa · Remote  
🔗 [GitHub](https://github.com/Siman-Gill) | [LinkedIn](https://linkedin.com/in/simangill1/)  
📧 simangill1@outlook.com

---

*Built with Python, Streamlit, SQLAlchemy, AlienVault OTX · Targeting Government of Canada · Banking · Healthcare · IT security roles*
