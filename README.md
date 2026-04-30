# 🛡️ CyberShield Canada — Multi-Sector SOC Platform

> A live Security Operations Centre platform serving Government of Canada, Banking, Healthcare, and IT sectors — with automated Canadian compliance mapping (PHIPA · PIPEDA · OSFI B-10 · ITSG-33)

🔴 **[Live Demo →](https://cybershield-canada.streamlit.app)**  
📁 **[GitHub →](https://github.com/Siman-Gill/cybershield-canada)**

---

## What This Project Does

CyberShield Canada simulates a real enterprise SOC platform that:

- Ingests **live threat intelligence** from AlienVault OTX (real IOCs updated hourly)
- **Automatically tags** every threat to one of four Canadian sectors: Government, Banking, Healthcare, IT
- **Maps threats to Canadian law** — PHIPA, PIPEDA, OSFI B-10, ITSG-33 — and shows which regulator must be notified and within what deadline
- **Generates incident response playbooks** per sector with Canadian regulatory notification timelines built in
- Displays everything in a **live Streamlit dashboard** with sector charts, severity metrics, and compliance status

---

## Screenshot

<img width="1244" height="790" alt="Screenshot 2026-04-29 at 7 33 25 PM" src="https://github.com/user-attachments/assets/a8c741bc-d7e9-4923-83f4-3f44995438d4" />
<img width="1244" height="790" alt="Screenshot 2026-04-29 at 7 33 15 PM" src="https://github.com/user-attachments/assets/bf57992b-fe69-4346-9deb-8342f228f2e9" />


---

## Canadian Regulatory Compliance Engine

| Sector | Applicable Laws | Notification Deadline | Notify |
|---|---|---|---|
| Healthcare | PHIPA, PIPEDA | 72 hours | IPC Ontario |
| Banking | OSFI B-10, PIPEDA, PCI-DSS | 24 hours | OSFI |
| Government | ITSG-33, Privacy Act, PIPEDA | 1 hour | CCCS |
| IT | PIPEDA | 72 hours | OPC Canada |

---

## Project Structure
