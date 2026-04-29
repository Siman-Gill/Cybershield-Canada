# playbooks/ransomware.py
# Generates a step-by-step incident response plan for ransomware attacks
# Different steps depending on sector (healthcare vs banking vs government)

from datetime import datetime, timedelta

def get_ransomware_playbook(sector: str, org_name: str = "Fictional Org Inc.") -> dict:
    """
    Returns the full incident response playbook for a ransomware attack.
    Steps are customized by sector with Canadian regulatory deadlines.
    """

    base_steps = [
        {"step": 1, "timeframe": "0-15 min",  "action": "ISOLATE — Disconnect all affected systems from the network immediately. Do NOT shut down — leave them running for forensics.", "owner": "SOC Analyst"},
        {"step": 2, "timeframe": "0-30 min",  "action": "NOTIFY — Alert the CISO, CTO, and Privacy Officer. Start the incident clock.", "owner": "SOC Lead"},
        {"step": 3, "timeframe": "30-60 min", "action": "ASSESS — Determine blast radius: which systems, which data, how many users affected?", "owner": "IR Team"},
        {"step": 4, "timeframe": "1-4 hrs",   "action": "PRESERVE — Take forensic images of affected systems. Collect logs (firewall, AD, email) before they rotate.", "owner": "Forensics Lead"},
        {"step": 5, "timeframe": "4-24 hrs",  "action": "ERADICATE — Identify the initial infection vector. Remove malware. Rebuild from clean backups.", "owner": "Security Engineer"},
        {"step": 6, "timeframe": "1-7 days",  "action": "RECOVER — Restore systems. Monitor for re-infection. Implement additional controls.", "owner": "IT Ops"},
        {"step": 7, "timeframe": "7-14 days", "action": "POST-INCIDENT — Write full incident report. Update IR plan. Train staff.", "owner": "CISO"}
    ]

    # Sector-specific regulatory steps
    regulatory_steps = {
        "healthcare": [
            {"step": "4a", "timeframe": "4-24 hrs",
             "action": "PHIPA: Assess if Personal Health Information (PHI) was accessed or exfiltrated.",
             "regulation": "PHIPA s.12(1)", "owner": "Privacy Officer"},
            {"step": "4b", "timeframe": "Within 72 hrs",
             "action": "PHIPA: If PHI breach confirmed — notify Information and Privacy Commissioner of Ontario (IPC). Draft notification letter.",
             "regulation": "PHIPA s.12(2)", "owner": "Privacy Officer",
             "deadline": (datetime.now() + timedelta(hours=72)).strftime("%Y-%m-%d %H:%M EST")},
            {"step": "4c", "timeframe": "After IPC notification",
             "action": "PHIPA: Notify all affected individuals whose PHI was compromised.",
             "regulation": "PHIPA s.12(3)", "owner": "Privacy Officer"}
        ],
        "banking": [
            {"step": "2a", "timeframe": "Within 24 hrs",
             "action": "OSFI: Report cyber incident to Office of the Superintendent of Financial Institutions.",
             "regulation": "OSFI B-10 s.7", "owner": "CRO / CISO",
             "deadline": (datetime.now() + timedelta(hours=24)).strftime("%Y-%m-%d %H:%M EST")},
            {"step": "2b", "timeframe": "Within 24 hrs",
             "action": "PIPEDA: Notify Office of the Privacy Commissioner if personal financial data was breached.",
             "regulation": "PIPEDA s.10.1", "owner": "Privacy Officer"}
        ],
        "government": [
            {"step": "2a", "timeframe": "Within 1 hr",
             "action": "GoC: Report to Canadian Centre for Cyber Security (CCCS) via secure channel.",
             "regulation": "GoC Directive on Security Management", "owner": "Departmental Security Officer",
             "deadline": (datetime.now() + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M EST")},
            {"step": "2b", "timeframe": "Within 4 hrs",
             "action": "GoC: Notify Treasury Board Secretariat if a Protected B or higher system is affected.",
             "regulation": "ITSG-33 IR-6", "owner": "DSO / CISO"}
        ]
    }

    incident_time = datetime.now().strftime("%Y-%m-%d %H:%M EST")

    return {
        "playbook_name": f"Ransomware Response — {sector.title()} Sector",
        "organization":  org_name,
        "sector":        sector,
        "triggered_at":  incident_time,
        "base_steps":    base_steps,
        "regulatory_steps": regulatory_steps.get(sector, []),
        "applicable_laws": {
            "healthcare": ["PHIPA", "PIPEDA"],
            "banking":    ["OSFI B-10", "PIPEDA", "PCI-DSS"],
            "government": ["ITSG-33", "Privacy Act", "PIPEDA"]
        }.get(sector, ["PIPEDA"])
    }

def print_playbook(sector: str):
    """Print a formatted playbook to the terminal"""
    pb = get_ransomware_playbook(sector, org_name=f"Fictional {sector.title()} Organization")

    print(f"\n{'='*60}")
    print(f"  INCIDENT RESPONSE PLAYBOOK: RANSOMWARE")
    print(f"  Sector: {pb['sector'].upper()}")
    print(f"  Triggered: {pb['triggered_at']}")
    print(f"  Applicable laws: {', '.join(pb['applicable_laws'])}")
    print(f"{'='*60}\n")

    print("── STANDARD RESPONSE STEPS ──")
    for step in pb["base_steps"]:
        print(f"\n  Step {step['step']} [{step['timeframe']}]")
        print(f"  {step['action']}")
        print(f"  Owner: {step['owner']}")

    if pb["regulatory_steps"]:
        print(f"\n── REGULATORY OBLIGATIONS ({sector.upper()}) ──")
        for step in pb["regulatory_steps"]:
            print(f"\n  Step {step['step']} [{step['timeframe']}]")
            print(f"  {step['action']}")
            if "deadline" in step:
                print(f"  !! HARD DEADLINE: {step['deadline']}")
            print(f"  Regulation: {step['regulation']}")

# Run: python playbooks/ransomware.py
if __name__ == "__main__":
    for sector in ["healthcare", "banking", "government"]:
        print_playbook(sector)
        print("\n")
