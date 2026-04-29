# collectors/threat_feed.py

import requests
import os
import sys
from datetime import datetime, timezone
from dotenv import load_dotenv

# This tells Python to look in the parent folder for database.py
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data.database import SessionLocal, ThreatEvent

# Load your .env file
load_dotenv()
OTX_API_KEY = os.getenv("OTX_API_KEY")

# ── SECTOR KEYWORDS ──────────────────────────────────────────
SECTOR_KEYWORDS = {
    "healthcare": ["hospital", "medical", "health", "patient", "clinic",
                   "pharma", "healthcare", "ehr", "ransomware"],
    "banking":    ["bank", "financial", "payment", "swift", "atm",
                   "fraud", "credit", "transaction", "finance"],
    "government": ["government", "military", "election", "infrastructure",
                   "espionage", "canada", "federal", "ministry"],
    "it":         ["software", "cloud", "tech", "saas", "api",
                   "developer", "supply chain", "open source"]
}

COMPLIANCE_MAP = {
    "healthcare": "PHIPA, PIPEDA",
    "banking":    "OSFI B-10, PIPEDA, PCI-DSS",
    "government": "ITSG-33, Privacy Act, PIPEDA",
    "it":         "PIPEDA"
}

def detect_sector(text: str) -> str:
    text_lower = text.lower()
    for sector, keywords in SECTOR_KEYWORDS.items():
        if any(keyword in text_lower for keyword in keywords):
            return sector
    return "it"

def load_sample_data():
    """Fallback data — works even without an API key"""
    print("Loading sample Canadian threat data...")
    return [
        {
            "name": "Ransomware targeting Canadian hospitals — LockBit 3.0",
            "description": "ransomware attacking healthcare patient data systems",
            "tags": ["ransomware", "healthcare", "critical"],
            "indicators": [
                {"type": "ip",     "indicator": "185.220.101.45"},
                {"type": "domain", "indicator": "lockbit-canada.onion"},
                {"type": "hash",   "indicator": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"}
            ]
        },
        {
            "name": "Banking phishing targeting Canadian Big 5",
            "description": "credential theft targeting bank financial payment fraud",
            "tags": ["phishing", "banking", "high"],
            "indicators": [
                {"type": "domain", "indicator": "fake-rbc-login.com"},
                {"type": "ip",     "indicator": "91.108.56.122"},
                {"type": "url",    "indicator": "http://td-secure-alert.phish/login"}
            ]
        },
        {
            "name": "APT targeting Government of Canada infrastructure",
            "description": "espionage campaign targeting government canada federal",
            "tags": ["apt", "government", "critical"],
            "indicators": [
                {"type": "ip",     "indicator": "45.142.212.100"},
                {"type": "domain", "indicator": "gc-secure-update.malware.net"}
            ]
        },
        {
            "name": "Supply chain attack on Canadian IT providers",
            "description": "software supply chain compromise targeting IT MSP cloud saas",
            "tags": ["supply-chain", "it", "high"],
            "indicators": [
                {"type": "domain", "indicator": "malicious-npm-package.io"},
                {"type": "ip",     "indicator": "193.32.162.88"}
            ]
        },
        {
            "name": "Credential stuffing targeting Ontario Health portals",
            "description": "credential stuffing health patient login systems",
            "tags": ["credential-stuffing", "healthcare", "medium"],
            "indicators": [
                {"type": "ip",  "indicator": "103.216.221.15"},
                {"type": "url", "indicator": "https://fake-ontario-health.ru/login"}
            ]
        }
    ]

def fetch_otx_threats():
    print("=" * 50)
    print("CyberShield Canada — Threat Feed Collector")
    print("=" * 50)

    # Check key exists
    if not OTX_API_KEY or OTX_API_KEY == "paste_your_key_here":
        print("WARNING: No OTX API key found in .env file")
        print("Using sample data instead...")
        return load_sample_data()

    print(f"OTX API key found: {OTX_API_KEY[:8]}...")
    print("Connecting to AlienVault OTX...")

    url     = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    params  = {"limit": 10}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=15)

        if response.status_code == 403:
            print("403 Forbidden — API key rejected by OTX")
            print("Falling back to sample data...")
            return load_sample_data()

        response.raise_for_status()
        pulses = response.json().get("results", [])
        print(f"SUCCESS: Downloaded {len(pulses)} threat pulses from OTX")
        return pulses

    except Exception as e:
        print(f"Connection error: {e}")
        print("Falling back to sample data...")
        return load_sample_data()

def save_threats_to_database(pulses):
    print("\nSaving threats to database...")
    db = SessionLocal()
    saved_count = 0

    for pulse in pulses:
        pulse_name  = pulse.get("name", "Unknown threat")
        description = pulse.get("description", "")
        tags        = " ".join(pulse.get("tags", []))
        full_text   = f"{pulse_name} {description} {tags}"

        sector     = detect_sector(full_text)
        compliance = COMPLIANCE_MAP[sector]

        severity = "medium"
        if any(t in tags.lower() for t in ["ransomware", "apt", "critical"]):
            severity = "critical"
        elif any(t in tags.lower() for t in ["high", "phishing", "banking"]):
            severity = "high"

        for indicator in pulse.get("indicators", [])[:5]:
            threat = ThreatEvent(
                ioc_type    = indicator.get("type", "unknown"),
                ioc_value   = indicator.get("indicator", ""),
                source      = "AlienVault OTX",
                severity    = severity,
                sector      = sector,
                compliance  = compliance,
                description = pulse_name,
                detected_at = datetime.utcnow(datetime.UTC),
                status      = "open"
            )
            db.add(threat)
            saved_count += 1

    db.commit()
    db.close()
    print(f"Saved {saved_count} threats to database")
    return saved_count

# ── THIS IS WHAT RUNS WHEN YOU TYPE: python collectors/threat_feed.py ──
if __name__ == "__main__":
    print("\nStarting threat collection...\n")
    pulses = fetch_otx_threats()
    count  = save_threats_to_database(pulses)
    print(f"\n{'='*50}")
    print(f"DONE: {count} threats saved to database")
    print(f"Next step: streamlit run dashboard/app.py")
    print(f"{'='*50}\n")
