# data/database.py
# Run this file ONCE to create your database and tables

from sqlalchemy import create_engine, Column, String, Integer, DateTime, Text
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime
import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data/cybershield.db")
engine = create_engine(DATABASE_URL, echo=False)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# TABLE 1: Every threat we detect goes here
class ThreatEvent(Base):
    __tablename__ = "threat_events"

    id          = Column(Integer, primary_key=True, index=True)
    ioc_type    = Column(String)   # "ip", "domain", "url", "hash"
    ioc_value   = Column(String)   # the actual IP address or domain
    source      = Column(String)   # "AlienVault OTX", "AbuseIPDB"
    severity    = Column(String)   # "critical", "high", "medium", "low"
    sector      = Column(String)   # "healthcare", "banking", "government", "it"
    compliance  = Column(String)   # "PHIPA, PIPEDA" — Canadian laws that apply
    description = Column(Text)     # what this threat does
    detected_at = Column(DateTime, default=datetime.utcnow)
    status      = Column(String, default="open")  # "open", "investigating", "closed"

# TABLE 2: Compliance assessment results go here
class ComplianceRecord(Base):
    __tablename__ = "compliance_records"

    id             = Column(Integer, primary_key=True, index=True)
    threat_id      = Column(Integer)
    law            = Column(String)   # "PHIPA", "PIPEDA", "OSFI B-10", "ITSG-33"
    is_breach      = Column(String)   # "yes", "no", "unknown"
    notification   = Column(Text)     # draft notification letter text
    deadline       = Column(String)   # "2024-01-15 14:00 EST"
    assessed_at    = Column(DateTime, default=datetime.utcnow)

# TABLE 3: IR playbook runs go here
class PlaybookRun(Base):
    __tablename__ = "playbook_runs"

    id          = Column(Integer, primary_key=True, index=True)
    threat_id   = Column(Integer)
    playbook    = Column(String)   # "ransomware_healthcare", "phishing_banking"
    steps_json  = Column(Text)     # all steps as JSON
    started_at  = Column(DateTime, default=datetime.utcnow)
    status      = Column(String, default="in_progress")

# This runs when you execute: python data/database.py
if __name__ == "__main__":
    Base.metadata.create_all(bind=engine)
    print("Database created successfully!")
    print(f"Location: cybershield-canada/data/cybershield.db")
    print("Tables created: threat_events, compliance_records, playbook_runs")
