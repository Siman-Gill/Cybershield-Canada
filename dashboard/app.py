# dashboard/app.py
# Run with: streamlit run dashboard/app.py
# Then open: http://localhost:8501 in your browser

import streamlit as st
import pandas as pd
import sys, os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from data.database import SessionLocal, ThreatEvent, ComplianceRecord
from compliance.sector_mapper import compliance_summary
from playbooks.ransomware import get_ransomware_playbook

# ── PAGE CONFIG ────────────────────────────────────────────
st.set_page_config(
    page_title="CyberShield Canada — SOC Dashboard",
    layout="wide",
    page_icon="🛡️"
)

st.title("🛡️ CyberShield Canada")
st.caption("Multi-Sector Security Operations Centre  |  PIPEDA · PHIPA · OSFI B-10 · ITSG-33")
st.markdown("---")

# ── SIDEBAR CONTROLS ───────────────────────────────────────
st.sidebar.header("Filters")
sector_filter = st.sidebar.selectbox(
    "Sector",
    ["All", "healthcare", "banking", "government", "it"]
)
severity_filter = st.sidebar.multiselect(
    "Severity",
    ["critical", "high", "medium", "low"],
    default=["critical", "high"]
)

# ── LOAD DATA ──────────────────────────────────────────────
@st.cache_data(ttl=60)  # refresh every 60 seconds
def load_threats(sector, severities):
    db = SessionLocal()
    query = db.query(ThreatEvent)
    if sector != "All":
        query = query.filter(ThreatEvent.sector == sector)
    if severities:
        query = query.filter(ThreatEvent.severity.in_(severities))
    results = query.order_by(ThreatEvent.detected_at.desc()).limit(200).all()
    db.close()
    return results

threats = load_threats(sector_filter, severity_filter)

# ── TOP KPI METRICS ────────────────────────────────────────
col1, col2, col3, col4 = st.columns(4)

critical_count = sum(1 for t in threats if t.severity == "critical")
high_count     = sum(1 for t in threats if t.severity == "high")
open_count     = sum(1 for t in threats if t.status == "open")

col1.metric("Total threats detected", len(threats))
col2.metric("Critical severity",      critical_count,  delta=f"+{critical_count} open", delta_color="inverse")
col3.metric("High severity",          high_count)
col4.metric("Open incidents",         open_count,      delta="Needs attention" if open_count > 0 else "Clear", delta_color="inverse")

st.markdown("---")

# ── THREAT TABLE ───────────────────────────────────────────
st.subheader("Live Threat Intelligence Feed")

if threats:
    df = pd.DataFrame([{
        "Type":        t.ioc_type,
        "Indicator":   t.ioc_value[:40] + "..." if len(t.ioc_value) > 40 else t.ioc_value,
        "Severity":    t.severity.upper(),
        "Sector":      t.sector.title(),
        "Compliance":  t.compliance,
        "Description": t.description[:50] + "..." if t.description and len(t.description) > 50 else t.description,
        "Detected":    t.detected_at.strftime("%Y-%m-%d %H:%M") if t.detected_at else "",
        "Status":      t.status.upper()
    } for t in threats])

    st.dataframe(df, use_container_width=True, height=350)
else:
    st.info("No threats found. Run: python collectors/threat_feed.py first")

st.markdown("---")

# ── COMPLIANCE STATUS ──────────────────────────────────────
st.subheader("Canadian Compliance Status")

col_a, col_b = st.columns(2)

with col_a:
    st.markdown("**Sector breakdown**")
    sector_counts = {}
    for t in load_threats("All", []):
        sector_counts[t.sector] = sector_counts.get(t.sector, 0) + 1
    if sector_counts:
        chart_df = pd.DataFrame(list(sector_counts.items()), columns=["Sector", "Threats"])
        st.bar_chart(chart_df.set_index("Sector"))

with col_b:
    st.markdown("**Compliance obligations triggered**")
    for sector in ["healthcare", "banking", "government", "it"]:
        sector_threats = [t for t in load_threats("All", []) if t.sector == sector]
        critical = sum(1 for t in sector_threats if t.severity in ["critical", "high"])
        if sector_threats:
            st.write(f"**{sector.title()}** — {len(sector_threats)} threats, {critical} require notification")
            st.caption(compliance_summary(sector, "critical" if critical > 0 else "low"))

st.markdown("---")

# ── IR PLAYBOOK GENERATOR ──────────────────────────────────
st.subheader("Incident Response Playbook Generator")

pb_col1, pb_col2 = st.columns([1, 3])
with pb_col1:
    pb_sector = st.selectbox("Select sector", ["healthcare", "banking", "government"])
    generate_btn = st.button("Generate IR Playbook")

if generate_btn:
    pb = get_ransomware_playbook(pb_sector)
    with pb_col2:
        st.success(f"Playbook: {pb['playbook_name']}")
        st.caption(f"Applicable laws: {', '.join(pb['applicable_laws'])}")
        for step in pb["base_steps"][:4]:  # show first 4 steps
            st.markdown(f"**Step {step['step']}** [{step['timeframe']}] — {step['action']}")
        if pb["regulatory_steps"]:
            st.warning("Regulatory obligations:")
            for rs in pb["regulatory_steps"]:
                dl = f" — DEADLINE: {rs.get('deadline','')}" if "deadline" in rs else ""
                st.markdown(f"**{rs['regulation']}**: {rs['action']}{dl}")
