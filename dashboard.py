"""
dashboard.py — Home / landing page for APK Triage
Navigate to the tool pages using the sidebar.
"""
import streamlit as st
from campaign.db import init_db
from campaign.cluster import get_stats
from utils.styles import inject_css, divider_with_label, status_pill

init_db()

st.set_page_config(
    page_title="APK Triage  |  Home",
    page_icon="shield",
    layout="wide"
)

inject_css()

# ─── Hero ─────────────────────────────────────────────────────────────────────────

st.markdown("MALAYSIAN APK MALWARE INTELLIGENCE")
st.title("A-Analyzer")
st.markdown("Static Analysis · VirusTotal Enrichment · Campaign Clustering")
st.markdown("`PDRM` &nbsp; `BNM` &nbsp; `CyberSecurity Malaysia`")

st.divider()

# ─── Live DB stats ────────────────────────────────────────────────────────────────

try:
    stats = get_stats()
    has_data = stats["total_apks"] > 0
except Exception:
    stats = {"total_apks": 0, "total_campaigns": 0, "critical_apks": 0, "telegram_c2": 0, "ip_c2": 0}
    has_data = False

if has_data:
    divider_with_label("Database Summary")
    s1, s2, s3, s4, s5 = st.columns(5)
    s1.metric("APKs Analysed",   stats["total_apks"])
    s2.metric("Campaigns Found", stats["total_campaigns"])
    s3.metric("Critical APKs",   stats["critical_apks"])
    s4.metric("Telegram C2s",    stats["telegram_c2"])
    s5.metric("IP-based C2s",   stats["ip_c2"])
else:
    st.info("No scans yet — database is empty. Upload an APK on the Triage page to get started.")

# ─── Feature cards ────────────────────────────────────────────────────────────────

divider_with_label("Tools")

col1, col2 = st.columns(2, gap="large")

with col1:
    st.subheader("APK Triage")
    st.caption("FEATURE 01")
    st.markdown(
        "Upload a suspicious APK and get an instant forensic report. "
        "Risk-scored, GTI-enriched, and packaged for court submission."
    )
    st.markdown("""
- Static analysis — permissions, IoCs, risk scoring
- VirusTotal / GTI hash + IP + URL reputation
- Gemini AI verdict in plain English
- Signed PDF · JSON evidence · CoC log · BNMLINK template
""")
    st.page_link("pages/1_Triage.py", label="Open Triage", icon=None)

with col2:
    st.subheader("Campaign Clustering")
    st.caption("FEATURE 02")
    st.markdown(
        "Detect coordinated scam campaigns across multiple APKs. "
        "Groups by shared Telegram bot, IP, or C2 infrastructure automatically."
    )
    st.markdown("""
- Auto-clustering by shared C2 indicator
- Interactive vis.js network graph
- Timeline view — all scans newest-first
- Rename campaigns, drill into members, delete scans
""")
    st.page_link("pages/2_Campaigns.py", label="Open Campaigns", icon=None)

# ─── Risk level reference ─────────────────────────────────────────────────────────

divider_with_label("Risk Levels")

r1, r2, r3, r4, r5 = st.columns(5)

with r1:
    st.metric("CLEAN",    "0%")
    st.caption("No suspicious indicators")

with r2:
    st.metric("LOW",      "1–19%")
    st.caption("Minor indicators, likely benign")

with r3:
    st.metric("MEDIUM",   "20–44%")
    st.caption("Multiple indicators — review recommended")

with r4:
    st.metric("HIGH",     "45–74%")
    st.caption("Strong malicious indicators")

with r5:
    st.metric("CRITICAL", "75–100%")
    st.caption("Confirmed malware pattern")

# ─── Footer ───────────────────────────────────────────────────────────────────────

st.divider()
st.caption(
    "APK Triage v1.0 · All analysis performed locally · "
    "Hash data submitted to VirusTotal only · APK binary never leaves your machine"
)