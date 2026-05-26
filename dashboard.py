"""
dashboard.py — Home / landing page for APK Triage
Navigate to the tool pages using the sidebar.
"""
import streamlit as st
from campaign.db import init_db

init_db()   # ensure DB is ready before any page loads

st.set_page_config(
    page_title="APK Triage  |  Home",
    page_icon="🔍",
    layout="wide"
)

st.title("A-Analyzer")
st.caption("Static analysis · GTI enrichment · Campaign clustering")
st.divider()

col1, col2 = st.columns(2)

with col1:
    st.markdown("""
    ### 🔍 Triage
    Upload an APK and get an instant forensic report:
    - Static analysis with risk scoring
    - Google Threat Intelligence (VirusTotal) enrichment
    - AI-powered verdict (Gemini)
    - Downloadable case package (signed PDF · JSON · CoC log · BNMLINK template)
    - **Auto-saved to the campaign database**
    """)
    st.page_link("pages/1_🔍_Triage.py", label="Go to Triage →", icon="🔍")

with col2:
    st.markdown("""
    ### 🕸️ Campaign Clustering
    Detect coordinated scam campaigns across multiple APKs:
    - Groups APKs that share the same Telegram bot, IP, or URL
    - Interactive network graph showing APK ↔ C2 connections
    - Campaign timeline and analyst drilldown
    - Rename campaigns, remove stale scans
    """)
    st.page_link("pages/2_🕸️_Campaigns.py", label="Go to Campaigns →", icon="🕸️")

st.divider()
st.caption(
    "Built for PDRM · BNM · CyberSecurity Malaysia investigators. "
    "All analysis is performed locally — no APK data is sent externally except to VirusTotal (hash only)."
)