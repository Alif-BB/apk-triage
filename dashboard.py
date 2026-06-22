"""
dashboard.py — Home / landing page for APK Triage
Navigate to the tool pages using the sidebar.
"""
import streamlit as st
from campaign.db import init_db
from campaign.cluster import get_stats
from utils.styles import inject_css, divider_with_label, status_pill, brand_header, sidebar_branding

init_db()

st.set_page_config(
    page_title="APK Triage  |  Home",
    page_icon="shield",
    layout="wide"
)

inject_css()

# ─── Sidebar Branding ─────────────────────────────────────────────────────────────
with st.sidebar:
    sidebar_branding()

# ─── Hero ─────────────────────────────────────────────────────────────────────────

brand_header(
    title="A-Analyzer",
    subtitle="Static Analysis · VirusTotal Enrichment · Campaign Clustering",
    badge="Malaysian APK Malware Intelligence"
)
st.markdown("`PDRM` &nbsp; `BNM` &nbsp; `CyberSecurity Malaysia`")

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

    # ─── Data Visualisation Row ───
    st.markdown("<div style='margin-top: 1rem;'></div>", unsafe_allow_html=True)
    c1, col_gap, c2 = st.columns([1, 0.08, 1.2])
    with c1:
        try:
            from campaign.db import get_connection
            conn = get_connection()
            risk_rows = conn.execute("SELECT risk_level, COUNT(*) as cnt FROM apk_scans GROUP BY risk_level").fetchall()
            risk_data = {r["risk_level"]: r["cnt"] for r in risk_rows}
            conn.close()
        except Exception:
            risk_data = {}

        if risk_data:
            with st.container(border=True):
                import plotly.graph_objects as go
                from utils.styles import apply_plotly_theme
                
                risk_order = ["CLEAN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
                risk_colors = {
                    "CLEAN": "#1e293b",      # Muted slate/dark blue
                    "LOW": "#60a5fa",        # Soft sky blue
                    "MEDIUM": "#3b82f6",     # Vibrant blue
                    "HIGH": "#1d4ed8",       # Deep cobalt blue
                    "CRITICAL": "#00d2ff",   # Glowing electric cyan-blue
                    "UNKNOWN": "#334155"     # Muted dark slate
                }
                
                labels = [level for level in risk_order if level in risk_data and risk_data[level] > 0]
                values = [risk_data[level] for level in labels]
                colors = [risk_colors[level] for level in labels]
                
                for level, count in risk_data.items():
                    if level not in labels and count > 0:
                        labels.append(level)
                        values.append(count)
                        colors.append(risk_colors.get(level, "#95a5a6"))
                
                fig_risk = go.Figure(data=[go.Pie(
                    labels=labels,
                    values=values,
                    hole=.4,
                    marker=dict(colors=colors, line=dict(color="#131b2e", width=2)),
                    textinfo="percent+label",
                    hovertemplate="<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>"
                )])
                fig_risk.update_layout(
                    title=dict(text="Database Risk Profile", font=dict(size=13, color="#f1f5f9"), x=0.02, y=0.98),
                    showlegend=False,
                    height=240,
                    margin=dict(l=10, r=10, t=40, b=10)
                )
                apply_plotly_theme(fig_risk)
                st.plotly_chart(fig_risk, use_container_width=True)

    with c2:
        try:
            import json
            from collections import Counter
            from campaign.db import get_connection
            conn = get_connection()
            perm_rows = conn.execute("SELECT permissions FROM apk_scans WHERE risk_level IN ('HIGH', 'CRITICAL')").fetchall()
            conn.close()
            
            all_perms = []
            for r in perm_rows:
                if r["permissions"]:
                    try:
                        perms_list = json.loads(r["permissions"])
                        all_perms.extend(perms_list)
                    except Exception:
                        pass
            perm_counts = Counter(all_perms).most_common(10)
        except Exception:
            perm_counts = []

        if perm_counts:
            with st.container(border=True):
                import plotly.graph_objects as go
                from utils.styles import apply_plotly_theme
                
                perm_labels = [p[0].split(".")[-1] for p in perm_counts]
                perm_values = [p[1] for p in perm_counts]
                
                perm_labels.reverse()
                perm_values.reverse()
                
                fig_perms = go.Figure(data=[go.Bar(
                    x=perm_values,
                    y=perm_labels,
                    orientation='h',
                    marker=dict(
                        color='rgba(78, 162, 255, 0.7)',
                        line=dict(color='#4ea2ff', width=1.5)
                    ),
                    hovertemplate="<b>%{y}</b><br>Requested in %{x} APKs<extra></extra>"
                )])
                fig_perms.update_layout(
                    title=dict(text="Top Dangerous Capabilities Requested", font=dict(size=13, color="#f1f5f9"), x=0.02, y=0.98),
                    xaxis=dict(title="APK Count", gridcolor="#1c2c47"),
                    yaxis=dict(gridcolor="rgba(0,0,0,0)"),
                    showlegend=False,
                    height=240,
                    margin=dict(l=10, r=10, t=40, b=10)
                )
                apply_plotly_theme(fig_perms)
                st.plotly_chart(fig_perms, use_container_width=True)
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