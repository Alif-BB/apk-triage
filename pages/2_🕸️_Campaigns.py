"""
pages/2_Campaigns.py
Campaign Clustering UI — Feature 2.
"""
import json
import datetime
import streamlit as st
import streamlit.components.v1 as components
import pandas as pd

from campaign.db      import init_db
from campaign.cluster import (
    get_stats,
    get_all_campaigns,
    get_campaign_members,
    get_apk_timeline,
    get_network_graph_data,
    rename_campaign,
    delete_scan,
)
from utils.styles import (
    inject_css, section_header, status_pill, risk_badge,
    ioc_badge, divider_with_label,
)

# ── Ensure DB exists ──────────────────────────────────────────────────────────────
init_db()

# ─── Page Config ──────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Campaign Clustering  |  APK Triage",
    page_icon="🕸️",
    layout="wide"
)

inject_css()  # ← Apply global dark theme + IBM Plex typography

with st.sidebar:
    st.header("⚙️ Settings")
    st.divider()
    with st.expander("⚠️ Danger Zone"):
        if st.button("🗑️ Clear entire database", type="secondary"):
            from campaign.db import get_connection
            conn = get_connection()
            conn.executescript("DELETE FROM c2_indicators; DELETE FROM campaigns; DELETE FROM apk_scans;")
            conn.commit()
            conn.close()
            st.success("Database cleared.")
            st.rerun()

st.title("A-Analyzer — Campaign Clustering")
st.caption("C2 fingerprinting — links APKs that share the same Telegram bot, IP, or URL infrastructure")
st.divider()

# ─── Header Stats ─────────────────────────────────────────────────────────────────
stats = get_stats()

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("📦 APKs Analysed",   stats["total_apks"])
c2.metric("🕸️ Campaigns Found",  stats["total_campaigns"])
c3.metric("🔴 Critical APKs",   stats["critical_apks"])
c4.metric("📱 Telegram C2s",    stats["telegram_c2"])
c5.metric("🌐 IP-based C2s",    stats["ip_c2"])

if stats["total_apks"] == 0:
    st.divider()
    st.info(
        "No APKs in the database yet. "
        "Upload and analyse an APK on the **🔍 Triage** page — "
        "it will be saved here automatically."
    )
    st.stop()

st.divider()

# ─── Main tabs ────────────────────────────────────────────────────────────────────
tab_campaigns, tab_graph, tab_timeline = st.tabs([
    "📋 Campaigns",
    "🕸️ Network Graph",
    "🕐 Timeline",
])

# ══════════════════════════════════════════════════════════════════════════════════
# TAB 1 — Campaign Table + Drilldown
# ══════════════════════════════════════════════════════════════════════════════════
with tab_campaigns:

    col_f1, col_f2 = st.columns([1, 3])
    with col_f1:
        filter_type = st.selectbox(
            "Filter by C2 type",
            ["all", "telegram", "ip", "url"],
            format_func=lambda x: {
                "all": "All types",
                "telegram": "📱 Telegram",
                "ip": "🌐 IP address",
                "url": "🔗 URL",
            }[x]
        )

    campaigns = get_all_campaigns(filter_type)

    if not campaigns:
        st.info("No campaigns match this filter.")
    else:
        RISK_EMOJI = {
            "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
            "LOW": "🟢", "CLEAN": "✅", "UNKNOWN": "⚪"
        }
        C2_EMOJI   = {"telegram": "📱", "ip": "🌐", "url": "🔗"}
        IOC_TYPE   = {"telegram": "telegram", "ip": "ip", "url": "url"}

        st.markdown(f"**{len(campaigns)} campaign(s) found**")

        for camp in campaigns:
            emoji     = C2_EMOJI.get(camp["pivot_type"], "❓")
            apk_count = camp["apk_count"]
            badge     = "🔴 **ACTIVE**" if apk_count >= 3 else ("🟠 **GROWING**" if apk_count >= 2 else "🟡 **SINGLE**")

            with st.expander(
                f"{emoji} {camp['name']}  —  {apk_count} APK(s)  {badge}",
                expanded=(apk_count >= 2)
            ):
                col_info, col_action = st.columns([3, 1])

                with col_info:
                    # Styled pivot IoC badge
                    ioc_badge(camp["pivot_value"], IOC_TYPE.get(camp["pivot_type"], ""))
                    st.markdown(
                        f"First seen: `{camp['first_seen'][:10]}`  |  "
                        f"Last seen: `{camp['last_seen'][:10]}`  |  "
                        f"APKs sharing this C2: **{apk_count}**"
                    )

                with col_action:
                    new_name = st.text_input(
                        "Rename campaign",
                        value=camp["name"],
                        key=f"rename_{camp['id']}"
                    )
                    if st.button("💾 Save name", key=f"save_{camp['id']}"):
                        rename_campaign(camp["id"], new_name)
                        st.success("Name updated — refresh to see change.")

                # ── Member APKs ────────────────────────────────────────────────────
                members = get_campaign_members(camp["pivot_type"], camp["pivot_value"])
                if members:
                    st.markdown("**Linked APKs:**")
                    rows = []
                    for m in members:
                        perms = json.loads(m["permissions"] or "[]")
                        rows.append({
                            "Risk":       f"{RISK_EMOJI.get(m['risk_level'], '⚪')} {m['risk_level']}",
                            "Package":    m["package"],
                            "Score":      m["risk_score"],
                            "GTI":        f"{m['gti_malicious']}/{m['gti_total']}" if m["gti_total"] else "—",
                            "Threat":     m["gti_threat"] or "—",
                            "Analyst":    m["analyst_name"] or "—",
                            "Scanned":    m["scanned_at"][:10],
                            "SHA-256":    m["sha256"][:16] + "…",
                        })
                    st.dataframe(
                        pd.DataFrame(rows),
                        use_container_width=True,
                        hide_index=True,
                    )

                    with st.expander("🗑️ Remove an APK from the database", expanded=False):
                        del_options = {f"{m['package']} ({m['sha256'][:12]}…)": m["id"] for m in members}
                        selected    = st.selectbox("Select APK to delete", list(del_options.keys()), key=f"del_{camp['id']}")
                        if st.button("🗑️ Delete this scan", key=f"delbtn_{camp['id']}", type="secondary"):
                            delete_scan(del_options[selected])
                            st.warning("Scan deleted. Refresh the page.")

# ══════════════════════════════════════════════════════════════════════════════════
# TAB 2 — Network Graph
# ══════════════════════════════════════════════════════════════════════════════════
with tab_graph:

    graph_data = get_network_graph_data()

    if not graph_data["nodes"]:
        st.info("No data to display. Analyse some APKs first.")
    else:
        apk_count_graph = sum(1 for n in graph_data["nodes"] if n["type"] == "apk")
        c2_count_graph  = sum(1 for n in graph_data["nodes"] if n["type"] == "c2")

        st.subheader("APK ↔ C2 Network")
        st.caption(f"{apk_count_graph} APK node(s) connected to {c2_count_graph} C2 node(s) via {len(graph_data['edges'])} edge(s)")

        # Legend pills
        leg_cols = st.columns(6)
        legends = [
            ("🔴 CRITICAL APK",  "critical"),
            ("🟠 HIGH APK",       "warn"),
            ("🟡 MEDIUM APK",     "warn"),
            ("📱 Telegram C2",    "ok"),
            ("🌐 IP C2",          "ok"),
            ("🔗 URL C2",         "ok"),
        ]
        for col, (label, _) in zip(leg_cols, legends):
            with col:
                st.markdown(f"<span style='font-size:12px;color:#7d8590'>{label}</span>", unsafe_allow_html=True)

        nodes    = graph_data["nodes"]
        edges    = graph_data["edges"]
        COLOR_MAP = {
            "CRITICAL": "#e74c3c", "HIGH": "#e67e22", "MEDIUM": "#f39c12",
            "LOW": "#27ae60",      "CLEAN": "#2ecc71", "UNKNOWN": "#95a5a6",
            "telegram": "#2980b9", "ip": "#8e44ad",   "url": "#16a085",
        }

        nodes_js = json.dumps([{
            "id":    n["id"],
            "label": n["label"],
            "title": n["title"],
            "color": n["color"],
            "size":  n["size"],
            "shape": "dot" if n["type"] == "apk" else "diamond",
            "font":  {"size": 11, "color": "#ecf0f1"},
        } for n in nodes])

        edges_js = json.dumps([{
            "from":  e["source"],
            "to":    e["target"],
            "color": {"color": COLOR_MAP.get(e["ioc_type"], "#7f8c8d"), "opacity": 0.7},
            "width": 2,
        } for e in edges])

        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
          <script src="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.6/dist/vis-network.min.js"></script>
          <link  href="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.6/dist/vis-network.min.css" rel="stylesheet"/>
          <style>
            body {{ margin:0; background:#0d1117; }}
            #graph {{ width:100%; height:580px; border:1px solid #30363d; border-radius:8px; }}
          </style>
        </head>
        <body>
          <div id="graph"></div>
          <script>
            var nodes = new vis.DataSet({nodes_js});
            var edges = new vis.DataSet({edges_js});
            var container = document.getElementById("graph");
            var options = {{
              physics: {{
                enabled: true,
                forceAtlas2Based: {{
                  gravitationalConstant: -80,
                  centralGravity: 0.005,
                  springLength: 120,
                  springConstant: 0.08,
                }},
                solver: "forceAtlas2Based",
                stabilization: {{ iterations: 150 }},
              }},
              interaction: {{
                hover: true,
                tooltipDelay: 100,
                navigationButtons: true,
                keyboard: true,
              }},
              nodes: {{
                borderWidth: 2,
                borderWidthSelected: 4,
                shadow: {{ enabled: true, size: 8 }},
              }},
              edges: {{
                smooth: {{ type: "curvedCW", roundness: 0.15 }},
                shadow: {{ enabled: false }},
              }},
            }};
            new vis.Network(container, {{ nodes, edges }}, options);
          </script>
        </body>
        </html>
        """
        components.html(html, height=600, scrolling=False)

        st.caption(
            "🔴/🟠/🟡 = APK nodes coloured by risk level  |  "
            "💠 = C2 nodes (blue=Telegram, purple=IP, teal=URL)  |  "
            "APKs sharing the same C2 node belong to the same campaign."
        )

# ══════════════════════════════════════════════════════════════════════════════════
# TAB 3 — Timeline
# ══════════════════════════════════════════════════════════════════════════════════
with tab_timeline:

    timeline = get_apk_timeline()

    if not timeline:
        st.info("No scans yet.")
    else:
        st.subheader("Scan Timeline")
        st.caption(f"{len(timeline)} APK(s) in database — newest first")

        rows = []
        for scan in timeline:
            rows.append({
                "Risk Level":    scan["risk_level"],
                "Score":         scan["risk_score"],
                "Package":       scan["package"],
                "GTI":           f"{scan['gti_malicious']}/{scan['gti_total']}" if scan["gti_total"] else "—",
                "Threat Label":  scan["gti_threat"] or "—",
                "Analyst":       scan["analyst_name"] or "—",
                "Scanned (UTC)": scan["scanned_at"][:16].replace("T", " "),
            })

        df = pd.DataFrame(rows)
        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Score": st.column_config.ProgressColumn(
                    "Score", min_value=0, max_value=150, format="%d"
                ),
            }
        )

