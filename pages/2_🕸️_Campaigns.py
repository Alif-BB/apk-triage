"""
pages/2_Campaigns.py
Campaign Clustering UI — Feature 2.
"""
import json
import re
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
    get_scan_details,
    save_ai_verdict,
    get_network_graph_data,
    rename_campaign,
    delete_scan,
)
from core.ai         import generate_ai_summary
from core.pdf_report import generate_pdf, sign_pdf_buffer
from core.case_package import generate_case_package
from core.analyser   import get_likelihood
from utils.styles import (
    inject_css, section_header, status_pill, risk_badge,
    ioc_badge, divider_with_label,
)

init_db()

# ─── Page Config ──────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Campaign Clustering  |  APK Triage",
    page_icon="🕸️",
    layout="wide"
)
inject_css()


# ─── Helper: rebuild analyse_apk-style result dict from DB record ─────────────────

def _db_to_result(details: dict) -> dict:
    """
    Reconstructs an analyse_apk-compatible result dict from a DB scan record.
    Activities / services / receivers / URLs are not stored in the DB so they
    default to empty — the PDF sections for those will show 'None'.
    """
    permissions  = json.loads(details.get("permissions") or "[]")
    keywords_raw = json.loads(details.get("keywords")    or "[]")

    telegrams, ips = set(), set()
    for ioc in details.get("indicators", []):
        if ioc["ioc_type"] == "telegram":
            telegrams.add(ioc["ioc_value"])
        elif ioc["ioc_type"] == "ip":
            ips.add(ioc["ioc_value"])

    score = details["risk_score"]
    return {
        "package":    details["package"],
        "version":    details.get("version")    or "",
        "min_sdk":    details.get("min_sdk")    or "",
        "target_sdk": details.get("target_sdk") or "",
        "permissions": permissions,
        "activities":  [],
        "services":    [],
        "receivers":   [],
        "urls":        set(),
        "ips":         ips,
        "telegrams":   telegrams,
        "keywords":    set(keywords_raw),
        "score":       score,
        "likelihood":  get_likelihood(score),
        "md5":         details.get("md5")    or "",
        "sha1":        details.get("sha1")   or "",
        "sha256":      details.get("sha256") or "",
    }


def _db_to_gti(details: dict) -> dict | None:
    """
    Rebuilds a minimal gti dict from the summary columns stored in the DB.
    Full per-IP / per-URL detail is not stored, so only the file block is filled.
    """
    if not details.get("gti_total"):
        return None
    return {
        "file": {
            "malicious":   details["gti_malicious"],
            "suspicious":  0,
            "undetected":  details["gti_total"] - details["gti_malicious"],
            "total":       details["gti_total"],
            "threat_name": details.get("gti_threat") or "Unknown",
            "first_seen":  "N/A",
            "times_seen":  0,
            "link": f"https://www.virustotal.com/gui/file/{details['sha256']}",
        },
        "ips":    {},
        "urls":   {},
        "errors": [],
    }


# ─── Sidebar ──────────────────────────────────────────────────────────────────────

with st.sidebar:
    st.header("⚙️ Settings")

    # AI key — needed for on-demand verdict generation
    gemini_api_key = st.secrets.get("GEMINI_API_KEY", None)
    if gemini_api_key:
        status_pill("AI Analyst enabled", "ok")
    else:
        status_pill("AI not configured — contact admin", "off")

    st.divider()
    with st.expander("⚠️ Danger Zone"):
        if st.button("🗑️ Clear entire database", type="secondary"):
            from campaign.db import get_connection
            conn = get_connection()
            conn.executescript(
                "DELETE FROM c2_indicators; DELETE FROM campaigns; DELETE FROM apk_scans;"
            )
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

    col_f1, _ = st.columns([1, 3])
    with col_f1:
        filter_type = st.selectbox(
            "Filter by C2 type",
            ["all", "telegram", "ip", "url"],
            format_func=lambda x: {
                "all": "All types", "telegram": "📱 Telegram",
                "ip": "🌐 IP address", "url": "🔗 URL",
            }[x]
        )

    campaigns = get_all_campaigns(filter_type)

    if not campaigns:
        st.info("No campaigns match this filter.")
    else:
        RISK_EMOJI = {
            "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
            "LOW": "🟢",      "CLEAN": "✅", "UNKNOWN": "⚪",
        }
        C2_EMOJI = {"telegram": "📱", "ip": "🌐", "url": "🔗"}
        IOC_TYPE = {"telegram": "telegram", "ip": "ip", "url": "url"}

        st.markdown(f"**{len(campaigns)} campaign(s) found**")

        for camp in campaigns:
            emoji     = C2_EMOJI.get(camp["pivot_type"], "❓")
            apk_count = camp["apk_count"]
            badge     = ("🔴 **ACTIVE**"  if apk_count >= 3
                         else "🟠 **GROWING**" if apk_count >= 2
                         else "🟡 **SINGLE**")

            with st.expander(
                f"{emoji} {camp['name']}  —  {apk_count} APK(s)  {badge}",
                expanded=(apk_count >= 2),
            ):
                col_info, col_action = st.columns([3, 1])
                with col_info:
                    ioc_badge(camp["pivot_value"], IOC_TYPE.get(camp["pivot_type"], ""))
                    st.markdown(
                        f"First seen: `{camp['first_seen'][:10]}`  |  "
                        f"Last seen: `{camp['last_seen'][:10]}`  |  "
                        f"APKs sharing this C2: **{apk_count}**"
                    )
                with col_action:
                    new_name = st.text_input("Rename campaign", value=camp["name"],
                                             key=f"rename_{camp['id']}")
                    if st.button("💾 Save name", key=f"save_{camp['id']}"):
                        rename_campaign(camp["id"], new_name)
                        st.success("Name updated — refresh to see change.")

                members = get_campaign_members(camp["pivot_type"], camp["pivot_value"])
                if members:
                    st.markdown("**Linked APKs:**")
                    rows = []
                    for m in members:
                        rows.append({
                            "Risk":    f"{RISK_EMOJI.get(m['risk_level'], '⚪')} {m['risk_level']}",
                            "Package": m["package"],
                            "Score":   m["risk_score"],
                            "GTI":     f"{m['gti_malicious']}/{m['gti_total']}" if m["gti_total"] else "—",
                            "Threat":  m["gti_threat"] or "—",
                            "Analyst": m["analyst_name"] or "—",
                            "Scanned": m["scanned_at"][:10],
                            "SHA-256": m["sha256"][:16] + "…",
                        })
                    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

                    with st.expander("🗑️ Remove an APK from the database", expanded=False):
                        del_options = {
                            f"{m['package']} ({m['sha256'][:12]}…)": m["id"]
                            for m in members
                        }
                        selected = st.selectbox("Select APK to delete",
                                                list(del_options.keys()),
                                                key=f"del_{camp['id']}")
                        if st.button("🗑️ Delete this scan",
                                     key=f"delbtn_{camp['id']}", type="secondary"):
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
        st.caption(
            f"{apk_count_graph} APK node(s) connected to {c2_count_graph} "
            f"C2 node(s) via {len(graph_data['edges'])} edge(s)"
        )
        leg_cols = st.columns(6)
        for col, label in zip(leg_cols, [
            "🔴 CRITICAL APK", "🟠 HIGH APK", "🟡 MEDIUM APK",
            "📱 Telegram C2",  "🌐 IP C2",    "🔗 URL C2",
        ]):
            col.markdown(f"<span style='font-size:12px;color:#7d8590'>{label}</span>",
                         unsafe_allow_html=True)

        COLOR_MAP = {
            "CRITICAL": "#e74c3c", "HIGH": "#e67e22", "MEDIUM": "#f39c12",
            "LOW": "#27ae60",      "CLEAN": "#2ecc71", "UNKNOWN": "#95a5a6",
            "telegram": "#2980b9", "ip":   "#8e44ad",  "url": "#16a085",
        }
        nodes_js = json.dumps([{
            "id":    n["id"],   "label": n["label"],
            "title": n["title"],"color": n["color"],
            "size":  n["size"], "shape": "dot" if n["type"] == "apk" else "diamond",
            "font":  {"size": 11, "color": "#ecf0f1"},
        } for n in graph_data["nodes"]])
        edges_js = json.dumps([{
            "from": e["source"], "to": e["target"],
            "color": {"color": COLOR_MAP.get(e["ioc_type"], "#7f8c8d"), "opacity": 0.7},
            "width": 2,
        } for e in graph_data["edges"]])

        components.html(f"""
        <!DOCTYPE html><html>
        <head>
          <script src="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.6/dist/vis-network.min.js"></script>
          <link  href="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.6/dist/vis-network.min.css" rel="stylesheet"/>
          <style>body{{margin:0;background:#0d1117}}
          #graph{{width:100%;height:580px;border:1px solid #30363d;border-radius:8px}}</style>
        </head>
        <body><div id="graph"></div>
        <script>
          var nodes=new vis.DataSet({nodes_js});
          var edges=new vis.DataSet({edges_js});
          new vis.Network(document.getElementById("graph"),{{nodes,edges}},{{
            physics:{{enabled:true,forceAtlas2Based:{{gravitationalConstant:-80,
              centralGravity:0.005,springLength:120,springConstant:0.08}},
              solver:"forceAtlas2Based",stabilization:{{iterations:150}}}},
            interaction:{{hover:true,tooltipDelay:100,navigationButtons:true,keyboard:true}},
            nodes:{{borderWidth:2,borderWidthSelected:4,shadow:{{enabled:true,size:8}}}},
            edges:{{smooth:{{type:"curvedCW",roundness:0.15}},shadow:{{enabled:false}}}},
          }});
        </script></body></html>
        """, height=600, scrolling=False)
        st.caption(
            "🔴/🟠/🟡 = APK nodes coloured by risk level  |  "
            "💠 = C2 nodes (blue=Telegram, purple=IP, teal=URL)  |  "
            "APKs sharing the same C2 node belong to the same campaign."
        )

# ══════════════════════════════════════════════════════════════════════════════════
# TAB 3 — Timeline  (clickable rows → full scan detail panel)
# ══════════════════════════════════════════════════════════════════════════════════
with tab_timeline:
    timeline = get_apk_timeline()
    if not timeline:
        st.info("No scans yet.")
    else:
        st.subheader("Scan Timeline")
        st.caption(
            f"{len(timeline)} APK(s) in database — newest first  ·  "
            "**Click any row** to view full scan details, generate AI verdict, or export a report"
        )

        RISK_EMOJI = {
            "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
            "LOW": "🟢",      "CLEAN": "✅", "UNKNOWN": "⚪",
        }
        rows = []
        for scan in timeline:
            rows.append({
                "Risk":          f"{RISK_EMOJI.get(scan['risk_level'], '⚪')} {scan['risk_level']}",
                "Score":         scan["risk_score"],
                "Package":       scan["package"],
                "GTI":           f"{scan['gti_malicious']}/{scan['gti_total']}" if scan["gti_total"] else "—",
                "Threat Label":  scan["gti_threat"] or "—",
                "Analyst":       scan["analyst_name"] or "—",
                "Scanned (UTC)": scan["scanned_at"][:16].replace("T", " "),
            })

        selection_event = st.dataframe(
            pd.DataFrame(rows),
            use_container_width=True,
            hide_index=True,
            on_select="rerun",
            selection_mode="single-row",
            column_config={
                "Score": st.column_config.ProgressColumn(
                    "Score", min_value=0, max_value=150, format="%d"
                ),
            },
            key="timeline_table",
        )

        selected_rows = selection_event.selection.rows

        # ── Detail panel ──────────────────────────────────────────────────────────
        if not selected_rows:
            st.html("""
            <div style='text-align:center;padding:28px;margin-top:8px;
                        background:#161b22;border:1px dashed #30363d;border-radius:8px;
                        color:#7d8590;font-family:IBM Plex Sans,sans-serif;font-size:13px'>
              👆 Click any row in the table above to view full scan details
            </div>
            """)
        else:
            idx     = selected_rows[0]
            scan_id = timeline[idx]["id"]
            details = get_scan_details(scan_id)

            if not details:
                st.error("Could not load scan details.")
            else:
                st.divider()

                RISK_COLOR = {
                    "CRITICAL": "#e74c3c", "HIGH": "#e67e22", "MEDIUM": "#f39c12",
                    "LOW": "#27ae60",      "CLEAN": "#2ecc71", "UNKNOWN": "#95a5a6",
                }
                risk_color  = RISK_COLOR.get(details["risk_level"], "#95a5a6")
                likelihood  = min(round((details["risk_score"] / 300) * 100), 100)
                result      = _db_to_result(details)
                gti_minimal = _db_to_gti(details)
                analyst_full = details.get("analyst_name") or ""
                if details.get("analyst_org"):
                    analyst_full += f" — {details['analyst_org']}"

                # ── Panel header ─────────────────────────────────────────────────
                st.html(f"""
                <div style="display:flex;align-items:center;gap:14px;
                            padding:14px 18px;margin-bottom:4px;
                            background:#161b22;border:1px solid #30363d;
                            border-left:4px solid {risk_color};border-radius:8px">
                  <div style="flex:1;min-width:0">
                    <div style="font-family:'IBM Plex Mono',monospace;font-size:14px;
                                font-weight:600;color:#e6edf3;margin-bottom:3px;
                                word-break:break-all">{details['package']}</div>
                    <div style="font-size:12px;color:#7d8590">
                      Scan #{details['id']}
                      &nbsp;·&nbsp; v{details['version'] or '—'}
                      &nbsp;·&nbsp; Scanned {details['scanned_at'][:16].replace('T',' ')} UTC
                    </div>
                  </div>
                  <span style="font-size:13px;font-weight:700;padding:5px 14px;
                               border-radius:20px;white-space:nowrap;
                               background:{risk_color}22;color:{risk_color};
                               border:1px solid {risk_color}55;
                               font-family:'IBM Plex Mono',monospace">
                    {details['risk_level']} · {likelihood}%
                  </span>
                </div>
                """)

                # ── Quick metrics ─────────────────────────────────────────────────
                m1, m2, m3, m4 = st.columns(4)
                m1.metric("Risk Score",  f"{details['risk_score']} / 300")
                m2.metric("Min SDK",     details["min_sdk"]    or "—")
                m3.metric("Target SDK",  details["target_sdk"] or "—")
                m4.metric("GTI Engines",
                          f"{details['gti_malicious']}/{details['gti_total']}"
                          if details["gti_total"] else "Not checked")

                # ── Evidence integrity ────────────────────────────────────────────
                with st.expander("🔐 Evidence Integrity", expanded=True):
                    for label, val in [
                        ("MD5",     details.get("md5",    "—")),
                        ("SHA-1",   details.get("sha1",   "—")),
                        ("SHA-256", details.get("sha256", "—")),
                    ]:
                        r1, r2 = st.columns([1, 3], vertical_alignment="center")
                        with r1:
                            st.markdown(f"**{label}**")
                        with r2:
                            st.code(val, language=None)
                    r1, r2 = st.columns([1, 3], vertical_alignment="center")
                    with r1:
                        st.markdown("**Analyst**")
                    with r2:
                        st.markdown(
                            f"<div style='padding:8px 0;font-size:14px'>"
                            f"{analyst_full.strip(' —') or 'Not specified'}</div>",
                            unsafe_allow_html=True,
                        )
                    if details.get("case_number"):
                        r1, r2 = st.columns([1, 3], vertical_alignment="center")
                        with r1:
                            st.markdown("**Case Ref**")
                        with r2:
                            st.markdown(
                                f"<div style='padding:8px 0;font-size:14px'>"
                                f"`{details['case_number']}`</div>",
                                unsafe_allow_html=True,
                            )

                # ── Permissions + C2 indicators ───────────────────────────────────
                left_col, right_col = st.columns(2)
                with left_col:
                    perms = json.loads(details.get("permissions") or "[]")
                    with st.expander(f"🔒 Dangerous Permissions ({len(perms)})",
                                     expanded=bool(perms)):
                        if perms:
                            for p in perms:
                                st.markdown(
                                    f"<div style='padding:5px 10px;margin:3px 0;"
                                    f"background:#1c2330;border-left:3px solid #e74c3c;"
                                    f"border-radius:4px;font-family:IBM Plex Mono,monospace;"
                                    f"font-size:12px;color:#e6edf3'>{p}</div>",
                                    unsafe_allow_html=True,
                                )
                        else:
                            st.success("No dangerous permissions recorded.")

                with right_col:
                    indicators = details.get("indicators", [])
                    with st.expander(f"🎯 C2 Indicators ({len(indicators)})",
                                     expanded=bool(indicators)):
                        if indicators:
                            C2_COLOUR = {"telegram": "#2980b9", "ip": "#8e44ad", "url": "#16a085"}
                            C2_LABEL  = {"telegram": "TG",      "ip": "IP",      "url": "URL"}
                            for ioc in indicators:
                                colour = C2_COLOUR.get(ioc["ioc_type"], "#58a6ff")
                                label  = C2_LABEL.get(ioc["ioc_type"], "IOC")
                                st.html(f"""
                                <div style='display:flex;align-items:center;gap:8px;
                                            padding:6px 10px;margin:3px 0;
                                            background:#161b22;border:1px solid #30363d;
                                            border-left:3px solid {colour};border-radius:5px'>
                                  <span style='color:{colour};font-size:10px;font-weight:600;
                                               background:{colour}22;padding:1px 5px;
                                               border-radius:3px;font-family:IBM Plex Mono,monospace;
                                               white-space:nowrap'>{label}</span>
                                  <span style='color:#e6edf3;font-family:IBM Plex Mono,monospace;
                                               font-size:12px;word-break:break-all'>{ioc['ioc_value']}</span>
                                </div>
                                """)
                        else:
                            st.info("No C2 indicators recorded for this scan.")

                # ── Banking keywords ──────────────────────────────────────────────
                kw_list = []
                try:
                    kw_list = json.loads(details.get("keywords") or "[]")
                except Exception:
                    pass
                if kw_list:
                    st.markdown(
                        "**🏦 Banking keywords detected:** "
                        + "  ".join(f"`{k}`" for k in kw_list)
                    )

                # ── GTI threat label ──────────────────────────────────────────────
                if details.get("gti_threat"):
                    st.error(f"🏷️ GTI Threat Label: **{details['gti_threat']}**")

                st.divider()

                # ════════════════════════════════════════════════════════════════
                # AI VERDICT
                # ════════════════════════════════════════════════════════════════
                section_header("AI Analyst Verdict", "Gemini-powered plain-English summary")

                current_verdict = details.get("ai_verdict") or ""

                if current_verdict:
                    # ── Display stored verdict ────────────────────────────────────
                    paragraphs = [p.strip() for p in current_verdict.strip().split("\n\n") if p.strip()]
                    paras_html = "".join(
                        f"<p style='margin:0 0 10px;line-height:1.7;font-size:13px;"
                        f"color:#c9d1d9;font-family:IBM Plex Sans,sans-serif'>{p}</p>"
                        for p in paragraphs
                    )
                    st.html(f"""
                    <div style='background:#161b22;border:1px solid #30363d;
                                border-left:3px solid #f39c12;border-radius:8px;
                                padding:14px 16px;margin:4px 0'>
                      <div style='font-size:10px;font-weight:600;color:#f39c12;
                                  text-transform:uppercase;letter-spacing:0.08em;
                                  margin-bottom:10px;font-family:IBM Plex Sans,sans-serif'>
                        🤖 AI Analyst Verdict &nbsp;·&nbsp;
                        <span style='font-weight:400;color:#7d8590'>
                          AI-generated — not a definitive forensic finding
                        </span>
                      </div>
                      {paras_html}
                    </div>
                    """)

                    # Allow re-generating if AI is available
                    if gemini_api_key:
                        if st.button("🔄 Re-generate verdict", key=f"regen_{scan_id}"):
                            with st.spinner("Generating AI verdict via Gemini…"):
                                new_verdict = generate_ai_summary(result, gemini_api_key, gti_minimal)
                            save_ai_verdict(scan_id, new_verdict)
                            st.success("Verdict updated — reloading…")
                            st.rerun()
                    else:
                        st.caption("AI re-generation disabled — no Gemini API key configured.")

                else:
                    # ── No verdict yet ────────────────────────────────────────────
                    if gemini_api_key:
                        st.html("""
                        <div style='padding:14px 16px;background:#161b22;
                                    border:1px dashed #30363d;border-radius:8px;
                                    color:#7d8590;font-size:13px;
                                    font-family:IBM Plex Sans,sans-serif'>
                          No AI verdict was generated when this APK was originally scanned.
                          Click the button below to generate one now.
                        </div>
                        """)
                        if st.button("🤖 Generate AI Verdict", key=f"gen_{scan_id}",
                                     type="primary"):
                            with st.spinner("Generating AI verdict via Gemini…"):
                                new_verdict = generate_ai_summary(result, gemini_api_key, gti_minimal)
                            save_ai_verdict(scan_id, new_verdict)
                            st.success("Verdict generated and saved — reloading…")
                            st.rerun()
                    else:
                        st.html("""
                        <div style='padding:12px 16px;background:#161b22;
                                    border:1px solid #30363d;border-radius:8px;
                                    color:#7d8590;font-size:13px;
                                    font-family:IBM Plex Sans,sans-serif'>
                          ○ AI verdicts not configured — add a Gemini API key to
                          <code>.streamlit/secrets.toml</code>.
                        </div>
                        """)

                st.divider()

                # ════════════════════════════════════════════════════════════════
                # EXPORT — PDF REPORT / CASE PACKAGE
                # ════════════════════════════════════════════════════════════════
                section_header("Export Report", "Generate a court-ready PDF or full case package for this scan")

                ai_for_export = details.get("ai_verdict") or None

                # Classification selector (not stored in DB, default RESTRICTED)
                classification = st.selectbox(
                    "Document Classification",
                    ["RESTRICTED", "CONFIDENTIAL", "SECRET", "UNCLASSIFIED"],
                    index=0,
                    key=f"cls_{scan_id}",
                )

                ts_str   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                safe_pkg = re.sub(r"[^\w.]", "_", details["package"])
                fname    = f"{safe_pkg}_{ts_str}"

                exp_col1, exp_col2, exp_col3 = st.columns(3)

                # ── Unsigned PDF ──────────────────────────────────────────────────
                with exp_col1:
                    st.markdown("#### 📄 PDF Report")
                    st.caption("Quick forensic report — unsigned")
                    try:
                        pdf_buf = generate_pdf(
                            result,
                            analyst_full or "Not specified",
                            ai_for_export,
                            gti_minimal,
                        )
                        st.download_button(
                            label="⬇️ Download PDF (unsigned)",
                            data=pdf_buf,
                            file_name=f"triage_{fname}.pdf",
                            mime="application/pdf",
                            use_container_width=True,
                            key=f"dl_pdf_{scan_id}",
                        )
                    except Exception as e:
                        st.error(f"PDF generation failed: {e}")

                # ── Signed PDF ────────────────────────────────────────────────────
                with exp_col2:
                    st.markdown("#### 🔏 Signed PDF")
                    st.caption("Digitally signed — court-admissible")
                    try:
                        pdf_buf_s = generate_pdf(
                            result,
                            analyst_full or "Not specified",
                            ai_for_export,
                            gti_minimal,
                        )
                        signed = sign_pdf_buffer(
                            pdf_buf_s, details.get("analyst_name") or "Unknown Analyst"
                        )
                        st.download_button(
                            label="⬇️ Download Signed PDF",
                            data=signed,
                            file_name=f"triage_{fname}_signed.pdf",
                            mime="application/pdf",
                            use_container_width=True,
                            key=f"dl_signed_{scan_id}",
                        )
                    except Exception as e:
                        st.error(f"Signing failed: {e}")

                # ── Full case package ─────────────────────────────────────────────
                with exp_col3:
                    st.markdown("#### 📦 Case Package")
                    st.caption("ZIP: signed PDF + JSON + incident report + CoC log")
                    try:
                        case_zip = generate_case_package(
                            result,
                            details.get("analyst_name")  or "",
                            details.get("analyst_org")   or "",
                            details.get("case_number")   or "",
                            classification,
                            gti_minimal,
                            ai_for_export,
                        )
                        st.download_button(
                            label="⬇️ Download Case Package (.zip)",
                            data=case_zip,
                            file_name=f"case_package_{fname}.zip",
                            mime="application/zip",
                            use_container_width=True,
                            key=f"dl_zip_{scan_id}",
                        )
                    except Exception as e:
                        st.error(f"Package generation failed: {e}")

                st.caption(
                    "ℹ️ App components (receivers, services, activities) and URL IoCs are not "
                    "stored in the database — those sections will show 'None' in the exported report."
                )

