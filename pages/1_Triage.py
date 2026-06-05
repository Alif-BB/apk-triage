import re
import os
import json
import datetime
import tempfile
import streamlit as st

from core.analyser      import analyse_apk, get_risk_level, get_likelihood, DANGEROUS_PERMISSIONS
from core.gti           import check_virustotal, gti_score_boost
from core.ai            import generate_ai_summary
from core.pdf_report    import generate_pdf, sign_pdf_buffer
from campaign.db        import init_db
from campaign.store     import save_scan
from utils.styles       import (
    inject_css, section_header, status_pill, risk_badge,
    ioc_badge, permission_card, divider_with_label,
    ai_verdict_box, analysis_stepper,
)

init_db()

from core.case_package  import (
    generate_case_json,
    generate_bnmlink_template,
    generate_chain_of_custody_log,
    generate_case_package,
)

# ─── Page Config ─────────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="APK Triage  |  Powered by VirusTotal",
    page_icon="search",
    layout="wide"
)

inject_css()

st.title("A-Analyzer — APK Triage Tool")
st.caption("Static analysis + VirusTotal enrichment for Malaysian financial scam APKs")
st.divider()

# ─── Sidebar ─────────────────────────────────────────────────────────────────────

with st.sidebar:
    st.header("Settings")

    # ── Analyst Identity
    st.subheader("Analyst Identity")
    st.caption("Embedded in all exported files")
    analyst_name = st.text_input(
        "Name / badge number",
        placeholder="e.g. Insp. Ahmad bin Ali  D/12345",
        help="Embedded in the PDF for chain-of-custody purposes"
    )
    analyst_org = st.text_input(
        "Unit / organisation",
        placeholder="e.g. PDRM Cyber Crime D11, KL",
        help="Included in the Evidence Integrity section of the report"
    )
    full_analyst = f"{analyst_name} — {analyst_org}" if analyst_org else analyst_name

    st.divider()

    # ── Case Details
    st.subheader("Case Details")
    case_number = st.text_input(
        "Case / Report Number",
        placeholder="e.g. CCID/KL/2025/00123",
        help="Reference number for this investigation — embedded in all exported files"
    )
    classification = st.selectbox(
        "Document Classification",
        ["RESTRICTED", "CONFIDENTIAL", "SECRET", "UNCLASSIFIED"],
        index=0,
        help="Classification marking applied to all exported documents"
    )

    # ── TLP Classification
    tlp = st.selectbox(
        "TLP Classification",
        ["GREEN", "WHITE", "AMBER", "RED"],
        index=0,
        help=(
            "Traffic Light Protocol — controls how recipients may share this report.\n\n"
            "WHITE  = unrestricted public sharing\n"
            "GREEN  = share within the community (default for inter-agency)\n"
            "AMBER  = share on need-to-know basis only\n"
            "RED    = do not share outside named recipients"
        )
    )

    st.divider()

    # ── VirusTotal
    st.subheader("VirusTotal")
    vt_api_key = st.secrets.get("VT_API_KEY", None) or st.text_input(
        "VirusTotal API Key",
        type="password",
        placeholder="Paste your VT API key",
        help="Get a free key at virustotal.com"
    )
    if vt_api_key:
        status_pill("VirusTotal key loaded", "ok")
    else:
        status_pill("No VirusTotal key — enrichment disabled", "off")

    st.divider()

    # ── Gemini AI
    st.subheader("AI Settings")
    gemini_api_key = st.secrets.get("GEMINI_API_KEY", None)
    if gemini_api_key:
        status_pill("AI Analyst enabled", "ok")
    else:
        status_pill("AI not configured — contact admin", "off")

    st.divider()
    st.caption("PDF reports include SHA-256 hash + digital signature for court-admissible chain of custody.")

# ─── File Upload ──────────────────────────────────────────────────────────────────

uploaded_file = st.file_uploader("Upload an APK file", type=["apk"])

if uploaded_file:
    if not analyst_name:
        st.warning("No analyst name entered. Add your name in the sidebar for a complete chain-of-custody report.")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
        tmp.write(uploaded_file.read())
        tmp_path = tmp.name

    stepper_placeholder = st.empty()

    with stepper_placeholder:
        analysis_stepper([
            ("Static Analysis", "active"),
            ("VirusTotal",      "pending"),
            ("AI Verdict",      "pending"),
            ("Saved",           "pending"),
        ])

    # ── Static Analysis
    with st.spinner("Running static analysis..."):
        try:
            result = analyse_apk(tmp_path)
        except Exception as e:
            st.error(f"Analysis failed: {e}")
            os.unlink(tmp_path)
            st.stop()

    # ── VirusTotal Enrichment
    gti = None
    if vt_api_key:
        with stepper_placeholder:
            analysis_stepper([
                ("Static Analysis", "done"),
                ("VirusTotal",      "active"),
                ("AI Verdict",      "pending"),
                ("Saved",           "pending"),
            ])
        with st.spinner("Querying VirusTotal..."):
            gti = check_virustotal(tmp_path, result, vt_api_key)
            result["score"] += gti_score_boost(gti)

    os.unlink(tmp_path)

    # ── Auto-save to Campaign DB
    with st.spinner("Saving to campaign database..."):
        scan_id = save_scan(
            result,
            analyst_name=analyst_name,
            analyst_org=analyst_org,
            case_number=case_number,
            gti=gti,
            ai_summary=None,
        )

    with stepper_placeholder:
        analysis_stepper([
            ("Static Analysis", "done"),
            ("VirusTotal",      "done" if gti else "pending"),
            ("AI Verdict",      "pending"),
            ("Saved",           "done"),
        ])

    if scan_id:
        st.success(f"Saved to campaign database (Scan #{scan_id})")
    else:
        st.info("This APK was already in the campaign database (duplicate SHA-256).")

    risk_level, risk_color = get_risk_level(result["score"])

    # ── Risk Gauge
    divider_with_label("Risk Assessment")
    col1, col2, col3 = st.columns([1.2, 2, 1.2])
    with col1:
        st.metric("Package", result["package"])
        st.metric("Version", result["version"])

    with col2:
        likelihood = get_likelihood(result["score"])
        st.markdown(
            f"""
            <div style='text-align:center; padding:20px; border-radius:12px;
                        background-color:{risk_color}22; border:2px solid {risk_color}'>
                <div style='font-size:48px; font-weight:bold; color:{risk_color}'>{risk_level}</div>
                <div style='font-size:32px; font-weight:bold; color:{risk_color}'>{likelihood}%</div>
                <div style='font-size:13px; color:#aaa; margin-top:2px'>likelihood of malicious behaviour</div>
                <div style='font-size:11px; color:#666; margin-top:6px'>raw score: {result["score"]} / 300</div>
                <div style='font-size:13px; color:#888; margin-top:6px'>
                    {"VirusTotal enriched" if gti else "Static analysis only"}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
        st.progress(likelihood / 100)

    with col3:
        st.metric("Min SDK",    result["min_sdk"])
        st.metric("Target SDK", result["target_sdk"])

    # ── Evidence Integrity
    divider_with_label("Evidence Integrity")
    with st.expander("Evidence Integrity", expanded=True):
        integrity_data = [
            ("MD5", result["md5"], True),
            ("SHA-1", result["sha1"], True),
            ("SHA-256", result["sha256"], True),
            ("Analyst", full_analyst.strip(" —") or "Not specified", False),
            ("Timestamp (UTC)", datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"), False),
        ]

        for label, val, is_code in integrity_data:
            row_c1, row_c2 = st.columns([1, 3], vertical_alignment="center")
            with row_c1:
                st.markdown(f"**{label}**")
            with row_c2:
                if is_code:
                    st.code(val, language=None)
                else:
                    st.markdown(f"<div style='padding: 8px 0; font-size: 14px;'>{val}</div>", unsafe_allow_html=True)

        st.write("")
        st.caption("SHA-256 uniquely identifies this exact APK. Any modification changes the hash, detecting tampering.")

    # ── VirusTotal Results
    divider_with_label("VirusTotal")
    section_header("VirusTotal Results", "Hash, IP, and URL reputation enrichment")

    if gti:
        if gti.get("errors"):
            for err in gti["errors"]:
                st.warning(f"{err}")

        file_data = gti.get("file")
        if file_data:
            if file_data.get("not_found"):
                st.info("APK hash **not found** in VirusTotal — may be a new or private sample. Treat with caution.")
            else:
                malicious = file_data["malicious"]
                total     = file_data["total"]
                if malicious > 10:
                    st.error(f"**{malicious}/{total} antivirus engines flagged this APK as malicious**")
                elif malicious > 0:
                    st.warning(f"**{malicious}/{total} engines flagged this APK**")
                else:
                    st.success(f"**0/{total} engines detected threats in this APK**")

                col_a, col_b, col_c = st.columns(3)
                col_a.metric("Malicious",  file_data["malicious"])
                col_b.metric("Suspicious", file_data["suspicious"])
                col_c.metric("Times Seen", file_data["times_seen"])

                if file_data.get("threat_name") and file_data["threat_name"] != "Unknown":
                    st.error(f"Threat Label: **{file_data['threat_name']}**")
                st.markdown(f"[View full report on VirusTotal]({file_data['link']})")

        if gti.get("ips"):
            st.markdown("**IP Address Reputation:**")
            for ip, data in gti["ips"].items():
                if data:
                    ioc_badge(
                        f"{ip}  —  {data['malicious']}/{data['total']} detections  |  "
                        f"{data.get('country', '?')}  |  {data.get('owner', '?')}",
                        "ip"
                    )
                else:
                    st.markdown(f"`{ip}` — Not found in VirusTotal")

        if gti.get("urls"):
            st.markdown("**URL Reputation:**")
            for url, data in gti["urls"].items():
                if data:
                    short = url[:60] + "..." if len(url) > 60 else url
                    ioc_badge(f"{short}  —  {data['malicious']}/{data['total']} detections", "url")
                else:
                    st.markdown(f"`{url[:60]}` — Not found in VirusTotal")
    else:
        status_pill("Add your VirusTotal API key in the sidebar to enable enrichment", "warn")

    # ── AI Verdict
    divider_with_label("AI Analyst Verdict")
    ai_summary = None
    if gemini_api_key:
        with stepper_placeholder:
            analysis_stepper([
                ("Static Analysis", "done"),
                ("VirusTotal",      "done" if gti else "pending"),
                ("AI Verdict",      "active"),
                ("Saved",           "done"),
            ])
        with st.spinner("Generating AI analysis..."):
            ai_summary = generate_ai_summary(result, gemini_api_key, gti)
        ai_verdict_box(ai_summary)

        with stepper_placeholder:
            analysis_stepper([
                ("Static Analysis", "done"),
                ("VirusTotal",      "done" if gti else "pending"),
                ("AI Verdict",      "done"),
                ("Saved",           "done"),
            ])
    else:
        status_pill("AI verdicts not configured — contact admin", "off")

    st.divider()

    # ── Permissions & IoCs
    left, right = st.columns(2)

    with left:
        section_header("Permissions", "Dangerous capabilities detected")
        danger_count = 0
        for perm in result["permissions"]:
            if perm in DANGEROUS_PERMISSIONS:
                desc, score = DANGEROUS_PERMISSIONS[perm]
                permission_card(perm.split(".")[-1], desc, score)
                danger_count += 1
            else:
                st.text(f"  {perm.split('.')[-1]}")
        if danger_count == 0:
            st.success("No dangerous permissions found.")

    with right:
        section_header("Indicators of Compromise", "Extracted C2 and network IoCs")

        if result["telegrams"]:
            st.error("**Telegram C2 detected**  `confidence: HIGH`")
            for t in result["telegrams"]:
                ioc_badge(t, "telegram")

        if result["ips"]:
            st.warning("**Hardcoded IP addresses**  `confidence: MEDIUM`")
            for ip in result["ips"]:
                gti_suffix = ""
                if gti and gti["ips"].get(ip):
                    m = gti["ips"][ip].get("malicious", 0)
                    gti_suffix = f"  — VirusTotal: {m} detections" if m > 0 else "  — VirusTotal: clean"
                ioc_badge(f"{ip}{gti_suffix}", "ip")

        if result["urls"]:
            with st.expander(f"URLs found ({len(result['urls'])})  `confidence: LOW`"):
                for u in result["urls"]:
                    gti_suffix = ""
                    if gti and gti["urls"].get(u):
                        m = gti["urls"][u].get("malicious", 0)
                        gti_suffix = f"  — VirusTotal: {m} detections" if m > 0 else "  — VirusTotal: clean"
                    ioc_badge(f"{u}{gti_suffix}", "url")

        if result["keywords"]:
            st.warning(f"**Banking keywords:** {', '.join(result['keywords'])}")

        if not result["telegrams"] and not result["ips"] and not result["keywords"]:
            st.success("No IoCs detected.")

    st.divider()

    # ── App Components
    section_header("App Components", "Receivers, services, and activities declared in the manifest")
    c1, c2, c3 = st.columns(3)

    with c1:
        with st.expander(f"Receivers ({len(result['receivers'])})"):
            for r in result["receivers"]:
                label = r.split(".")[-1]
                if re.search(r'(?i)sms|boot', r):
                    st.error(label)
                else:
                    st.text(label)

    with c2:
        with st.expander(f"Services ({len(result['services'])})"):
            for s in result["services"]:
                st.text(s.split(".")[-1])

    with c3:
        with st.expander(f"Activities ({len(result['activities'])})"):
            for a in result["activities"]:
                st.text(a.split(".")[-1])

    st.divider()

    # ── Case Package Export
    section_header("Export Case Package", "Court-ready bundle for BNMLINK / Cyber999 / PDRM CCID")
    st.markdown(
        "The **Case Package** bundles everything an investigator needs — generated in one click."
    )

    with st.expander("What's inside the Case Package?", expanded=False):
        st.markdown("""
| File | Purpose |
|------|---------|
| `triage_report_*_signed.pdf` | Court-ready forensic report with digital signature + analysis environment |
| `evidence_*.json` | Machine-readable evidence with TLP marking + IoC confidence levels |
| `incident_report_template_*.txt` | Pre-filled submission — victim fields at top, NSRC 997 as step 1 |
| `chain_of_custody_*.csv` | Timestamped chain-of-custody log with handover rows |
| `README.txt` | Submission contacts and file guide |
        """)

    CLASS_COLORS = {
        "RESTRICTED":   "#e67e22",
        "CONFIDENTIAL": "#e74c3c",
        "SECRET":       "#8e44ad",
        "UNCLASSIFIED": "#27ae60",
    }
    TLP_COLORS = {
        "WHITE": "#ecf0f1",
        "GREEN": "#27ae60",
        "AMBER": "#f39c12",
        "RED":   "#e74c3c",
    }
    cls_color = CLASS_COLORS.get(classification, "#888")
    tlp_color = TLP_COLORS.get(tlp, "#888")

    badge_col1, badge_col2 = st.columns(2)
    with badge_col1:
        st.markdown(
            f"<div style='text-align:center; padding:8px; border-radius:6px; "
            f"background:{cls_color}22; border:1.5px solid {cls_color}; "
            f"color:{cls_color}; font-weight:bold; font-size:15px; letter-spacing:2px'>"
            f"{classification}</div>",
            unsafe_allow_html=True
        )
    with badge_col2:
        st.markdown(
            f"<div style='text-align:center; padding:8px; border-radius:6px; "
            f"background:{tlp_color}22; border:1.5px solid {tlp_color}; "
            f"color:{tlp_color}; font-weight:bold; font-size:15px; letter-spacing:2px'>"
            f"TLP:{tlp}</div>",
            unsafe_allow_html=True
        )

    st.caption(f"Case Ref: **{case_number or 'UNASSIGNED'}** — set in sidebar")
    st.markdown("")

    safe_pkg = re.sub(r'[^\w.]', '_', result['package'])
    filename_base = f"triage_{safe_pkg}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
    col_a, col_b, col_c = st.columns(3)

    with col_a:
        st.markdown("#### Case Package")
        st.caption("ZIP containing signed PDF + JSON + incident template + CoC log")
        with st.spinner("Building case package..."):
            try:
                case_zip = generate_case_package(
                    result, analyst_name, analyst_org,
                    case_number, classification, gti, ai_summary, tlp
                )
                st.download_button(
                    label="Download Case Package (.zip)",
                    data=case_zip,
                    file_name=f"case_package_{filename_base}.zip",
                    mime="application/zip",
                    use_container_width=True,
                )
            except Exception as e:
                st.error(f"Package generation failed: {e}")

    with col_b:
        st.markdown("#### PDF Report")
        st.caption("Unsigned PDF — quick preview or internal use")
        unsigned_pdf = generate_pdf(result, full_analyst, ai_summary, gti)
        st.download_button(
            label="Download PDF (unsigned)",
            data=unsigned_pdf,
            file_name=f"{filename_base}.pdf",
            mime="application/pdf",
            use_container_width=True,
        )

    with col_c:
        st.markdown("#### JSON Evidence File")
        st.caption("Machine-readable — includes TLP marking + IoC confidence levels")
        evidence_json = generate_case_json(
            result, analyst_name, analyst_org,
            case_number, classification, gti, ai_summary, tlp
        )
        st.download_button(
            label="Download evidence.json",
            data=json.dumps(evidence_json, indent=2, default=str),
            file_name=f"evidence_{filename_base}.json",
            mime="application/json",
            use_container_width=True,
        )

    st.divider()

    with st.expander("Preview: BNMLINK / Cyber999 Incident Report Template", expanded=False):
        template_text = generate_bnmlink_template(
            result, analyst_name, analyst_org, case_number, classification, gti, tlp
        )
        st.text(template_text)
        st.download_button(
            label="Download Incident Report (.txt)",
            data=template_text,
            file_name=f"incident_report_{filename_base}.txt",
            mime="text/plain",
        )

    with st.expander("Preview: Chain of Custody Log", expanded=False):
        coc_csv = generate_chain_of_custody_log(
            result, analyst_name, analyst_org, case_number
        )
        st.code(coc_csv, language=None)
        st.download_button(
            label="Download Chain of Custody (.csv)",
            data=coc_csv,
            file_name=f"chain_of_custody_{filename_base}.csv",
            mime="text/csv",
        )

    st.caption("Signed PDF uses a self-signed certificate. For court submission, replace with an agency-issued PKI certificate.")