import streamlit as st
import tempfile
import os
import re
from io import BytesIO
from datetime import datetime

from loguru import logger
logger.disable("androguard")
from androguard.misc import AnalyzeAPK

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.units import cm

import google.generativeai as genai

# ─── Patterns & Rules ────────────────────────────────────────────────────────────

URL_PATTERN      = re.compile(r'https?://[^\s\'"<>]{4,}')
IP_PATTERN       = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
TELEGRAM_PATTERN = re.compile(r'(?:bot\d{8,12}:[A-Za-z0-9_-]{35,}|t\.me/[^\s\'"]{3,})')
KEYWORD_PATTERN  = re.compile(r'(?i)(maybank|cimb|rhb|pbebank|hongleong|bankislam|TAC|OTP|transaction)')
EXCLUDED_IPS     = {"127.0.0.1", "0.0.0.0", "255.255.255.255"}

DANGEROUS_PERMISSIONS = {
    "android.permission.RECEIVE_SMS":              ("Intercepts incoming SMS — steals TAC/OTP codes", 30),
    "android.permission.READ_SMS":                 ("Reads all SMS messages on the device", 25),
    "android.permission.SEND_SMS":                 ("Sends SMS silently without user knowledge", 20),
    "android.permission.BIND_ACCESSIBILITY_SERVICE":("Enables overlay attacks on other apps", 30),
    "android.permission.SYSTEM_ALERT_WINDOW":      ("Draws over other apps — phishing overlay", 25),
    "android.permission.REQUEST_INSTALL_PACKAGES": ("Silently installs other APKs — dropper behaviour", 20),
    "android.permission.READ_CONTACTS":            ("Harvests contact list for scam propagation", 15),
    "android.permission.RECORD_AUDIO":             ("Records microphone — spyware behaviour", 15),
    "android.permission.PROCESS_OUTGOING_CALLS":   ("Intercepts and redirects phone calls", 15),
    "android.permission.READ_CALL_LOG":            ("Reads full call history", 15),
    "android.permission.CAMERA":                   ("Access camera without user interaction", 10),
}

def get_risk_level(score):
    if score == 0:
        return "CLEAN",    "#2ecc71"
    elif score < 30:
        return "LOW",      "#27ae60"
    elif score < 60:
        return "MEDIUM",   "#f39c12"
    elif score < 90:
        return "HIGH",     "#e67e22"
    else:
        return "CRITICAL", "#e74c3c"

# ─── Core Analysis Function ──────────────────────────────────────────────────────

def analyse_apk(filepath):
    apk, dex, analysis = AnalyzeAPK(filepath)

    all_strings = [s.get_value() for s in analysis.get_strings()]
    urls, ips, telegrams, keywords = set(), set(), set(), set()

    for s in all_strings:
        urls.update(URL_PATTERN.findall(s))
        ips.update(IP_PATTERN.findall(s))
        telegrams.update(TELEGRAM_PATTERN.findall(s))
        keywords.update(KEYWORD_PATTERN.findall(s))

    ips -= EXCLUDED_IPS

    score = 0
    permissions = apk.get_permissions()
    for perm in permissions:
        if perm in DANGEROUS_PERMISSIONS:
            score += DANGEROUS_PERMISSIONS[perm][1]

    receivers = apk.get_receivers()
    for r in receivers:
        if re.search(r'(?i)sms', r):
            score += 25
            break
        if re.search(r'(?i)boot', r):
            score += 15
            break

    if telegrams:
        score += 40 * len(telegrams)
    if ips:
        score += 20 * len(ips)
    if keywords:
        score += 10

    return {
        "package":     apk.get_package(),
        "version":     apk.get_androidversion_name(),
        "min_sdk":     apk.get_min_sdk_version(),
        "target_sdk":  apk.get_target_sdk_version(),
        "permissions": permissions,
        "activities":  apk.get_activities(),
        "services":    apk.get_services(),
        "receivers":   receivers,
        "urls":        urls,
        "ips":         ips,
        "telegrams":   telegrams,
        "keywords":    set(k.upper() for k in keywords),
        "score":       score,
    }

# ─── Gemini AI Summary ───────────────────────────────────────────────────────────

def generate_ai_summary(result, api_key):
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-2.5-flash")

        danger_perms = [p.split(".")[-1] for p in result["permissions"]
                        if p in DANGEROUS_PERMISSIONS]
        risk_level, _ = get_risk_level(result["score"])

        prompt = f"""You are a cybersecurity analyst specialising in Malaysian mobile banking fraud (like Macau scams, fake banking apps).

Analyse this Android APK scan result and write a clear verdict for a non-technical user (e.g. a bank officer or police investigator).

--- SCAN DATA ---
Package name   : {result['package']}
Risk score     : {result['score']} ({risk_level})
Dangerous perms: {danger_perms if danger_perms else 'None'}
Telegram C2    : {list(result['telegrams']) if result['telegrams'] else 'None found'}
Hardcoded IPs  : {list(result['ips']) if result['ips'] else 'None found'}
Banking keywords: {list(result['keywords']) if result['keywords'] else 'None found'}
SMS receivers  : {[r for r in result['receivers'] if re.search(r'(?i)sms', r)]}
---

Write exactly 3 short paragraphs:
1. Overall verdict — is this malware? How confident are you?
2. What is this app likely doing to the victim's device/banking?
3. Recommended action (e.g. do not install, report to BNMLINK, submit to CyberSecurity Malaysia).

Be direct and concise. No bullet points. No markdown headers."""

        response = model.generate_content(prompt)
        return response.text

    except Exception as e:
        return f"⚠️ AI summary failed: {str(e)}\n\nMake sure your Gemini API key is correct."

# ─── PDF Generator ───────────────────────────────────────────────────────────────

def generate_pdf(result, ai_summary=None):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
                            rightMargin=2*cm, leftMargin=2*cm,
                            topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    story  = []

    risk_level, risk_color = get_risk_level(result["score"])

    story.append(Paragraph("APK Triage Report", styles["Title"]))
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]))
    story.append(Spacer(1, 0.5*cm))

    info_data = [
        ["Package",    result["package"]],
        ["Version",    result["version"]],
        ["Min SDK",    result["min_sdk"]],
        ["Target SDK", result["target_sdk"]],
        ["Risk Score", str(result["score"])],
        ["Risk Level", risk_level],
    ]
    t = Table(info_data, colWidths=[4*cm, 13*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
        ("FONTNAME",   (0, 0), (0, -1), "Helvetica-Bold"),
        ("GRID",       (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING",    (0, 0), (-1, -1), 6),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.5*cm))

    # AI Summary section in PDF
    if ai_summary:
        story.append(Paragraph("AI Analyst Verdict", styles["Heading2"]))
        for para in ai_summary.strip().split("\n\n"):
            if para.strip():
                story.append(Paragraph(para.strip(), styles["Normal"]))
                story.append(Spacer(1, 0.2*cm))
        story.append(Spacer(1, 0.3*cm))

    story.append(Paragraph("Dangerous Permissions", styles["Heading2"]))
    danger_perms = [p for p in result["permissions"] if p in DANGEROUS_PERMISSIONS]
    if danger_perms:
        for p in danger_perms:
            desc = DANGEROUS_PERMISSIONS[p][0]
            story.append(Paragraph(f"• {p}", styles["Normal"]))
            story.append(Paragraph(f"  → {desc}", styles["Normal"]))
    else:
        story.append(Paragraph("None detected.", styles["Normal"]))
    story.append(Spacer(1, 0.4*cm))

    story.append(Paragraph("Indicators of Compromise (IoCs)", styles["Heading2"]))
    for label, items in [("Telegram tokens", result["telegrams"]),
                          ("Hardcoded IPs",   result["ips"]),
                          ("URLs",            result["urls"]),
                          ("Banking keywords",result["keywords"])]:
        story.append(Paragraph(f"{label}:", styles["Heading3"]))
        if items:
            for item in items:
                story.append(Paragraph(f"• {item}", styles["Normal"]))
        else:
            story.append(Paragraph("None found.", styles["Normal"]))
        story.append(Spacer(1, 0.2*cm))

    story.append(Paragraph("App Components", styles["Heading2"]))
    for label, items in [("Receivers",  result["receivers"]),
                          ("Services",   result["services"]),
                          ("Activities", result["activities"])]:
        story.append(Paragraph(f"{label}:", styles["Heading3"]))
        for item in items:
            story.append(Paragraph(f"• {item}", styles["Normal"]))
        story.append(Spacer(1, 0.2*cm))

    doc.build(story)
    buffer.seek(0)
    return buffer

# ─── Streamlit UI ────────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="APK Triage",
    page_icon="🔍",
    layout="wide"
)

st.title("🔍 APK Malware Triage Tool")
st.caption("Automated static analysis for Malaysian financial scam APKs")
st.divider()

# ── Gemini API Key Input ─────────────────────────────────────────────────────────
with st.sidebar:
    st.header("⚙️ Settings")
    gemini_api_key = st.text_input(
        "Gemini API Key",
        type="password",
        placeholder="Paste your key from aistudio.google.com",
        help="Free API key from aistudio.google.com — no credit card needed"
    )
    if gemini_api_key:
        st.success("API key loaded ✓")
    else:
        st.info("Add your Gemini key to enable AI summaries.\nGet one free at aistudio.google.com")

# ── File Upload ──────────────────────────────────────────────────────────────────
uploaded_file = st.file_uploader("Upload an APK file", type=["apk"])

if uploaded_file:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
        tmp.write(uploaded_file.read())
        tmp_path = tmp.name

    with st.spinner("Analysing APK..."):
        try:
            result = analyse_apk(tmp_path)
        except Exception as e:
            st.error(f"Analysis failed: {e}")
            st.stop()
        finally:
            os.unlink(tmp_path)

    risk_level, risk_color = get_risk_level(result["score"])

    # ── Risk gauge ───────────────────────────────────────────────────────────────
    st.subheader("Risk Assessment")
    col1, col2, col3 = st.columns([1, 2, 1])

    with col1:
        st.metric("Package", result["package"])
        st.metric("Version", result["version"])

    with col2:
        st.markdown(
            f"""
            <div style='text-align:center; padding:20px; border-radius:12px;
                        background-color:{risk_color}22; border: 2px solid {risk_color}'>
                <div style='font-size:48px; font-weight:bold; color:{risk_color}'>{risk_level}</div>
                <div style='font-size:28px; color:{risk_color}'>Score: {result["score"]}</div>
            </div>
            """,
            unsafe_allow_html=True
        )
        st.progress(min(result["score"], 100) / 100)

    with col3:
        st.metric("Min SDK",    result["min_sdk"])
        st.metric("Target SDK", result["target_sdk"])

    st.divider()

    # ── AI Verdict ───────────────────────────────────────────────────────────────
    st.subheader("🤖 AI Analyst Verdict")

    ai_summary = None
    if gemini_api_key:
        with st.spinner("Generating AI analysis..."):
            ai_summary = generate_ai_summary(result, gemini_api_key)
        st.info(ai_summary)
    else:
        st.warning("Add your Gemini API key in the sidebar to get an AI-powered verdict.")

    st.divider()

    # ── Main panels ──────────────────────────────────────────────────────────────
    left, right = st.columns(2)

    with left:
        st.subheader("🛡️ Permissions")
        danger_count = 0
        for perm in result["permissions"]:
            if perm in DANGEROUS_PERMISSIONS:
                desc = DANGEROUS_PERMISSIONS[perm][0]
                st.error(f"**{perm.split('.')[-1]}**\n\n{desc}")
                danger_count += 1
            else:
                st.text(f"  {perm.split('.')[-1]}")
        if danger_count == 0:
            st.success("No dangerous permissions found.")

    with right:
        st.subheader("🎯 Indicators of Compromise")

        if result["telegrams"]:
            st.error("**Telegram C2 detected**")
            for t in result["telegrams"]:
                st.code(t)

        if result["ips"]:
            st.warning("**Hardcoded IP addresses**")
            for ip in result["ips"]:
                st.code(ip)

        if result["urls"]:
            with st.expander(f"URLs found ({len(result['urls'])})"):
                for u in result["urls"]:
                    st.text(u)

        if result["keywords"]:
            st.warning(f"**Banking keywords:** {', '.join(result['keywords'])}")

        if not result["telegrams"] and not result["ips"] and not result["keywords"]:
            st.success("No IoCs detected.")

    st.divider()

    # ── Components ───────────────────────────────────────────────────────────────
    st.subheader("⚙️ App Components")
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

    # ── PDF Download ─────────────────────────────────────────────────────────────
    st.subheader("📄 Export Report")
    pdf_buffer = generate_pdf(result, ai_summary)
    st.download_button(
        label="Download PDF Report",
        data=pdf_buffer,
        file_name=f"triage_{result['package']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
        mime="application/pdf"
    )
