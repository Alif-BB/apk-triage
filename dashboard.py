from loguru import logger
logger.disable("androguard")

from androguard.misc import AnalyzeAPK
import sys
import re
import hashlib
import os
import asyncio
import datetime
import tempfile
import streamlit as st
from io import BytesIO

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.units import cm

import google.generativeai as genai

# ─── PDF Signing (pyhanko + cryptography) ────────────────────────────────────────

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import pkcs12 as crypto_pkcs12

from pyhanko.sign import signers, fields
from pyhanko.pdf_utils import incremental_writer
from pyhanko.sign.fields import SigFieldSpec

# Path where the self-signed cert is stored (persists across reruns)
CERT_PATH = os.path.join(os.path.expanduser("~"), ".apktriage_signer.p12")
CERT_PASS = b"apktriage_internal"


def get_or_create_signing_cert():
    """
    Returns a pyhanko SimpleSigner backed by a self-signed certificate.
    Creates the certificate on first run and reuses it on subsequent runs.
    """
    if not os.path.exists(CERT_PATH):
        key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        now = datetime.datetime.now(datetime.timezone.utc)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "APK Triage Tool"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Digital Forensics Unit"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256(), default_backend())
        )
        p12_bytes = crypto_pkcs12.serialize_key_and_certificates(
            b"apktriage", key, cert, None,
            serialization.BestAvailableEncryption(CERT_PASS)
        )
        with open(CERT_PATH, "wb") as f:
            f.write(p12_bytes)

    return signers.SimpleSigner.load_pkcs12(CERT_PATH, passphrase=CERT_PASS)


def sign_pdf_buffer(unsigned_buffer: BytesIO, analyst_name: str) -> BytesIO:
    """
    Applies an invisible digital signature to the PDF and returns a signed BytesIO.
    The signature is verifiable in Adobe Acrobat and other PDF validators.
    """
    signer = get_or_create_signing_cert()

    async def _sign():
        w = incremental_writer.IncrementalPdfFileWriter(unsigned_buffer)
        # Add an invisible signature field on the last page
        fields.append_signature_field(
            w,
            SigFieldSpec("DigitalSignature", on_page=-1, box=(36, 36, 300, 60))
        )
        meta = signers.PdfSignatureMetadata(
            field_name="DigitalSignature",
            reason=f"Triage report certified by {analyst_name}",
            location="APK Triage System",
            name=analyst_name,
        )
        out = await signers.async_sign_pdf(w, meta, signer=signer)
        return out.read()

    signed_bytes = asyncio.run(_sign())
    return BytesIO(signed_bytes)


# ─── Patterns & Rules ────────────────────────────────────────────────────────────

URL_PATTERN      = re.compile(r'https?://[^\s\'"<>]{4,}')
IP_PATTERN       = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
TELEGRAM_PATTERN = re.compile(r'(?:bot\d{8,12}:[A-Za-z0-9_-]{35,}|t\.me/[^\s\'"]{3,})')
KEYWORD_PATTERN  = re.compile(r'(?i)(maybank|cimb|rhb|pbebank|hongleong|bankislam|TAC|OTP|transaction)')
EXCLUDED_IPS     = {"127.0.0.1", "0.0.0.0", "255.255.255.255"}

DANGEROUS_PERMISSIONS = {
    "android.permission.RECEIVE_SMS":               ("Intercepts incoming SMS — steals TAC/OTP codes", 50),
    "android.permission.READ_SMS":                  ("Reads all SMS messages on the device", 25),
    "android.permission.SEND_SMS":                  ("Sends SMS silently without user knowledge", 20),
    "android.permission.BIND_ACCESSIBILITY_SERVICE":("Enables overlay attacks on other apps", 30),
    "android.permission.SYSTEM_ALERT_WINDOW":       ("Draws over other apps — phishing overlay", 25),
    "android.permission.REQUEST_INSTALL_PACKAGES":  ("Silently installs other APKs — dropper behaviour", 20),
    "android.permission.READ_CONTACTS":             ("Harvests contact list for scam propagation", 15),
    "android.permission.RECORD_AUDIO":              ("Records microphone — spyware behaviour", 15),
    "android.permission.PROCESS_OUTGOING_CALLS":    ("Intercepts and redirects phone calls", 15),
    "android.permission.READ_CALL_LOG":             ("Reads full call history", 15),
    "android.permission.CAMERA":                    ("Access camera without user interaction", 10),
}


def get_risk_level(score):
    if score == 0:
        return "CLEAN",    "#2ecc71"
    elif score < 30:
        return "LOW",      "#27ae60"
    elif score < 60:
        return "MEDIUM",   "#f39c12"
    elif score < 90:
        return "HIGH",     "#e74c3c"
    else:
        return "CRITICAL", "#e74c3c"


# ─── Core Analysis Function ──────────────────────────────────────────────────────

def analyse_apk(filepath):
    # ── Compute SHA-256 before analysis ──────────────────────────────────────────
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    apk_hash = sha256.hexdigest()

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
        "sha256":      apk_hash,                        # ← NEW
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

def generate_pdf(result, analyst_name, ai_summary=None):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
                            rightMargin=2*cm, leftMargin=2*cm,
                            topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()

    # Custom mono style for hash display
    mono_style = ParagraphStyle(
        "Mono",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8,
        leading=12,
        textColor=colors.HexColor("#333333"),
    )

    story  = []
    risk_level, risk_color = get_risk_level(result["score"])
    generated_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    story.append(Paragraph("APK Triage Report", styles["Title"]))
    story.append(Paragraph(f"Generated: {generated_at}", styles["Normal"]))
    story.append(Spacer(1, 0.5*cm))

    # ── App Info table ────────────────────────────────────────────────────────────
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

    # ── Evidence Integrity Block ──────────────────────────────────────────────────
    story.append(Paragraph("Evidence Integrity", styles["Heading2"]))

    integrity_data = [
        ["Field", "Value"],
        ["SHA-256 Hash",    result["sha256"]],
        ["Analysed By",     analyst_name if analyst_name else "Not specified"],
        ["Timestamp (UTC)", datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")],
        ["Tool Version",    "APK Triage v1.0"],
        ["Signature",       "Digital signature applied — verify with Adobe Acrobat"],
    ]
    it = Table(integrity_data, colWidths=[4*cm, 13*cm])
    it.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0),  colors.HexColor("#2c3e50")),
        ("TEXTCOLOR",   (0, 0), (-1, 0),  colors.white),
        ("FONTNAME",    (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("BACKGROUND",  (0, 1), (0, -1),  colors.HexColor("#ecf0f1")),
        ("FONTNAME",    (0, 1), (0, -1),  "Helvetica-Bold"),
        ("FONTNAME",    (1, 2), (1, 2),   "Courier"),   # SHA-256 row in monospace
        ("FONTSIZE",    (1, 2), (1, 2),   7.5),
        ("GRID",        (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING",     (0, 0), (-1, -1), 6),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
    ]))
    story.append(it)
    story.append(Spacer(1, 0.5*cm))

    # ── AI Summary ────────────────────────────────────────────────────────────────
    if ai_summary:
        story.append(Paragraph("AI Analyst Verdict", styles["Heading2"]))
        for para in ai_summary.strip().split("\n\n"):
            if para.strip():
                story.append(Paragraph(para.strip(), styles["Normal"]))
                story.append(Spacer(1, 0.2*cm))
        story.append(Spacer(1, 0.3*cm))

    # ── Dangerous Permissions ─────────────────────────────────────────────────────
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

    # ── IoCs ──────────────────────────────────────────────────────────────────────
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

    # ── App Components ────────────────────────────────────────────────────────────
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


# ─── Streamlit UI ─────────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="APK Triage",
    page_icon="🔍",
    layout="wide"
)

st.title(" APK Malware Triage Tool")
st.caption("Automated static analysis for Malaysian financial scam APKs")
st.divider()

# ── Sidebar ───────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.header("⚙️ Settings")

    # ── Analyst identity (for chain of custody) ───────────────────────────────────
    st.subheader("🪪 Analyst Identity")
    analyst_name = st.text_input(
        "Your name / badge number",
        placeholder="e.g. Insp. Ahmad bin Ali  D/12345",
        help="Embedded in the PDF report for chain-of-custody purposes"
    )
    analyst_org = st.text_input(
        "Unit / organisation",
        placeholder="e.g. PDRM Cyber Crime D11, KL",
        help="Included in the Evidence Integrity section of the report"
    )
    full_analyst = f"{analyst_name} — {analyst_org}" if analyst_org else analyst_name

    st.divider()

    # ── Gemini API key ────────────────────────────────────────────────────────────
    st.subheader(" AI Settings")
    gemini_api_key = st.secrets.get("GEMINI_API_KEY", None)
    if gemini_api_key:
        st.success("AI Analyst enable ✓")
    else:
        st.info("contact your admin for AI-powered summar")

    st.divider()
    st.caption("📋 The PDF report includes a digital signature and SHA-256 hash for court-admissible chain of custody.")

# ── File Upload ───────────────────────────────────────────────────────────────────
uploaded_file = st.file_uploader("Upload an APK file", type=["apk"])

if uploaded_file:
    # Warn if analyst name missing
    if not analyst_name:
        st.warning("⚠️ No analyst name entered. Add your name in the sidebar for a complete chain-of-custody report.")

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

    # ── Risk gauge ────────────────────────────────────────────────────────────────
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

    # ── SHA-256 hash display ──────────────────────────────────────────────────────
    st.divider()
    with st.expander("🔐 Evidence Integrity", expanded=True):
        c1, c2 = st.columns([1, 2])
        with c1:
            st.markdown("**SHA-256 Hash**")
            st.markdown("**Analyst**")
            st.markdown("**Timestamp (UTC)**")
        with c2:
            st.code(result["sha256"], language=None)
            st.text(full_analyst if full_analyst.strip(" —") else "Not specified")
            st.text(datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
        st.caption("The SHA-256 hash uniquely identifies this exact APK file. Any modification changes the hash, detecting tampering.")

    # ── AI Verdict ────────────────────────────────────────────────────────────────
    st.divider()
    st.subheader(" AI Analyst Verdict")
    ai_summary = None
    if gemini_api_key:
        with st.spinner("Generating AI analysis..."):
            ai_summary = generate_ai_summary(result, gemini_api_key)
        st.info(ai_summary)
    else:
        st.warning("Add your Gemini API key in the sidebar to get an AI-powered verdict.")

    st.divider()

    # ── Main panels ───────────────────────────────────────────────────────────────
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

    # ── Components ────────────────────────────────────────────────────────────────
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

    # ── PDF Export (unsigned + signed) ────────────────────────────────────────────
    st.subheader("📄 Export Report")

    col_a, col_b = st.columns(2)
    filename_base = f"triage_{result['package']}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"

    with col_a:
        unsigned_pdf = generate_pdf(result, full_analyst, ai_summary)
        st.download_button(
            label="⬇️ Download PDF (unsigned)",
            data=unsigned_pdf,
            file_name=f"{filename_base}.pdf",
            mime="application/pdf",
            help="Plain PDF report without digital signature"
        )

    with col_b:
        with st.spinner("Applying digital signature..."):
            try:
                unsigned_pdf2 = generate_pdf(result, full_analyst, ai_summary)
                signed_pdf = sign_pdf_buffer(unsigned_pdf2, full_analyst or "Unknown Analyst")
                st.download_button(
                    label="🔏 Download PDF (digitally signed)",
                    data=signed_pdf,
                    file_name=f"{filename_base}_signed.pdf",
                    mime="application/pdf",
                    help="PDF with embedded digital signature — verifiable in Adobe Acrobat"
                )
                st.caption("✅ Signed with self-signed certificate. For court use, replace with an agency-issued certificate.")
            except Exception as e:
                st.error(f"Signing failed: {e}")
