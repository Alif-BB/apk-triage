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
import vt          # pip install vt-py
import zipfile
import csv
import json
import uuid

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


# ─── Patterns & Constants ─────────────────────────────────────────────────────────

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
        return "HIGH",     "#e67e22"
    else:
        return "CRITICAL", "#e74c3c"


# ─── APK Hashing ──────────────────────────────────────────────────────────────────

def get_file_hashes(filepath):
    """Returns MD5, SHA-1, SHA-256 of the APK file."""
    md5    = hashlib.md5()
    sha1   = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()


# ─── Core APK Analysis ────────────────────────────────────────────────────────────

def analyse_apk(filepath):
    md5, sha1, sha256 = get_file_hashes(filepath)

    apk, dex, analysis = AnalyzeAPK(filepath)

    all_strings = [s.get_value() for s in analysis.get_strings()]
    urls, ips, telegrams, keywords = set(), set(), set(), set()

    for s in all_strings:
        urls.update(URL_PATTERN.findall(s))
        ips.update(IP_PATTERN.findall(s))
        telegrams.update(TELEGRAM_PATTERN.findall(s))
        keywords.update(KEYWORD_PATTERN.findall(s))

    ips -= EXCLUDED_IPS

    score       = 0
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
        "md5":         md5,
        "sha1":        sha1,
        "sha256":      sha256,
    }


# ─── GTI / VirusTotal Enrichment ──────────────────────────────────────────────────

def check_virustotal(filepath, result, api_key):
    """
    Queries Google Threat Intelligence (VirusTotal) for:
      - APK file hash reputation
      - Hardcoded IP address reputation
      - URL reputation (first 5 URLs)
    """
    gti = {"file": None, "ips": {}, "urls": {}, "errors": []}

    try:
        with vt.Client(api_key) as client:

            # 1 ── APK file hash ───────────────────────────────────────────────────
            try:
                file_report = client.get_object(f"/files/{result['sha256']}")
                stats = file_report.last_analysis_stats
                gti["file"] = {
                    "malicious":   stats.get("malicious", 0),
                    "suspicious":  stats.get("suspicious", 0),
                    "undetected":  stats.get("undetected", 0),
                    "total":       sum(stats.values()),
                    "tags":        getattr(file_report, "tags", []),
                    "threat_name": getattr(file_report, "popular_threat_classification", {})
                                    .get("suggested_threat_label", "Unknown"),
                    "first_seen":  str(getattr(file_report, "first_submission_date", "N/A")),
                    "times_seen":  getattr(file_report, "times_submitted", 0),
                    "link":        f"https://www.virustotal.com/gui/file/{result['sha256']}"
                }
            except vt.error.APIError as e:
                if "NotFoundError" in str(e):
                    gti["file"] = {"not_found": True}
                else:
                    gti["errors"].append(f"File lookup failed: {e}")

            # 2 ── IP reputation ───────────────────────────────────────────────────
            for ip in list(result["ips"])[:10]:
                try:
                    ip_report = client.get_object(f"/ip_addresses/{ip}")
                    stats = ip_report.last_analysis_stats
                    gti["ips"][ip] = {
                        "malicious": stats.get("malicious", 0),
                        "total":     sum(stats.values()),
                        "country":   getattr(ip_report, "country", "Unknown"),
                        "owner":     getattr(ip_report, "as_owner", "Unknown"),
                        "link":      f"https://www.virustotal.com/gui/ip-address/{ip}"
                    }
                except vt.error.APIError:
                    gti["ips"][ip] = None

            # 3 ── URL reputation ──────────────────────────────────────────────────
            for url in list(result["urls"])[:5]:
                try:
                    url_id = vt.url_id(url)
                    url_report = client.get_object(f"/urls/{url_id}")
                    stats = url_report.last_analysis_stats
                    gti["urls"][url] = {
                        "malicious": stats.get("malicious", 0),
                        "total":     sum(stats.values()),
                        "link":      f"https://www.virustotal.com/gui/url/{url_id}"
                    }
                except vt.error.APIError:
                    gti["urls"][url] = None

    except Exception as e:
        gti["errors"].append(f"GTI connection error: {str(e)}")

    return gti


def gti_score_boost(gti):
    """Extra risk score points based on GTI confirmation."""
    boost = 0
    if gti.get("file") and not gti["file"].get("not_found"):
        malicious = gti["file"].get("malicious", 0)
        if malicious > 20:
            boost += 50
        elif malicious > 5:
            boost += 30
        elif malicious > 0:
            boost += 15
    for ip, data in gti.get("ips", {}).items():
        if data and data.get("malicious", 0) > 0:
            boost += 20
    for url, data in gti.get("urls", {}).items():
        if data and data.get("malicious", 0) > 0:
            boost += 10
    return boost


# ─── Gemini AI Summary ────────────────────────────────────────────────────────────

def generate_ai_summary(result, api_key, gti=None):
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-2.5-flash")

        danger_perms = [p.split(".")[-1] for p in result["permissions"]
                        if p in DANGEROUS_PERMISSIONS]
        risk_level, _ = get_risk_level(result["score"])

        gti_summary = "GTI enrichment not available."
        if gti:
            file_data = gti.get("file")
            if file_data and not file_data.get("not_found"):
                gti_summary = (
                    f"VirusTotal: {file_data['malicious']}/{file_data['total']} engines "
                    f"flagged this file. Threat label: {file_data.get('threat_name', 'N/A')}. "
                    f"First seen: {file_data.get('first_seen', 'N/A')}."
                )
            elif file_data and file_data.get("not_found"):
                gti_summary = "APK hash not found in VirusTotal — likely a new or unpublished sample."
            malicious_ips = {ip: d for ip, d in gti.get("ips", {}).items()
                             if d and d.get("malicious", 0) > 0}
            if malicious_ips:
                gti_summary += f" {len(malicious_ips)} hardcoded IP(s) are confirmed malicious by GTI."

        prompt = f"""You are a cybersecurity analyst specialising in Malaysian mobile banking fraud (Macau scams, fake banking apps).

Analyse this APK scan result and write a clear verdict for a non-technical user (bank officer, police investigator).

--- SCAN DATA ---
Package name    : {result['package']}
SHA-256         : {result['sha256']}
Risk score      : {result['score']} ({risk_level})
Dangerous perms : {danger_perms if danger_perms else 'None'}
Telegram C2     : {list(result['telegrams']) if result['telegrams'] else 'None found'}
Hardcoded IPs   : {list(result['ips']) if result['ips'] else 'None found'}
Banking keywords: {list(result['keywords']) if result['keywords'] else 'None found'}
SMS receivers   : {[r for r in result['receivers'] if re.search(r'(?i)sms', r)]}
GTI Enrichment  : {gti_summary}
---

Write exactly 3 short paragraphs:
1. Overall verdict — is this malware? How confident are you? Reference GTI data if available.
2. What is this app likely doing to the victim's device/banking?
3. Recommended action (do not install, report to BNMLINK, submit to CyberSecurity Malaysia, etc.).

Be direct and concise. No bullet points. No markdown headers."""

        response = model.generate_content(prompt)
        return response.text

    except Exception as e:
        return f"⚠️ AI summary failed: {str(e)}"


# ─── PDF Report ───────────────────────────────────────────────────────────────────

def generate_pdf(result, analyst_name, ai_summary=None, gti=None):
    buffer = BytesIO()
    doc    = SimpleDocTemplate(buffer, pagesize=A4,
                               rightMargin=2*cm, leftMargin=2*cm,
                               topMargin=2*cm, bottomMargin=2*cm)
    styles        = getSampleStyleSheet()
    story         = []
    risk_level, _ = get_risk_level(result["score"])
    generated_at  = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Title ─────────────────────────────────────────────────────────────────────
    story.append(Paragraph("APK Triage Report", styles["Title"]))
    story.append(Paragraph(
        f"Generated: {generated_at}  |  Powered by Google Threat Intelligence (VirusTotal)",
        styles["Normal"]
    ))
    story.append(Spacer(1, 0.5*cm))

    # ── App Info ──────────────────────────────────────────────────────────────────
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

    # ── Evidence Integrity ────────────────────────────────────────────────────────
    story.append(Paragraph("Evidence Integrity", styles["Heading2"]))
    integrity_data = [
        ["Field",           "Value"],
        ["MD5 Hash",        result["md5"]],
        ["SHA-1 Hash",      result["sha1"]],
        ["SHA-256 Hash",    result["sha256"]],
        ["Analysed By",     analyst_name if analyst_name else "Not specified"],
        ["Timestamp (UTC)", datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")],
        ["Tool Version",    "APK Triage v1.0"],
        ["Signature",       "Digital signature applied — verify with Adobe Acrobat"],
    ]
    it = Table(integrity_data, colWidths=[4*cm, 13*cm])
    it.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0),  colors.HexColor("#2c3e50")),
        ("TEXTCOLOR",      (0, 0), (-1, 0),  colors.white),
        ("FONTNAME",       (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("BACKGROUND",     (0, 1), (0, -1),  colors.HexColor("#ecf0f1")),
        ("FONTNAME",       (0, 1), (0, -1),  "Helvetica-Bold"),
        ("FONTNAME",       (1, 2), (1, 4),   "Courier"),
        ("FONTSIZE",       (1, 2), (1, 4),   7.5),
        ("GRID",           (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING",        (0, 0), (-1, -1), 6),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
    ]))
    story.append(it)
    story.append(Spacer(1, 0.5*cm))

    # ── GTI / VirusTotal Section ──────────────────────────────────────────────────
    story.append(Paragraph("Google Threat Intelligence (VirusTotal)", styles["Heading2"]))
    if gti:
        if gti.get("errors"):
            for err in gti["errors"]:
                story.append(Paragraph(f"⚠ {err}", styles["Normal"]))

        file_data = gti.get("file")
        if file_data:
            if file_data.get("not_found"):
                story.append(Paragraph(
                    "APK hash not found in VirusTotal — may be a new or private sample. Treat with caution.",
                    styles["Normal"]
                ))
            else:
                story.append(Paragraph(
                    f"Antivirus detections: {file_data['malicious']}/{file_data['total']} engines flagged this file as malicious.",
                    styles["Normal"]
                ))
                if file_data.get("threat_name") and file_data["threat_name"] != "Unknown":
                    story.append(Paragraph(
                        f"Threat label: {file_data['threat_name']}",
                        styles["Normal"]
                    ))
                story.append(Paragraph(
                    f"First seen: {file_data.get('first_seen', 'N/A')}  |  "
                    f"Times submitted: {file_data.get('times_seen', 'N/A')}",
                    styles["Normal"]
                ))
                story.append(Paragraph(
                    f"Full report: {file_data['link']}",
                    styles["Normal"]
                ))

        malicious_ips = {ip: d for ip, d in gti.get("ips", {}).items()
                         if d and d.get("malicious", 0) > 0}
        if malicious_ips:
            story.append(Paragraph("Malicious IPs confirmed by GTI:", styles["Heading3"]))
            for ip, data in malicious_ips.items():
                story.append(Paragraph(
                    f"• {ip} — {data['malicious']}/{data['total']} detections | "
                    f"{data.get('country', '')} | {data.get('owner', '')}",
                    styles["Normal"]
                ))

        malicious_urls = {url: d for url, d in gti.get("urls", {}).items()
                          if d and d.get("malicious", 0) > 0}
        if malicious_urls:
            story.append(Paragraph("Malicious URLs confirmed by GTI:", styles["Heading3"]))
            for url, data in malicious_urls.items():
                story.append(Paragraph(
                    f"• {url} — {data['malicious']}/{data['total']} detections",
                    styles["Normal"]
                ))
    else:
        story.append(Paragraph(
            "GTI enrichment was not performed (no API key provided).",
            styles["Normal"]
        ))
    story.append(Spacer(1, 0.4*cm))

    # ── AI Verdict ────────────────────────────────────────────────────────────────
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
    for label, items in [("Telegram tokens",  result["telegrams"]),
                          ("Hardcoded IPs",    result["ips"]),
                          ("URLs",             result["urls"]),
                          ("Banking keywords", result["keywords"])]:
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
        for item in (items or ["None"]):
            story.append(Paragraph(f"• {item}", styles["Normal"]))
        story.append(Spacer(1, 0.2*cm))

    doc.build(story)
    buffer.seek(0)
    return buffer


# ─── Case Package Generator (Feature 1) ──────────────────────────────────────────

def generate_case_json(result, analyst_name, analyst_org, case_number, classification, gti=None, ai_summary=None):
    """
    Produces a structured JSON evidence file suitable for case management systems,
    inter-agency sharing (PDRM ↔ BNM ↔ CyberSecurity Malaysia), and archival.
    """
    risk_level, _ = get_risk_level(result["score"])

    gti_section = None
    if gti:
        file_data = gti.get("file")
        gti_section = {
            "file_reputation": {
                "found":       not bool(file_data and file_data.get("not_found")),
                "malicious":   file_data.get("malicious")   if file_data and not file_data.get("not_found") else None,
                "suspicious":  file_data.get("suspicious")  if file_data and not file_data.get("not_found") else None,
                "total":       file_data.get("total")        if file_data and not file_data.get("not_found") else None,
                "threat_label":file_data.get("threat_name") if file_data and not file_data.get("not_found") else None,
                "first_seen":  file_data.get("first_seen")  if file_data and not file_data.get("not_found") else None,
                "vt_link":     file_data.get("link")         if file_data and not file_data.get("not_found") else None,
            } if file_data else None,
            "ip_reputation": {
                ip: {
                    "malicious": d.get("malicious"),
                    "total":     d.get("total"),
                    "country":   d.get("country"),
                    "owner":     d.get("owner"),
                    "vt_link":   d.get("link"),
                } if d else None
                for ip, d in gti.get("ips", {}).items()
            },
            "url_reputation": {
                url: {
                    "malicious": d.get("malicious"),
                    "total":     d.get("total"),
                    "vt_link":   d.get("link"),
                } if d else None
                for url, d in gti.get("urls", {}).items()
            },
            "errors": gti.get("errors", []),
        }

    return {
        "case_metadata": {
            "case_number":      case_number or "UNASSIGNED",
            "classification":   classification,
            "generated_at_utc": datetime.datetime.utcnow().isoformat() + "Z",
            "tool":             "APK Triage v1.0",
            "analyst":          analyst_name or "Not specified",
            "unit":             analyst_org  or "Not specified",
        },
        "evidence_integrity": {
            "filename":  f"{result['package']}.apk",
            "md5":       result["md5"],
            "sha1":      result["sha1"],
            "sha256":    result["sha256"],
        },
        "app_info": {
            "package":    result["package"],
            "version":    result["version"],
            "min_sdk":    result["min_sdk"],
            "target_sdk": result["target_sdk"],
        },
        "risk_assessment": {
            "score":      result["score"],
            "level":      risk_level,
        },
        "dangerous_permissions": [
            {
                "permission":  p,
                "description": DANGEROUS_PERMISSIONS[p][0],
                "score":       DANGEROUS_PERMISSIONS[p][1],
            }
            for p in result["permissions"] if p in DANGEROUS_PERMISSIONS
        ],
        "all_permissions": list(result["permissions"]),
        "indicators_of_compromise": {
            "telegram_c2":      list(result["telegrams"]),
            "hardcoded_ips":    list(result["ips"]),
            "urls":             list(result["urls"]),
            "banking_keywords": list(result["keywords"]),
        },
        "app_components": {
            "receivers":  list(result["receivers"]),
            "services":   list(result["services"]),
            "activities": list(result["activities"]),
        },
        "threat_intelligence": gti_section,
        "ai_verdict": ai_summary or None,
    }


def generate_bnmlink_template(result, analyst_name, analyst_org, case_number, classification, gti=None):
    """
    Generates a pre-filled incident report template formatted for submission to:
    - BNMLINK (Bank Negara Malaysia)     : bnmlink@bnm.gov.my / 1-300-88-5465
    - Cyber999 (CyberSecurity Malaysia)  : cyber999@cybersecurity.my / 1-300-88-2999
    - PDRM CCID                          : ccid.rmp.gov.my
    """
    risk_level, _ = get_risk_level(result["score"])
    now           = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    danger_perms  = [p.split(".")[-1] for p in result["permissions"] if p in DANGEROUS_PERMISSIONS]

    gti_block = "GTI/VirusTotal enrichment not performed."
    if gti:
        fd = gti.get("file")
        if fd and not fd.get("not_found"):
            gti_block = (
                f"VirusTotal Detections : {fd['malicious']}/{fd['total']} antivirus engines\n"
                f"Threat Label          : {fd.get('threat_name', 'N/A')}\n"
                f"First Seen            : {fd.get('first_seen', 'N/A')}\n"
                f"VT Report             : {fd.get('link', 'N/A')}"
            )
        elif fd and fd.get("not_found"):
            gti_block = "VirusTotal: Hash not found — likely a new/unpublished sample."
        mal_ips = {ip: d for ip, d in gti.get("ips", {}).items() if d and d.get("malicious", 0) > 0}
        if mal_ips:
            gti_block += f"\nConfirmed Malicious IPs : {', '.join(mal_ips.keys())}"

    lines = [
        "=" * 70,
        "  CYBER INCIDENT REPORT — APK MALWARE TRIAGE",
        "  For submission to BNMLINK / Cyber999 / PDRM CCID",
        "=" * 70,
        "",
        "── SUBMISSION DETAILS ──────────────────────────────────────────────────",
        f"  Report Date      : {now}",
        f"  Case Reference   : {case_number or 'UNASSIGNED — assign before submission'}",
        f"  Classification   : {classification}",
        f"  Prepared By      : {analyst_name or 'Not specified'}",
        f"  Unit / Agency    : {analyst_org or 'Not specified'}",
        "",
        "── INCIDENT SUMMARY ────────────────────────────────────────────────────",
        f"  Incident Type    : Malicious Android APK — Mobile Banking Fraud",
        f"  Risk Level       : {risk_level}  (Score: {result['score']})",
        f"  APK Package Name : {result['package']}",
        f"  APK Version      : {result['version']}",
        "",
        "── EVIDENCE INTEGRITY (SHA hashes for chain-of-custody) ────────────────",
        f"  MD5    : {result['md5']}",
        f"  SHA-1  : {result['sha1']}",
        f"  SHA-256: {result['sha256']}",
        "",
        "── THREAT INTELLIGENCE (VirusTotal / GTI) ──────────────────────────────",
        *[f"  {line}" for line in gti_block.splitlines()],
        "",
        "── DANGEROUS CAPABILITIES DETECTED ────────────────────────────────────",
    ]

    if danger_perms:
        for p in danger_perms:
            desc = DANGEROUS_PERMISSIONS[f"android.permission.{p}"][0] \
                   if f"android.permission.{p}" in DANGEROUS_PERMISSIONS else ""
            lines.append(f"  [!] {p}")
            if desc:
                lines.append(f"       → {desc}")
    else:
        lines.append("  None detected.")

    lines += [
        "",
        "── INDICATORS OF COMPROMISE (IoCs) ─────────────────────────────────────",
    ]

    if result["telegrams"]:
        lines.append("  Telegram C2:")
        for t in result["telegrams"]:
            lines.append(f"    • {t}")
    if result["ips"]:
        lines.append("  Hardcoded IP Addresses:")
        for ip in result["ips"]:
            lines.append(f"    • {ip}")
    if result["keywords"]:
        lines.append(f"  Banking Keywords: {', '.join(result['keywords'])}")
    if not result["telegrams"] and not result["ips"] and not result["keywords"]:
        lines.append("  No IoCs detected.")

    lines += [
        "",
        "── RECOMMENDED ACTIONS ─────────────────────────────────────────────────",
        "  1. Do NOT install or run this APK on any non-sandboxed device.",
        "  2. Submit APK sample to CyberSecurity Malaysia:",
        "       cyber999@cybersecurity.my  |  1-300-88-2999",
        "  3. Report financial fraud to BNMLINK:",
        "       bnmlink@bnm.gov.my  |  1-300-88-5465",
        "  4. File police report with PDRM CCID:",
        "       ccid.rmp.gov.my",
        "  5. If Telegram C2 detected — report bot tokens to Telegram:",
        "       https://telegram.org/support",
        "  6. Request takedown of C2 IPs/domains via MyCERT:",
        "       mycert@cybersecurity.my",
        "",
        "── SUBMITTING AGENCY NOTES (fill in before submission) ─────────────────",
        "  Victim Name      : _______________________________________________",
        "  Victim IC / ID   : _______________________________________________",
        "  Bank Affected    : _______________________________________________",
        "  Amount Lost (RM) : _______________________________________________",
        "  Date of Incident : _______________________________________________",
        "  How APK Received : _______________________________________________",
        "  (e.g. WhatsApp link, SMS, Telegram, fake website)",
        "",
        "=" * 70,
        "  This report was generated automatically by APK Triage v1.0.",
        "  Verify hash values before submission to confirm evidence integrity.",
        "=" * 70,
    ]

    return "\n".join(lines)


def generate_chain_of_custody_log(result, analyst_name, analyst_org, case_number):
    """
    Returns a CSV-formatted chain of custody log as a string.
    Each action taken on the evidence is recorded as a timestamped row.
    """
    now_utc = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    rows = [
        ["#", "Timestamp (UTC)", "Action", "Actor", "Unit", "Details", "SHA-256"],
        ["1", now_utc, "Evidence Received",
         analyst_name or "Not specified",
         analyst_org  or "Not specified",
         f"APK uploaded for triage — Package: {result['package']} v{result['version']}",
         result["sha256"]],
        ["2", now_utc, "Hash Verification",
         "APK Triage Tool v1.0", "Automated",
         f"MD5: {result['md5']}  |  SHA-1: {result['sha1']}  |  SHA-256: {result['sha256']}",
         result["sha256"]],
        ["3", now_utc, "Static Analysis",
         "APK Triage Tool v1.0", "Automated",
         f"Risk Score: {result['score']}  |  "
         f"Dangerous permissions: {sum(1 for p in result['permissions'] if p in DANGEROUS_PERMISSIONS)}  |  "
         f"Telegram C2: {len(result['telegrams'])}  |  Hardcoded IPs: {len(result['ips'])}",
         result["sha256"]],
        ["4", now_utc, "GTI Enrichment",
         "APK Triage Tool v1.0 / VirusTotal", "Automated",
         "VirusTotal hash + IP + URL reputation queries executed",
         result["sha256"]],
        ["5", now_utc, "Report Generated",
         analyst_name or "Not specified",
         analyst_org  or "Not specified",
         f"Case Package generated — Case Ref: {case_number or 'UNASSIGNED'}",
         result["sha256"]],
    ]

    buf = []
    writer_target = []

    import io as _io
    output = _io.StringIO()
    writer = csv.writer(output)
    for row in rows:
        writer.writerow(row)
    return output.getvalue()


def generate_case_package(result, analyst_name, analyst_org, case_number,
                          classification, gti=None, ai_summary=None):
    """
    Bundles all case files into a single ZIP:
      ├── triage_report_signed.pdf          ← digitally signed forensic report
      ├── evidence.json                     ← structured machine-readable evidence
      ├── incident_report_template.txt      ← pre-filled BNMLINK/Cyber999 submission
      └── chain_of_custody.csv             ← timestamped CoC log
    """
    pkg_buffer = BytesIO()
    ts          = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_pkg    = re.sub(r'[^\w.]', '_', result["package"])

    with zipfile.ZipFile(pkg_buffer, "w", zipfile.ZIP_DEFLATED) as zf:

        # 1 ── Digitally signed PDF ────────────────────────────────────────────────
        try:
            pdf_buf    = generate_pdf(result, f"{analyst_name} — {analyst_org}" if analyst_org else analyst_name, ai_summary, gti)
            signed_pdf = sign_pdf_buffer(pdf_buf, analyst_name or "Unknown Analyst")
            zf.writestr(f"triage_report_{safe_pkg}_{ts}_signed.pdf", signed_pdf.read())
        except Exception as e:
            zf.writestr("triage_report_ERROR.txt", f"PDF generation failed: {e}")

        # 2 ── Structured JSON evidence ────────────────────────────────────────────
        evidence = generate_case_json(result, analyst_name, analyst_org,
                                      case_number, classification, gti, ai_summary)
        zf.writestr(f"evidence_{safe_pkg}_{ts}.json",
                    json.dumps(evidence, indent=2, default=str))

        # 3 ── BNMLINK / Cyber999 incident report template ─────────────────────────
        template = generate_bnmlink_template(result, analyst_name, analyst_org,
                                             case_number, classification, gti)
        zf.writestr(f"incident_report_template_{safe_pkg}_{ts}.txt",
                    template)

        # 4 ── Chain of Custody log ────────────────────────────────────────────────
        coc_csv = generate_chain_of_custody_log(result, analyst_name, analyst_org, case_number)
        zf.writestr(f"chain_of_custody_{safe_pkg}_{ts}.csv", coc_csv)

        # 5 ── README ──────────────────────────────────────────────────────────────
        readme = "\n".join([
            "APK TRIAGE — CASE PACKAGE",
            "=" * 40,
            f"Case Reference  : {case_number or 'UNASSIGNED'}",
            f"Classification  : {classification}",
            f"Package         : {result['package']}",
            f"SHA-256         : {result['sha256']}",
            f"Generated       : {datetime.datetime.utcnow().isoformat()}Z",
            f"Analyst         : {analyst_name or 'Not specified'}",
            f"Unit            : {analyst_org or 'Not specified'}",
            "",
            "FILES IN THIS PACKAGE",
            "-" * 40,
            "triage_report_*_signed.pdf      → Court-ready PDF with digital signature",
            "evidence_*.json                 → Machine-readable evidence (for SIEM/case mgmt)",
            "incident_report_template_*.txt  → Pre-filled submission for BNMLINK / Cyber999",
            "chain_of_custody_*.csv          → Timestamped chain-of-custody log",
            "",
            "SUBMISSION CONTACTS",
            "-" * 40,
            "BNMLINK (Bank Negara)         : bnmlink@bnm.gov.my  |  1-300-88-5465",
            "Cyber999 (CyberSecurity MY)   : cyber999@cybersecurity.my  |  1-300-88-2999",
            "PDRM CCID                     : ccid.rmp.gov.my",
        ])
        zf.writestr("README.txt", readme)

    pkg_buffer.seek(0)
    return pkg_buffer


# ─── Streamlit UI ─────────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="APK Triage  |  Powered by GTI",
    page_icon="🔍",
    layout="wide"
)

st.title("🔍 APK Malware Triage Tool")
st.caption("Static analysis + Google Threat Intelligence enrichment for Malaysian financial scam APKs")
st.divider()

# ── Sidebar ───────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.header("⚙️ Settings")

    # ── Analyst Identity ──────────────────────────────────────────────────────────
    st.subheader("🪪 Analyst Identity")
    analyst_name = st.text_input(
        "Your name / badge number",
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

    # ── Case Metadata ─────────────────────────────────────────────────────────────
    st.subheader("📁 Case Details")
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

    st.divider()

    # ── GTI / VirusTotal API Key ──────────────────────────────────────────────────
    st.subheader("🌐 Google Threat Intelligence")
    vt_api_key = st.secrets.get("VT_API_KEY", None) or st.text_input(
        "GTI / VirusTotal API Key",
        type="password",
        placeholder="Paste your VT API key",
        help="Get a free key at virustotal.com — Enterprise key from your GTI account manager"
    )
    if vt_api_key:
        st.success("GTI key loaded ✓")
    else:
        st.info("Add your GTI/VT API key to enable threat intelligence enrichment.")

    st.divider()

    # ── Gemini API Key ────────────────────────────────────────────────────────────
    st.subheader("🤖 AI Settings")
    gemini_api_key = st.secrets.get("GEMINI_API_KEY", None)
    if gemini_api_key:
        st.success("AI Analyst enabled ✓")
    else:
        st.info("Contact your admin to enable AI-powered summaries.")

    st.divider()
    st.caption("📋 PDF reports include SHA-256 hash + digital signature for court-admissible chain of custody.")

# ── File Upload ───────────────────────────────────────────────────────────────────
uploaded_file = st.file_uploader("Upload an APK file", type=["apk"])

if uploaded_file:
    if not analyst_name:
        st.warning("⚠️ No analyst name entered. Add your name in the sidebar for a complete chain-of-custody report.")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
        tmp.write(uploaded_file.read())
        tmp_path = tmp.name

    # ── Static Analysis ───────────────────────────────────────────────────────────
    with st.spinner("Running static analysis..."):
        try:
            result = analyse_apk(tmp_path)
        except Exception as e:
            st.error(f"Analysis failed: {e}")
            os.unlink(tmp_path)
            st.stop()

    # ── GTI Enrichment ────────────────────────────────────────────────────────────
    gti = None
    if vt_api_key:
        with st.spinner("Querying Google Threat Intelligence..."):
            gti = check_virustotal(tmp_path, result, vt_api_key)
            result["score"] += gti_score_boost(gti)

    # Delete temp file only after all file-based operations are complete
    os.unlink(tmp_path)

    risk_level, risk_color = get_risk_level(result["score"])

    # ── Risk Gauge ────────────────────────────────────────────────────────────────
    st.subheader("Risk Assessment")
    col1, col2, col3 = st.columns([1, 2, 1])

    with col1:
        st.metric("Package", result["package"])
        st.metric("Version", result["version"])

    with col2:
        st.markdown(
            f"""
            <div style='text-align:center; padding:20px; border-radius:12px;
                        background-color:{risk_color}22; border:2px solid {risk_color}'>
                <div style='font-size:48px; font-weight:bold; color:{risk_color}'>{risk_level}</div>
                <div style='font-size:28px; color:{risk_color}'>Score: {result["score"]}</div>
                <div style='font-size:13px; color:#888; margin-top:6px'>
                    {"✅ GTI enriched" if gti else "⚪ Static analysis only"}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
        st.progress(min(result["score"], 100) / 100)

    with col3:
        st.metric("Min SDK",    result["min_sdk"])
        st.metric("Target SDK", result["target_sdk"])

    # ── Evidence Integrity ────────────────────────────────────────────────────────
    st.divider()
    with st.expander("🔐 Evidence Integrity", expanded=True):
        c1, c2 = st.columns([1, 2])
        with c1:
            st.markdown("**MD5**")
            st.markdown("**SHA-1**")
            st.markdown("**SHA-256**")
            st.markdown("**Analyst**")
            st.markdown("**Timestamp (UTC)**")
        with c2:
            st.code(result["md5"],    language=None)
            st.code(result["sha1"],   language=None)
            st.code(result["sha256"], language=None)
            st.text(full_analyst.strip(" —") or "Not specified")
            st.text(datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
        st.caption("SHA-256 uniquely identifies this exact APK. Any modification changes the hash, detecting tampering.")

    # ── GTI Results ───────────────────────────────────────────────────────────────
    st.divider()
    st.subheader("🌐 Google Threat Intelligence Results")

    if gti:
        if gti.get("errors"):
            for err in gti["errors"]:
                st.warning(f"⚠️ {err}")

        file_data = gti.get("file")
        if file_data:
            if file_data.get("not_found"):
                st.info("📋 APK hash **not found** in VirusTotal — may be a new or private sample. Treat with caution.")
            else:
                malicious = file_data["malicious"]
                total     = file_data["total"]
                if malicious > 10:
                    st.error(f"🔴 **{malicious}/{total} antivirus engines flagged this APK as malicious**")
                elif malicious > 0:
                    st.warning(f"🟠 **{malicious}/{total} engines flagged this APK**")
                else:
                    st.success(f"✅ **0/{total} engines detected threats in this APK**")

                col_a, col_b, col_c = st.columns(3)
                col_a.metric("Malicious",  file_data["malicious"])
                col_b.metric("Suspicious", file_data["suspicious"])
                col_c.metric("Times Seen", file_data["times_seen"])

                if file_data.get("threat_name") and file_data["threat_name"] != "Unknown":
                    st.error(f"🏷️ Threat Label: **{file_data['threat_name']}**")

                st.markdown(f"[View full report on VirusTotal ↗]({file_data['link']})")

        if gti.get("ips"):
            st.markdown("**IP Address Reputation:**")
            for ip, data in gti["ips"].items():
                if data:
                    flag = "🔴" if data["malicious"] > 0 else "🟢"
                    st.markdown(
                        f"{flag} `{ip}` — {data['malicious']}/{data['total']} detections | "
                        f"{data.get('country', '?')} | {data.get('owner', '?')} "
                        f"[VT ↗]({data['link']})"
                    )
                else:
                    st.markdown(f"⚪ `{ip}` — Not found in GTI")

        if gti.get("urls"):
            st.markdown("**URL Reputation:**")
            for url, data in gti["urls"].items():
                if data:
                    flag  = "🔴" if data["malicious"] > 0 else "🟢"
                    short = url[:60] + "..." if len(url) > 60 else url
                    st.markdown(f"{flag} `{short}` — {data['malicious']}/{data['total']} detections")
                else:
                    st.markdown(f"⚪ `{url[:60]}` — Not found in GTI")
    else:
        st.warning("Add your **GTI / VirusTotal API key** in the sidebar to enable threat intelligence enrichment.")

    # ── AI Verdict ────────────────────────────────────────────────────────────────
    st.divider()
    st.subheader("🤖 AI Analyst Verdict")
    ai_summary = None
    if gemini_api_key:
        with st.spinner("Generating AI analysis..."):
            ai_summary = generate_ai_summary(result, gemini_api_key, gti)
        st.info(ai_summary)
    else:
        st.warning("Contact your admin to enable AI-powered verdicts.")

    st.divider()

    # ── Permissions & IoCs ────────────────────────────────────────────────────────
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
                gti_flag = ""
                if gti and gti["ips"].get(ip):
                    m = gti["ips"][ip].get("malicious", 0)
                    gti_flag = f"  🔴 GTI: {m} detections" if m > 0 else "  🟢 GTI: clean"
                st.code(f"{ip}{gti_flag}")

        if result["urls"]:
            with st.expander(f"URLs found ({len(result['urls'])})"):
                for u in result["urls"]:
                    gti_flag = ""
                    if gti and gti["urls"].get(u):
                        m = gti["urls"][u].get("malicious", 0)
                        gti_flag = f"  🔴 GTI: {m} detections" if m > 0 else "  🟢 GTI: clean"
                    st.text(f"{u}{gti_flag}")

        if result["keywords"]:
            st.warning(f"**Banking keywords:** {', '.join(result['keywords'])}")

        if not result["telegrams"] and not result["ips"] and not result["keywords"]:
            st.success("No IoCs detected.")

    st.divider()

    # ── App Components ────────────────────────────────────────────────────────────
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

    # ── Case Package Export (Feature 1) ───────────────────────────────────────────
    st.subheader("📦 Export Case Package")

    st.markdown(
        """
        The **Case Package** bundles everything an investigator needs to open a case file
        or submit to BNMLINK / Cyber999 / PDRM CCID — generated in one click.
        """
    )

    # Show what's included
    with st.expander("📋 What's inside the Case Package?", expanded=False):
        st.markdown("""
| File | Purpose |
|------|---------|
| `triage_report_*_signed.pdf` | Court-ready forensic report with digital signature |
| `evidence_*.json` | Machine-readable evidence for SIEM / case management systems |
| `incident_report_template_*.txt` | Pre-filled submission form for BNMLINK / Cyber999 / PDRM |
| `chain_of_custody_*.csv` | Timestamped chain-of-custody log |
| `README.txt` | Submission contacts and file guide |
        """)

    # Classification banner
    CLASS_COLORS = {
        "RESTRICTED":   "#e67e22",
        "CONFIDENTIAL": "#e74c3c",
        "SECRET":       "#8e44ad",
        "UNCLASSIFIED": "#27ae60",
    }
    cls_color = CLASS_COLORS.get(classification, "#888")
    st.markdown(
        f"<div style='text-align:center; padding:8px; border-radius:6px; "
        f"background:{cls_color}22; border:1.5px solid {cls_color}; "
        f"color:{cls_color}; font-weight:bold; font-size:15px; letter-spacing:2px'>"
        f"⚠ {classification}</div>",
        unsafe_allow_html=True
    )
    st.caption(f"Case Ref: **{case_number or 'UNASSIGNED'}** — set in sidebar")

    st.markdown("")

    col_a, col_b, col_c = st.columns(3)
    filename_base = f"triage_{re.sub(r'[^\\w.]', '_', result['package'])}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"

    # ── Button A: Full Case Package (ZIP) ─────────────────────────────────────────
    with col_a:
        st.markdown("#### 📦 Full Case Package")
        st.caption("ZIP containing signed PDF + JSON + incident template + CoC log")
        with st.spinner("Building case package..."):
            try:
                case_zip = generate_case_package(
                    result, analyst_name, analyst_org,
                    case_number, classification, gti, ai_summary
                )
                st.download_button(
                    label="⬇️ Download Case Package (.zip)",
                    data=case_zip,
                    file_name=f"case_package_{filename_base}.zip",
                    mime="application/zip",
                    use_container_width=True,
                )
            except Exception as e:
                st.error(f"Package generation failed: {e}")

    # ── Button B: PDF only (unsigned) ─────────────────────────────────────────────
    with col_b:
        st.markdown("#### 📄 PDF Report Only")
        st.caption("Unsigned PDF — quick preview or internal use")
        unsigned_pdf = generate_pdf(result, full_analyst, ai_summary, gti)
        st.download_button(
            label="⬇️ Download PDF (unsigned)",
            data=unsigned_pdf,
            file_name=f"{filename_base}.pdf",
            mime="application/pdf",
            use_container_width=True,
        )

    # ── Button C: JSON evidence only ──────────────────────────────────────────────
    with col_c:
        st.markdown("#### 🗂 JSON Evidence File")
        st.caption("Machine-readable — for SIEM, case management, or inter-agency sharing")
        evidence_json = generate_case_json(
            result, analyst_name, analyst_org,
            case_number, classification, gti, ai_summary
        )
        st.download_button(
            label="⬇️ Download evidence.json",
            data=json.dumps(evidence_json, indent=2, default=str),
            file_name=f"evidence_{filename_base}.json",
            mime="application/json",
            use_container_width=True,
        )

    st.divider()

    # ── Incident Report Preview ───────────────────────────────────────────────────
    with st.expander("📝 Preview: BNMLINK / Cyber999 Incident Report Template", expanded=False):
        template_text = generate_bnmlink_template(
            result, analyst_name, analyst_org, case_number, classification, gti
        )
        st.text(template_text)
        st.download_button(
            label="⬇️ Download Incident Report (.txt)",
            data=template_text,
            file_name=f"incident_report_{filename_base}.txt",
            mime="text/plain",
        )

    # ── Chain of Custody Preview ──────────────────────────────────────────────────
    with st.expander("🔗 Preview: Chain of Custody Log", expanded=False):
        coc_csv = generate_chain_of_custody_log(
            result, analyst_name, analyst_org, case_number
        )
        st.code(coc_csv, language=None)
        st.download_button(
            label="⬇️ Download Chain of Custody (.csv)",
            data=coc_csv,
            file_name=f"chain_of_custody_{filename_base}.csv",
            mime="text/csv",
        )

    st.caption("✅ Signed PDF uses a self-signed certificate. For court submission, replace with an agency-issued PKI certificate.")