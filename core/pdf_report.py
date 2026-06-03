import os
import platform
import asyncio
import datetime
from io import BytesIO

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.units import cm

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import pkcs12 as crypto_pkcs12

from pyhanko.sign import signers, fields
from pyhanko.pdf_utils import incremental_writer
from pyhanko.sign.fields import SigFieldSpec

from core.analyser import DANGEROUS_PERMISSIONS, get_risk_level, get_likelihood

CERT_PATH = os.path.join(os.path.expanduser("~"), ".apktriage_signer.p12")
CERT_PASS = b"apktriage_internal"


def get_or_create_signing_cert():
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
    signer = get_or_create_signing_cert()

    async def _sign():
        w = incremental_writer.IncrementalPdfFileWriter(unsigned_buffer)
        fields.append_signature_field(
            w, SigFieldSpec("DigitalSignature", on_page=-1, box=(36, 36, 300, 60))
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


def _get_androguard_version() -> str:
    """Safely retrieve the installed androguard version string."""
    try:
        import importlib.metadata
        return importlib.metadata.version("androguard")
    except Exception:
        try:
            import androguard
            return getattr(androguard, "__version__", "unknown")
        except Exception:
            return "unknown"


def get_analysis_environment() -> dict:
    """
    Collects runtime environment details required for s.90A Evidence Act 1950
    compliance — the court needs to know exactly what produced this report.
    """
    return {
        "tool":             "APK Triage v1.0",
        "python_version":   platform.python_version(),
        "androguard":       _get_androguard_version(),
        "os":               f"{platform.system()} {platform.release()}",
        "hostname":         platform.node(),
        "architecture":     platform.machine(),
        "generated_at_utc": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    }


def generate_pdf(result, analyst_name, ai_summary=None, gti=None):
    buffer = BytesIO()
    doc    = SimpleDocTemplate(buffer, pagesize=A4,
                               rightMargin=2*cm, leftMargin=2*cm,
                               topMargin=2*cm, bottomMargin=2*cm)
    styles        = getSampleStyleSheet()
    story         = []
    risk_level, _ = get_risk_level(result["score"])
    generated_at  = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Title
    story.append(Paragraph("APK Triage Report", styles["Title"]))
    story.append(Paragraph(
        f"Generated: {generated_at}  |  Powered by Google Threat Intelligence (VirusTotal)",
        styles["Normal"]
    ))
    story.append(Spacer(1, 0.5*cm))

    # ── App Info
    info_data = [
        ["Package",    result["package"]],
        ["Version",    result["version"]],
        ["Min SDK",    result["min_sdk"]],
        ["Target SDK", result["target_sdk"]],
        ["Risk Score", f"{result['score']} / 300 (raw)"],
        ["Likelihood", f"{result.get('likelihood', get_likelihood(result['score']))}% malicious"],
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

    # ── Evidence Integrity
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

    # ── Analysis Environment  ← NEW SECTION
    # Required for s.90A Evidence Act 1950 — documents the system that produced this report.
    story.append(Paragraph("Analysis Environment", styles["Heading2"]))
    story.append(Paragraph(
        "The following environment details are recorded to satisfy s.90A of the Evidence Act 1950 "
        "(Malaysia), which requires that the computer producing a document be identified and shown "
        "to be operating correctly at the time of production.",
        styles["Normal"]
    ))
    story.append(Spacer(1, 0.2*cm))

    env = get_analysis_environment()
    env_data = [
        ["Environment Field", "Value"],
        ["Tool",              env["tool"]],
        ["Python Version",    env["python_version"]],
        ["Androguard Version",env["androguard"]],
        ["Operating System",  env["os"]],
        ["Hostname / Station",env["hostname"]],
        ["Architecture",      env["architecture"]],
        ["Report Generated",  env["generated_at_utc"]],
        ["Certificate Type",  "Self-signed (internal use). Replace with agency PKI cert for court submission."],
    ]
    env_table = Table(env_data, colWidths=[4*cm, 13*cm])
    env_table.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0),  colors.HexColor("#1a3a5c")),
        ("TEXTCOLOR",      (0, 0), (-1, 0),  colors.white),
        ("FONTNAME",       (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("BACKGROUND",     (0, 1), (0, -1),  colors.HexColor("#ecf0f1")),
        ("FONTNAME",       (0, 1), (0, -1),  "Helvetica-Bold"),
        ("GRID",           (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING",        (0, 0), (-1, -1), 6),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
        ("FONTSIZE",       (0, 0), (-1, -1), 9),
    ]))
    story.append(env_table)
    story.append(Spacer(1, 0.4*cm))

    # ── GTI Section
    story.append(Paragraph("Google Threat Intelligence (VirusTotal)", styles["Heading2"]))
    if gti:
        if gti.get("errors"):
            for err in gti["errors"]:
                story.append(Paragraph(f"Warning: {err}", styles["Normal"]))
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
                    story.append(Paragraph(f"Threat label: {file_data['threat_name']}", styles["Normal"]))
                story.append(Paragraph(
                    f"First seen: {file_data.get('first_seen', 'N/A')}  |  "
                    f"Times submitted: {file_data.get('times_seen', 'N/A')}  |  "
                    f"GTI query timestamp: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
                    styles["Normal"]
                ))
                story.append(Paragraph(f"Full report: {file_data['link']}", styles["Normal"]))
        malicious_ips = {ip: d for ip, d in gti.get("ips", {}).items() if d and d.get("malicious", 0) > 0}
        if malicious_ips:
            story.append(Paragraph("Malicious IPs confirmed by GTI:", styles["Heading3"]))
            for ip, data in malicious_ips.items():
                story.append(Paragraph(
                    f"- {ip} — {data['malicious']}/{data['total']} detections | {data.get('country', '')} | {data.get('owner', '')}",
                    styles["Normal"]
                ))
        malicious_urls = {url: d for url, d in gti.get("urls", {}).items() if d and d.get("malicious", 0) > 0}
        if malicious_urls:
            story.append(Paragraph("Malicious URLs confirmed by GTI:", styles["Heading3"]))
            for url, data in malicious_urls.items():
                story.append(Paragraph(f"- {url} — {data['malicious']}/{data['total']} detections", styles["Normal"]))
    else:
        story.append(Paragraph("GTI enrichment was not performed (no API key provided).", styles["Normal"]))
    story.append(Spacer(1, 0.4*cm))

    # ── AI Verdict
    if ai_summary:
        story.append(Paragraph("AI Analyst Verdict", styles["Heading2"]))
        story.append(Paragraph(
            "⚠ Note: The following is AI-generated analysis for investigator reference only. "
            "It must NOT be presented as expert forensic opinion in court proceedings.",
            styles["Normal"]
        ))
        story.append(Spacer(1, 0.15*cm))
        for para in ai_summary.strip().split("\n\n"):
            if para.strip():
                story.append(Paragraph(para.strip(), styles["Normal"]))
                story.append(Spacer(1, 0.2*cm))
        story.append(Spacer(1, 0.3*cm))

    # ── Dangerous Permissions
    story.append(Paragraph("Dangerous Permissions", styles["Heading2"]))
    danger_perms = [p for p in result["permissions"] if p in DANGEROUS_PERMISSIONS]
    if danger_perms:
        for p in danger_perms:
            desc = DANGEROUS_PERMISSIONS[p][0]
            story.append(Paragraph(f"- {p}", styles["Normal"]))
            story.append(Paragraph(f"  -> {desc}", styles["Normal"]))
    else:
        story.append(Paragraph("None detected.", styles["Normal"]))
    story.append(Spacer(1, 0.4*cm))

    # ── IoCs
    story.append(Paragraph("Indicators of Compromise (IoCs)", styles["Heading2"]))
    for label, items in [("Telegram tokens",  result["telegrams"]),
                          ("Hardcoded IPs",    result["ips"]),
                          ("URLs",             result["urls"]),
                          ("Banking keywords", result["keywords"])]:
        story.append(Paragraph(f"{label}:", styles["Heading3"]))
        if items:
            for item in items:
                story.append(Paragraph(f"- {item}", styles["Normal"]))
        else:
            story.append(Paragraph("None found.", styles["Normal"]))
        story.append(Spacer(1, 0.2*cm))

    # ── App Components
    story.append(Paragraph("App Components", styles["Heading2"]))
    for label, items in [("Receivers",  result["receivers"]),
                          ("Services",   result["services"]),
                          ("Activities", result["activities"])]:
        story.append(Paragraph(f"{label}:", styles["Heading3"]))
        for item in (items or ["None"]):
            story.append(Paragraph(f"- {item}", styles["Normal"]))
        story.append(Spacer(1, 0.2*cm))

    doc.build(story)
    buffer.seek(0)
    return buffer