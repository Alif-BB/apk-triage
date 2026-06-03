import re
import csv
import json
import zipfile
import datetime
import platform
import io
from io import BytesIO

from core.analyser import DANGEROUS_PERMISSIONS, get_risk_level, get_likelihood
from core.pdf_report import generate_pdf, sign_pdf_buffer, get_analysis_environment

# ─── IoC confidence levels ────────────────────────────────────────────────────────
# Telegram bot tokens are unique per operator — very strong clustering signal.
# Hardcoded IPs are strong but can be shared hosting — medium confidence.
# URLs contain too much SDK/namespace noise to be high confidence.

IOC_CONFIDENCE = {
    "telegram": "HIGH",
    "ip":       "MEDIUM",
    "url":      "LOW",
}


def generate_case_json(result, analyst_name, analyst_org, case_number,
                       classification, gti=None, ai_summary=None, tlp="GREEN"):
    """
    Structured JSON evidence file for case management / inter-agency sharing.

    Includes:
      - TLP classification (Traffic Light Protocol) — for MyCERT / CERT sharing
      - Confidence level per IoC — for SIEM ingestion and automated triage
      - Analysis environment — for s.90A Evidence Act 1950 compliance
      - GTI query timestamp — VT results are time-sensitive
    """
    risk_level, _ = get_risk_level(result["score"])

    gti_section = None
    if gti:
        # Capture query timestamp — GTI results change over time, date of query is material
        gti_query_timestamp = datetime.datetime.utcnow().isoformat() + "Z"
        file_data = gti.get("file")
        gti_section = {
            "query_timestamp_utc": gti_query_timestamp,
            "file_reputation": {
                "found":        not bool(file_data and file_data.get("not_found")),
                "malicious":    file_data.get("malicious")    if file_data and not file_data.get("not_found") else None,
                "suspicious":   file_data.get("suspicious")   if file_data and not file_data.get("not_found") else None,
                "total":        file_data.get("total")         if file_data and not file_data.get("not_found") else None,
                "threat_label": file_data.get("threat_name")  if file_data and not file_data.get("not_found") else None,
                "first_seen":   file_data.get("first_seen")   if file_data and not file_data.get("not_found") else None,
                "vt_link":      file_data.get("link")          if file_data and not file_data.get("not_found") else None,
            } if file_data else None,
            "ip_reputation": {
                ip: {"malicious": d.get("malicious"), "total": d.get("total"),
                     "country": d.get("country"), "owner": d.get("owner"), "vt_link": d.get("link")} if d else None
                for ip, d in gti.get("ips", {}).items()
            },
            "url_reputation": {
                url: {"malicious": d.get("malicious"), "total": d.get("total"), "vt_link": d.get("link")} if d else None
                for url, d in gti.get("urls", {}).items()
            },
            "errors": gti.get("errors", []),
        }

    # ── IoCs with confidence levels ───────────────────────────────────────────────
    # Each IoC is now a dict with value + confidence, not a bare string.
    # This allows SIEM systems and MyCERT recipients to filter by confidence
    # without having to manually assess trust for each indicator type.
    iocs_with_confidence = {
        "telegram_c2": [
            {"value": t, "confidence": IOC_CONFIDENCE["telegram"]}
            for t in result.get("telegrams", [])
        ],
        "hardcoded_ips": [
            {"value": ip, "confidence": IOC_CONFIDENCE["ip"]}
            for ip in result.get("ips", [])
        ],
        "urls": [
            {"value": url, "confidence": IOC_CONFIDENCE["url"]}
            for url in result.get("urls", [])
        ],
        "banking_keywords": list(result.get("keywords", [])),
    }

    return {
        "case_metadata": {
            "case_number":      case_number or "UNASSIGNED",
            "classification":   classification,
            # TLP marking for inter-agency sharing (MyCERT, regional CERTs).
            # WHITE  = unrestricted sharing
            # GREEN  = share within community (default)
            # AMBER  = share with members on need-to-know basis
            # RED    = no disclosure outside specific recipients
            "tlp":              tlp,
            "generated_at_utc": datetime.datetime.utcnow().isoformat() + "Z",
            "tool":             "APK Triage v1.0",
            "analyst":          analyst_name or "Not specified",
            "unit":             analyst_org  or "Not specified",
        },
        "evidence_integrity": {
            "filename": f"{result['package']}.apk",
            "md5":      result["md5"],
            "sha1":     result["sha1"],
            "sha256":   result["sha256"],
        },
        # Analysis environment — required for s.90A Evidence Act 1950.
        # Documents the system that produced this evidence file.
        "analysis_environment": get_analysis_environment(),
        "app_info": {
            "package":    result["package"],
            "version":    result["version"],
            "min_sdk":    result["min_sdk"],
            "target_sdk": result["target_sdk"],
        },
        "risk_assessment": {
            "score":      result["score"],
            "likelihood": result.get("likelihood", get_likelihood(result["score"])),
            "likelihood_label": f"{result.get('likelihood', get_likelihood(result['score']))}% probability of malicious behaviour",
            "level":      risk_level,
        },
        "dangerous_permissions": [
            {"permission": p, "description": DANGEROUS_PERMISSIONS[p][0], "score": DANGEROUS_PERMISSIONS[p][1]}
            for p in result["permissions"] if p in DANGEROUS_PERMISSIONS
        ],
        "all_permissions": list(result["permissions"]),
        "indicators_of_compromise": iocs_with_confidence,
        "app_components": {
            "receivers":  list(result["receivers"]),
            "services":   list(result["services"]),
            "activities": list(result["activities"]),
        },
        "threat_intelligence": gti_section,
        "ai_verdict": ai_summary or None,
    }


def generate_bnmlink_template(result, analyst_name, analyst_org, case_number,
                               classification, gti=None, tlp="GREEN"):
    """
    Pre-filled incident report for BNMLINK / Cyber999 / PDRM CCID submission.

    Structure:
      1. VICTIM DETAILS — at the top, needed immediately by NSRC for fund freezing
      2. RECOMMENDED ACTIONS — NSRC 997 is step 1
      3. Submission details, incident summary, evidence, IoCs
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
                f"GTI Query Timestamp   : {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}\n"
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
        f"  TLP:{tlp}",
        "=" * 70,
        "",

        # ── VICTIM DETAILS (moved to top) ────────────────────────────────────────
        # NSRC and NFP require IC number and bank account number to initiate
        # automated fund tracing. These MUST be filled before calling 997 or
        # submitting to any agency. The fund freezing window is narrow.
        "⚠ ── VICTIM DETAILS — COMPLETE THIS SECTION FIRST ─────────────────────",
        "  The NSRC (hotline 997) and National Fraud Portal require victim IC",
        "  number and bank account details to initiate fund freezing.",
        "  Time is critical — incomplete details delay or prevent fund recovery.",
        "",
        "  Victim Full Name     : _______________________________________________",
        "  Victim IC / MyKad   : _______________________________________________",
        "  Victim Phone Number  : _______________________________________________",
        "  Bank Name Affected   : _______________________________________________",
        "  Bank Account Number  : _______________________________________________",
        "  Amount Lost (RM)     : _______________________________________________",
        "  Date of Incident     : _______________________________________________",
        "  How APK Was Received : _______________________________________________",
        "  (e.g. WhatsApp link, SMS, Telegram, fake website, email attachment)",
        "",
        "  Last Known Transaction Date/Time : __________________________________",
        "  Receiving Account (if known)     : __________________________________",
        "",

        # ── RECOMMENDED ACTIONS (NSRC 997 is now step 1) ────────────────────────
        "⚠ ── RECOMMENDED ACTIONS — READ BEFORE SUBMITTING ──────────────────────",
        "",
        "  STEP 1 — CALL NSRC 997 if victim has active financial loss.",
        "           NSRC can initiate fund freezing via the National Fraud Portal.",
        "           ⚠ This is time-critical. Do this BEFORE filing any written report.",
        "           Operating hours: 8:00 AM – 8:00 PM DAILY (including public holidays).",
        "           Have victim IC number and bank account number ready.",
        "           ⚠ If fraud discovered OUTSIDE operating hours (e.g. late at night):",
        "             → Call the victim's bank 24/7 fraud hotline IMMEDIATELY instead.",
        "             → Maybank   : 1-300-88-6688  |  CIMB    : 1-300-880-900",
        "             → RHB       : 1-800-88-9878   |  Public  : 1-800-22-5577",
        "             → Hong Leong: 1-300-88-8811  |  BSN     : 1-300-88-1900",
        "             → Request an EMERGENCY ACCOUNT FREEZE from the bank directly.",
        "",
        "  STEP 2 — Do NOT install or run this APK on any non-sandboxed device.",
        "",
        "  STEP 3 — Submit APK sample to CyberSecurity Malaysia (Cyber999):",
        "           Email : cyber999@cybersecurity.my",
        "           Phone : 1-300-88-2999 (office hours) | +60 19-2665850 (24/7)",
        "           Form  : mycert.org.my  (use for structured IoC submission)",
        "           When submitting via form, select:",
        "             Incident Type    : Malicious Code",
        "             Affected Platform: Android",
        "             Affected Resource: [paste SHA-256 hash below]",
        "",
        "  STEP 4 — Escalate to BNMLINK only if the bank fails to act:",
        "           BNM TELELINK is NOT a first-response fraud line. Use it to escalate",
        "           if: (a) victim's account is wrongly blocked, or (b) victim is",
        "           dissatisfied with how their bank's complaint unit handled the case.",
        "           Email : bnmlink@bnm.gov.my  |  Phone : 1-300-88-5465",
        "",
        "  STEP 5 — File police report with PDRM CCID:",
        "           ⚠ Victim MUST physically attend the nearest police station",
        "             within 24 hours to file an official report in person.",
        "             An investigating officer (IO) can only be assigned via",
        "             a physical report — online e-Reporting does NOT apply",
        "             to criminal matters and will reject scam/fraud cases.",
        "           CCID Main Line   : 03-2610 1222",
        "           CCID Ops Room    : 03-2610 1599",
        "",
        "  STEP 6 — If Telegram C2 detected — report bot token to Telegram:",
        "           https://telegram.org/support",
        "",
        "  STEP 7 — Request C2 IP/domain takedown via MyCERT:",
        "           mycert@cybersecurity.my",
        "",

        # ── SUBMISSION DETAILS ───────────────────────────────────────────────────
        "── SUBMISSION DETAILS ──────────────────────────────────────────────────",
        f"  Report Date      : {now}",
        f"  Case Reference   : {case_number or 'UNASSIGNED — assign before submission'}",
        f"  Classification   : {classification}  |  TLP:{tlp}",
        f"  Prepared By      : {analyst_name or 'Not specified'}",
        f"  Unit / Agency    : {analyst_org or 'Not specified'}",
        "",

        # ── INCIDENT SUMMARY ─────────────────────────────────────────────────────
        "── INCIDENT SUMMARY ────────────────────────────────────────────────────",
        f"  Incident Type    : Malicious Android APK — Mobile Banking Fraud",
        f"  Risk Level       : {risk_level}  ({result.get('likelihood', get_likelihood(result['score']))}% likelihood of malicious behaviour)",
        f"  APK Package Name : {result['package']}",
        f"  APK Version      : {result['version']}",
        "",

        # ── EVIDENCE INTEGRITY ───────────────────────────────────────────────────
        "── EVIDENCE INTEGRITY ──────────────────────────────────────────────────",
        f"  MD5    : {result['md5']}",
        f"  SHA-1  : {result['sha1']}",
        f"  SHA-256: {result['sha256']}",
        "",

        # ── ANALYSIS ENVIRONMENT ─────────────────────────────────────────────────
        "── ANALYSIS ENVIRONMENT (s.90A Evidence Act 1950) ──────────────────────",
    ]

    env = get_analysis_environment()
    lines += [
        f"  Tool             : {env['tool']}",
        f"  Python           : {env['python_version']}",
        f"  Androguard       : {env['androguard']}",
        f"  OS               : {env['os']}",
        f"  Hostname         : {env['hostname']}",
        f"  Generated (UTC)  : {env['generated_at_utc']}",
        "",
    ]

    lines += [
        "── THREAT INTELLIGENCE (VirusTotal / GTI) ──────────────────────────────",
        *[f"  {line}" for line in gti_block.splitlines()],
        "",
        "── DANGEROUS CAPABILITIES DETECTED ────────────────────────────────────",
    ]

    if danger_perms:
        for p in danger_perms:
            full = f"android.permission.{p}"
            desc = DANGEROUS_PERMISSIONS[full][0] if full in DANGEROUS_PERMISSIONS else ""
            lines.append(f"  [!] {p}")
            if desc:
                lines.append(f"       -> {desc}")
    else:
        lines.append("  None detected.")

    lines += ["", "── INDICATORS OF COMPROMISE (IoCs) ─────────────────────────────────────"]

    if result["telegrams"]:
        lines.append("  Telegram C2  [confidence: HIGH]:")
        for t in result["telegrams"]:
            lines.append(f"    - {t}")
    if result["ips"]:
        lines.append("  Hardcoded IP Addresses  [confidence: MEDIUM]:")
        for ip in result["ips"]:
            lines.append(f"    - {ip}")
    if result["keywords"]:
        lines.append(f"  Banking Keywords  [confidence: LOW]: {', '.join(result['keywords'])}")
    if not result["telegrams"] and not result["ips"] and not result["keywords"]:
        lines.append("  No IoCs detected.")

    lines += [
        "",
        "── CYBER999 FORM QUICK-FILL ─────────────────────────────────────────────",
        "  Use these values when submitting via mycert.org.my online form.",
        "  MyCERT requires: Source of attack, Destination of attack, Log files,",
        "  Email header (if applicable), and Time of attack. Mapped below:",
        "",
        f"  Incident Type      : Malicious Code",
        f"  Affected Platform  : Android",
        f"  Affected Resource  : {result['sha256']}",
        f"  Brief Description  : Malicious APK — {result['package']} — Risk: {risk_level}",
        "",
        "  SOURCE OF ATTACK",
        "  (= 'How APK Was Received' from victim details above)",
        "  Copy from victim details: How APK Was Received field.",
        "  e.g. 'WhatsApp link from unknown number' / 'SMS with download URL'",
        "",
        "  DESTINATION OF ATTACK",
        f"  Package Name       : {result['package']}",
        f"  SHA-256            : {result['sha256']}",
        f"  MD5                : {result['md5']}",
        "  Affected Device    : Victim's Android phone (model: [fill in if known])",
        "  Bank / App Targeted: [fill in from victim details above]",
        "",
        "  TIME OF ATTACK",
        "  (= 'Date of Incident' from victim details above)",
        "  Copy from victim details: Date of Incident field.",
        "  Format MyCERT expects: YYYY-MM-DD HH:MM (local time, MYT UTC+8)",
        "",
        "  LOG FILES / SUPPORTING ARTIFACTS TO ATTACH:",
        "  - This report (.txt)",
        "  - evidence_*.json (machine-readable IoCs)",
        "  - triage_report_*_signed.pdf (forensic report)",
        "  - Screenshots of fraudulent messages / download links (if available)",
        "  - chain_of_custody_*.csv",
        "",
        "  EMAIL HEADER  : Not applicable (APK delivered via app/SMS, not email).",
        "                  If APK was delivered via email, attach the full raw",
        "                  email header from the victim's email client.",
        "",
        "=" * 70,
        "  This report was generated automatically by APK Triage v1.0.",
        "  Verify hash values before submission to confirm evidence integrity.",
        "=" * 70,
    ]

    return "\n".join(lines)


def generate_chain_of_custody_log(result, analyst_name, analyst_org, case_number):
    """
    Returns a CSV chain-of-custody log.
    Includes analysis environment details and blank handover rows
    for subsequent transfers (to forensic lab, court clerk, etc.).
    """
    now_utc = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    env     = get_analysis_environment()

    rows = [
        ["#", "Timestamp (UTC)", "Action", "Actor", "Unit / Badge", "Details", "SHA-256"],

        ["1", now_utc, "Evidence Received",
         analyst_name or "Not specified", analyst_org or "Not specified",
         f"APK uploaded for triage — Package: {result['package']} v{result['version']} — "
         f"Received via: [fill in: seized device / email / WhatsApp / other]",
         result["sha256"]],

        ["2", now_utc, "Hash Verification",
         "APK Triage Tool v1.0", "Automated",
         f"MD5: {result['md5']}  |  SHA-1: {result['sha1']}  |  SHA-256: {result['sha256']}",
         result["sha256"]],

        # Analysis environment row — s.90A compliance
        ["3", now_utc, "Analysis Environment Recorded",
         "APK Triage Tool v1.0", "Automated",
         f"Tool: {env['tool']}  |  Python: {env['python_version']}  |  "
         f"Androguard: {env['androguard']}  |  OS: {env['os']}  |  "
         f"Hostname: {env['hostname']}",
         result["sha256"]],

        ["4", now_utc, "Static Analysis",
         "APK Triage Tool v1.0", "Automated",
         f"Risk Score: {result['score']}  |  "
         f"Dangerous permissions: {sum(1 for p in result['permissions'] if p in DANGEROUS_PERMISSIONS)}  |  "
         f"Telegram C2: {len(result['telegrams'])}  |  Hardcoded IPs: {len(result['ips'])}",
         result["sha256"]],

        ["5", now_utc, "GTI Enrichment",
         "APK Triage Tool v1.0 / VirusTotal", "Automated",
         f"VirusTotal hash + IP + URL reputation queries executed at {now_utc}",
         result["sha256"]],

        ["6", now_utc, "Report Generated",
         analyst_name or "Not specified", analyst_org or "Not specified",
         f"Case Package generated — Case Ref: {case_number or 'UNASSIGNED'}",
         result["sha256"]],

        # ── Evidence storage ─────────────────────────────────────────────────────
        # Fill in where the original APK is stored after analysis.
        ["7", "[fill in]", "Evidence Stored",
         analyst_name or "Not specified", analyst_org or "Not specified",
         "Original APK stored at: [fill in storage location, device ID, volume label]  |  "
         "Storage hash verified: [YES / NO]",
         result["sha256"]],

        # ── Handover rows — fill in each time evidence changes hands ─────────────
        # Required under the Criminal Procedure Code — every transfer must be logged.
        ["8", "[fill in]", "Evidence Handover",
         "[transferring officer name / badge]", "[unit]",
         "Transferred to: [recipient name / badge / organisation]  |  "
         "Method: [hand delivery / courier / encrypted email]  |  "
         "Purpose: [forensic lab / PDRM submission / court filing]",
         result["sha256"]],

        ["9", "[fill in]", "Evidence Handover",
         "[transferring officer name / badge]", "[unit]",
         "Transferred to: [recipient name / badge / organisation]  |  "
         "Method: [hand delivery / courier / encrypted email]  |  "
         "Purpose: [forensic lab / PDRM submission / court filing]",
         result["sha256"]],

        ["10", "[fill in]", "Evidence Handover",
         "[transferring officer name / badge]", "[unit]",
         "Transferred to: [recipient name / badge / organisation]  |  "
         "Method: [hand delivery / courier / encrypted email]  |  "
         "Purpose: [forensic lab / PDRM submission / court filing]",
         result["sha256"]],
    ]

    output = io.StringIO()
    writer = csv.writer(output)
    for row in rows:
        writer.writerow(row)
    return output.getvalue()


def generate_case_package(result, analyst_name, analyst_org, case_number,
                          classification, gti=None, ai_summary=None, tlp="GREEN"):
    """
    Bundles all case files into a single ZIP.
    tlp parameter flows through to JSON and incident report template.
    """
    pkg_buffer = BytesIO()
    ts         = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_pkg   = re.sub(r'[^\w.]', '_', result["package"])
    full_name  = f"{analyst_name} — {analyst_org}" if analyst_org else analyst_name

    with zipfile.ZipFile(pkg_buffer, "w", zipfile.ZIP_DEFLATED) as zf:

        # 1 — Signed PDF
        try:
            pdf_buf    = generate_pdf(result, full_name, ai_summary, gti)
            signed_pdf = sign_pdf_buffer(pdf_buf, analyst_name or "Unknown Analyst")
            zf.writestr(f"triage_report_{safe_pkg}_{ts}_signed.pdf", signed_pdf.read())
        except Exception as e:
            zf.writestr("triage_report_ERROR.txt", f"PDF generation failed: {e}")

        # 2 — JSON evidence
        evidence = generate_case_json(result, analyst_name, analyst_org,
                                      case_number, classification, gti, ai_summary, tlp)
        zf.writestr(f"evidence_{safe_pkg}_{ts}.json",
                    json.dumps(evidence, indent=2, default=str))

        # 3 — Incident report template
        template = generate_bnmlink_template(result, analyst_name, analyst_org,
                                             case_number, classification, gti, tlp)
        zf.writestr(f"incident_report_template_{safe_pkg}_{ts}.txt", template)

        # 4 — Chain of custody
        coc_csv = generate_chain_of_custody_log(result, analyst_name, analyst_org, case_number)
        zf.writestr(f"chain_of_custody_{safe_pkg}_{ts}.csv", coc_csv)

        # 5 — README
        readme = "\n".join([
            "APK TRIAGE — CASE PACKAGE",
            "=" * 40,
            f"Case Reference  : {case_number or 'UNASSIGNED'}",
            f"Classification  : {classification}  |  TLP:{tlp}",
            f"Package         : {result['package']}",
            f"SHA-256         : {result['sha256']}",
            f"Generated       : {datetime.datetime.utcnow().isoformat()}Z",
            f"Analyst         : {analyst_name or 'Not specified'}",
            f"Unit            : {analyst_org or 'Not specified'}",
            "",
            "FILES IN THIS PACKAGE",
            "-" * 40,
            "triage_report_*_signed.pdf      -> Court-ready PDF with digital signature",
            "evidence_*.json                 -> Machine-readable evidence (for SIEM/case mgmt)",
            "incident_report_template_*.txt  -> Pre-filled submission for BNMLINK / Cyber999",
            "chain_of_custody_*.csv          -> Timestamped chain-of-custody log",
            "",
            "FIRST RESPONSE",
            "-" * 40,
            "If victim has active financial loss: CALL NSRC 997 IMMEDIATELY.",
            "Have victim IC number and bank account ready. Fund freezing window is narrow.",
            "",
            "SUBMISSION CONTACTS",
            "-" * 40,
            "NSRC (fund freezing)          : 997  (8AM–8PM daily — call this FIRST)",
            "BNMLINK (Bank Negara)         : bnmlink@bnm.gov.my  |  1-300-88-5465  (escalation only)",
            "Cyber999 (CyberSecurity MY)   : cyber999@cybersecurity.my  |  +60 19-2665850 (24/7)",
            "Cyber999 online form          : mycert.org.my",
            "PDRM CCID Main Line           : 03-2610 1222",
            "PDRM CCID Ops Room            : 03-2610 1599",
            "PDRM police report            : Nearest police station in person (within 24 hours)",
        ])
        zf.writestr("README.txt", readme)

    pkg_buffer.seek(0)
    return pkg_buffer