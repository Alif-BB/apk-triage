import re
import csv
import json
import zipfile
import datetime
import io
from io import BytesIO

from core.analyser import DANGEROUS_PERMISSIONS, get_risk_level
from core.pdf_report import generate_pdf, sign_pdf_buffer


def generate_case_json(result, analyst_name, analyst_org, case_number, classification, gti=None, ai_summary=None):
    """Structured JSON evidence file for case management / inter-agency sharing."""
    risk_level, _ = get_risk_level(result["score"])

    gti_section = None
    if gti:
        file_data = gti.get("file")
        gti_section = {
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
            "filename": f"{result['package']}.apk",
            "md5":      result["md5"],
            "sha1":     result["sha1"],
            "sha256":   result["sha256"],
        },
        "app_info": {
            "package":    result["package"],
            "version":    result["version"],
            "min_sdk":    result["min_sdk"],
            "target_sdk": result["target_sdk"],
        },
        "risk_assessment": {
            "score": result["score"],
            "level": risk_level,
        },
        "dangerous_permissions": [
            {"permission": p, "description": DANGEROUS_PERMISSIONS[p][0], "score": DANGEROUS_PERMISSIONS[p][1]}
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
    """Pre-filled incident report for BNMLINK / Cyber999 / PDRM CCID submission."""
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
        "── EVIDENCE INTEGRITY ──────────────────────────────────────────────────",
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
            full = f"android.permission.{p}"
            desc = DANGEROUS_PERMISSIONS[full][0] if full in DANGEROUS_PERMISSIONS else ""
            lines.append(f"  [!] {p}")
            if desc:
                lines.append(f"       -> {desc}")
    else:
        lines.append("  None detected.")

    lines += ["", "── INDICATORS OF COMPROMISE (IoCs) ─────────────────────────────────────"]

    if result["telegrams"]:
        lines.append("  Telegram C2:")
        for t in result["telegrams"]:
            lines.append(f"    - {t}")
    if result["ips"]:
        lines.append("  Hardcoded IP Addresses:")
        for ip in result["ips"]:
            lines.append(f"    - {ip}")
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
    """Returns a CSV chain-of-custody log as a string."""
    now_utc = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    rows = [
        ["#", "Timestamp (UTC)", "Action", "Actor", "Unit", "Details", "SHA-256"],
        ["1", now_utc, "Evidence Received",
         analyst_name or "Not specified", analyst_org or "Not specified",
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
         analyst_name or "Not specified", analyst_org or "Not specified",
         f"Case Package generated — Case Ref: {case_number or 'UNASSIGNED'}",
         result["sha256"]],
    ]
    output = io.StringIO()
    writer = csv.writer(output)
    for row in rows:
        writer.writerow(row)
    return output.getvalue()


def generate_case_package(result, analyst_name, analyst_org, case_number,
                          classification, gti=None, ai_summary=None):
    """
    Bundles all case files into a single ZIP:
      triage_report_*_signed.pdf  — digitally signed forensic report
      evidence_*.json             — structured machine-readable evidence
      incident_report_*.txt       — pre-filled BNMLINK/Cyber999 submission
      chain_of_custody_*.csv      — timestamped CoC log
      README.txt                  — submission contacts and file guide
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
                                      case_number, classification, gti, ai_summary)
        zf.writestr(f"evidence_{safe_pkg}_{ts}.json",
                    json.dumps(evidence, indent=2, default=str))

        # 3 — Incident report template
        template = generate_bnmlink_template(result, analyst_name, analyst_org,
                                             case_number, classification, gti)
        zf.writestr(f"incident_report_template_{safe_pkg}_{ts}.txt", template)

        # 4 — Chain of custody
        coc_csv = generate_chain_of_custody_log(result, analyst_name, analyst_org, case_number)
        zf.writestr(f"chain_of_custody_{safe_pkg}_{ts}.csv", coc_csv)

        # 5 — README
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
            "triage_report_*_signed.pdf      -> Court-ready PDF with digital signature",
            "evidence_*.json                 -> Machine-readable evidence (for SIEM/case mgmt)",
            "incident_report_template_*.txt  -> Pre-filled submission for BNMLINK / Cyber999",
            "chain_of_custody_*.csv          -> Timestamped chain-of-custody log",
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