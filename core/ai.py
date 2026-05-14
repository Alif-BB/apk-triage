import re
import google.generativeai as genai
from core.analyser import DANGEROUS_PERMISSIONS, get_risk_level


def generate_ai_summary(result, api_key, gti=None):
    """
    Calls Gemini to produce a 3-paragraph plain-English verdict
    suitable for non-technical investigators (PDRM, BNM, bank officers).
    """
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