from loguru import logger
logger.disable("androguard")

from androguard.misc import AnalyzeAPK
import sys
import re

# ─── Patterns ───────────────────────────────────────────────────────────────────

URL_PATTERN      = re.compile(r'https?://[^\s\'"<>]{4,}')
IP_PATTERN       = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
TELEGRAM_PATTERN = re.compile(r'(?:bot\d{8,12}:[A-Za-z0-9_-]{35,}|t\.me/[^\s\'"]{3,})')
KEYWORD_PATTERN  = re.compile(r'(?i)(maybank|cimb|rhb|pbebank|hongleong|bankislam|TAC|OTP|transaction)')
EXCLUDED_IPS = {"127.0.0.1", "0.0.0.0", "255.255.255.255"}

# ─── Scoring Rules ──────────────────────────────────────────────────────────────
#
# Each rule has:
#   "type"        : "permission", "receiver", "string"
#   "match"       : exact string or compiled regex
#   "score"       : how many points this finding adds
#   "label"       : what to print in the report
#   "description" : why this is suspicious 

RULES = [
    # --- High-risk permissions ---
    {
        "type": "permission",
        "match": "android.permission.RECEIVE_SMS",
        "score": 30,
        "label": "RECEIVE_SMS permission",
        "description": "App can intercept incoming SMS — used to steal TAC/OTP codes"
    },
    {
        "type": "permission",
        "match": "android.permission.READ_SMS",
        "score": 25,
        "label": "READ_SMS permission",
        "description": "App can read all SMS messages on the device"
    },
    {
        "type": "permission",
        "match": "android.permission.SEND_SMS",
        "score": 20,
        "label": "SEND_SMS permission",
        "description": "App can send SMS silently without user knowledge"
    },
    {
        "type": "permission",
        "match": "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "score": 30,
        "label": "BIND_ACCESSIBILITY_SERVICE permission",
        "description": "Enables overlay attacks — app can tap buttons on behalf of user"
    },
    {
        "type": "permission",
        "match": "android.permission.SYSTEM_ALERT_WINDOW",
        "score": 25,
        "label": "SYSTEM_ALERT_WINDOW permission",
        "description": "App can draw over other apps — classic phishing overlay technique"
    },
    {
        "type": "permission",
        "match": "android.permission.REQUEST_INSTALL_PACKAGES",
        "score": 20,
        "label": "REQUEST_INSTALL_PACKAGES permission",
        "description": "App can silently install other APKs — dropper malware behaviour"
    },
    {
        "type": "permission",
        "match": "android.permission.READ_CONTACTS",
        "score": 15,
        "label": "READ_CONTACTS permission",
        "description": "App can harvest contact list — used for scam propagation"
    },
    {
        "type": "permission",
        "match": "android.permission.RECORD_AUDIO",
        "score": 15,
        "label": "RECORD_AUDIO permission",
        "description": "App can record microphone — spyware behaviour"
    },
    {
        "type": "permission",
        "match": "android.permission.PROCESS_OUTGOING_CALLS",
        "score": 15,
        "label": "PROCESS_OUTGOING_CALLS permission",
        "description": "App can intercept and redirect phone calls"
    },

    # --- Suspicious receivers ---
    {
        "type": "receiver",
        "match": re.compile(r'(?i)sms', re.IGNORECASE),
        "score": 25,
        "label": "SMS-related broadcast receiver",
        "description": "App has a component specifically listening for SMS events"
    },
    {
        "type": "receiver",
        "match": re.compile(r'(?i)boot', re.IGNORECASE),
        "score": 15,
        "label": "BOOT receiver",
        "description": "App auto-starts silently when the phone is turned on"
    },

    # --- Hardcoded string IoCs ---
    {
        "type": "string_telegram",
        "score": 40,
        "label": "Telegram bot token / t.me link",
        "description": "C2 communication via Telegram — most common in MY financial scams"
    },
    {
        "type": "string_ip",
        "score": 20,
        "label": "Hardcoded IP address",
        "description": "Direct C2 server IP — bypasses domain-based detection"
    },
    {
        "type": "string_keyword",
        "score": 10,
        "label": "Malaysian banking keyword",
        "description": "App references local bank names or TAC/OTP terms"
    },
]

# ─── Risk Level ─────────────────────────────────────────────────────────────────

def get_risk_level(score):
    if score == 0:
        return "CLEAN", "No suspicious indicators found."
    elif score < 30:
        return "LOW", "Minor suspicious indicators. Likely benign but worth noting."
    elif score < 60:
        return "MEDIUM", "Multiple suspicious indicators. Manual review recommended."
    elif score < 90:
        return "HIGH", "Strong indicators of malicious behaviour. Likely malware."
    else:
        return "CRITICAL", "Confirmed malware pattern. Matches Malaysian financial scam profile."

# ─── Scanner ────────────────────────────────────────────────────────────────────

def run_scoring(apk_path):
    print(f"\n[*] Analysing: {apk_path}\n")
    apk, dex, analysis = AnalyzeAPK(apk_path)

    total_score = 0
    findings = []

    permissions = apk.get_permissions()
    receivers   = apk.get_receivers()

    # Collect all strings from the APK
    all_strings = [s.get_value() for s in analysis.get_strings()]

    urls      = set()
    ips       = set()
    telegrams = set()
    keywords  = set()

    for s in all_strings:
        urls.update(URL_PATTERN.findall(s))
        ips.update(IP_PATTERN.findall(s))
        ips.update(IP_PATTERN.findall(s))
        ips -= EXCLUDED_IPS
        telegrams.update(TELEGRAM_PATTERN.findall(s))
        keywords.update(KEYWORD_PATTERN.findall(s))

    # Evaluate each rule
    for rule in RULES:

        if rule["type"] == "permission":
            if rule["match"] in permissions:
                total_score += rule["score"]
                findings.append((rule["score"], rule["label"], rule["description"]))

        elif rule["type"] == "receiver":
            for r in receivers:
                if rule["match"].search(r):
                    total_score += rule["score"]
                    findings.append((rule["score"], rule["label"], f'{rule["description"]} ({r})'))
                    break

        elif rule["type"] == "string_telegram" and telegrams:
            total_score += rule["score"] * len(telegrams)
            for t in telegrams:
                findings.append((rule["score"], rule["label"], f'Found: {t}'))

        elif rule["type"] == "string_ip" and ips:
            total_score += rule["score"] * len(ips)
            for ip in ips:
                findings.append((rule["score"], rule["label"], f'Found: {ip}'))

        elif rule["type"] == "string_keyword" and keywords:
            total_score += rule["score"]
            findings.append((rule["score"], rule["label"], f'Keywords: {", ".join(set(k.upper() for k in keywords))}'))

    # ─── Print Report ────────────────────────────────────────────────────────────

    print("=" * 55)
    print("  APK TRIAGE REPORT")
    print("=" * 55)
    print(f"  Package  : {apk.get_package()}")
    print(f"  Version  : {apk.get_androidversion_name()}")
    print()

    if findings:
        print("  FINDINGS:")
        print("  " + "-" * 53)
        for score, label, desc in sorted(findings, reverse=True):
            print(f"  [+{score:>3}]  {label}")
            print(f"         {desc}")
            print()
    else:
        print("  No suspicious findings detected.\n")

    risk_level, risk_summary = get_risk_level(total_score)

    print("=" * 55)
    print(f"  TOTAL SCORE : {total_score}")
    print(f"  RISK LEVEL  : {risk_level}")
    print(f"  SUMMARY     : {risk_summary}")
    print("=" * 55)
    print()

# ─── Main ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 scorer.py <file.apk>")
        sys.exit(1)

    run_scoring(sys.argv[1])
