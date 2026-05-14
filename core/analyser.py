from loguru import logger
logger.disable("androguard")

from androguard.misc import AnalyzeAPK
import hashlib
import re

# ─── Patterns ────────────────────────────────────────────────────────────────────

URL_PATTERN      = re.compile(r'https?://[^\s\'"<>]{4,}')
IP_PATTERN       = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
TELEGRAM_PATTERN = re.compile(r'(?:bot\d{8,12}:[A-Za-z0-9_-]{35,}|t\.me/[^\s\'"]{3,})')
KEYWORD_PATTERN  = re.compile(r'(?i)(maybank|cimb|rhb|pbebank|hongleong|bankislam|TAC|OTP|transaction)')
EXCLUDED_IPS     = {"127.0.0.1", "0.0.0.0", "255.255.255.255"}

# ─── Dangerous Permissions ────────────────────────────────────────────────────────

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


def get_file_hashes(filepath):
    md5    = hashlib.md5()
    sha1   = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()


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