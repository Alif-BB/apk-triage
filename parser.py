from loguru import logger
logger.disable("androguard")

from androguard.misc import AnalyzeAPK
import sys
import re

# ─── Load the APK ───────────────────────────────────────────────────────────────

def load_apk(filepath):
    print(f"\n[*] Loading APK: {filepath}\n")
    apk, dex, analysis = AnalyzeAPK(filepath)
    return apk, dex, analysis

# ─── Basic App Info ─────────────────────────────────────────────────────────────

def get_basic_info(apk):
    print("=" * 50)
    print("  BASIC APP INFO")
    print("=" * 50)
    print(f"  Package name : {apk.get_package()}")
    print(f"  Version name : {apk.get_androidversion_name()}")
    print(f"  Version code : {apk.get_androidversion_code()}")
    print(f"  Min SDK      : {apk.get_min_sdk_version()}")
    print(f"  Target SDK   : {apk.get_target_sdk_version()}")
    print()

# ─── Permissions ────────────────────────────────────────────────────────────────

# These are the permissions most associated with Malaysian financial scams
DANGEROUS_PERMISSIONS = [
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
]

def get_permissions(apk):
    print("=" * 50)
    print("  PERMISSIONS")
    print("=" * 50)
    permissions = apk.get_permissions()
    for perm in permissions:
        if perm in DANGEROUS_PERMISSIONS:
            print(f"  [!!!] HIGH RISK --> {perm}")
        else:
            print(f"  [ ] {perm}")
    print()

# ─── Components ─────────────────────────────────────────────────────────────────

def get_components(apk):
    print("=" * 50)
    print("  APP COMPONENTS")
    print("=" * 50)

    print("  Activities:")
    for activity in apk.get_activities():
        print(f"    - {activity}")

    print("\n  Services:")
    for service in apk.get_services():
        print(f"    - {service}")

    print("\n  Receivers:")
    for receiver in apk.get_receivers():
        print(f"    - {receiver}")
    print()

# ─── Hardcoded Strings (IoCs) ───────────────────────────────────────────────────

# Patterns to hunt for inside the APK's code
URL_PATTERN      = re.compile(r'https?://[^\s\'"<>]{4,}')
IP_PATTERN       = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
TELEGRAM_PATTERN = re.compile(r'(?:bot\d{8,12}:[A-Za-z0-9_-]{35,}|t\.me/[^\s\'"]{3,})')
KEYWORD_PATTERN  = re.compile(r'(?i)(maybank|cimb|rhb|pbebank|hongleong|bankislam|TAC|OTP|transaction)')

def get_hardcoded_strings(analysis):
    print("=" * 50)
    print("  HARDCODED STRINGS (IoCs)")
    print("=" * 50)

    urls, ips, telegrams, keywords = set(), set(), set(), set()

    for string_analysis in analysis.get_strings():
        s = string_analysis.get_value()
        urls.update(URL_PATTERN.findall(s))
        ips.update(IP_PATTERN.findall(s))
        telegrams.update(TELEGRAM_PATTERN.findall(s))
        keywords.update(KEYWORD_PATTERN.findall(s))

    print("  URLs found:")
    for u in urls:
        print(f"    [URL] {u}")

    print("\n  IP addresses found:")
    for ip in ips:
        print(f"    [IP] {ip}")

    print("\n  Telegram references found:")
    for t in telegrams:
        print(f"    [!!!] TELEGRAM --> {t}")

    print("\n  Banking keywords found:")
    for k in keywords:
        print(f"    [!!!] KEYWORD --> {k}")
    print()

# ─── Main ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 parser.py <file.apk>")
        sys.exit(1)

    apk_path = sys.argv[1]
    apk, dex, analysis = load_apk(apk_path)

    get_basic_info(apk)
    get_permissions(apk)
    get_components(apk)
    get_hardcoded_strings(analysis)
