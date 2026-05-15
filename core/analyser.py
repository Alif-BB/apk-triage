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

# ─── IP Exclusion List ────────────────────────────────────────────────────────────
# Covers: loopback, unspecified, broadcast, private RFC1918 ranges,
# link-local, multicast, Android emulator, documentation ranges (RFC5737),
# and common Android SDK test addresses.

EXCLUDED_IPS = {
    # Loopback / unspecified / broadcast
    "0.0.0.0",
    "127.0.0.1",
    "255.255.255.255",

    # Android emulator special addresses
    "10.0.2.2",       # host loopback from emulator
    "10.0.2.15",      # emulator ethernet
    "10.0.3.2",       # Genymotion host loopback

    # Common placeholder / example IPs (RFC 5737 documentation ranges)
    "192.0.2.1", "192.0.2.2", "192.0.2.255",
    "198.51.100.1", "198.51.100.255",
    "203.0.113.1",  "203.0.113.255",

    # Common hardcoded Google / Android SDK addresses
    "8.8.8.8",        # Google Public DNS (often in SDK code)
    "8.8.4.4",        # Google Public DNS secondary
    "1.1.1.1",        # Cloudflare (appears in network libs)
    "1.0.0.1",        # Cloudflare secondary

    # Versioning strings that look like IPs but aren't
    "1.0.0.0",
    "0.0.0.1",
}

# Private RFC1918 ranges — checked programmatically (too many to enumerate)
def _is_private_or_excluded_ip(ip: str) -> bool:
    """
    Returns True if the IP should be excluded from IoC extraction.
    Covers:
      - Exact matches in EXCLUDED_IPS
      - Private RFC1918 ranges: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
      - Link-local: 169.254.x.x
      - Multicast:  224.x.x.x – 239.x.x.x
      - Loopback:   127.x.x.x
    """
    if ip in EXCLUDED_IPS:
        return True
    try:
        parts = list(map(int, ip.split(".")))
        if len(parts) != 4:
            return True
        if not all(0 <= p <= 255 for p in parts):
            return True
        a, b, c, d = parts
        if a == 10:                          return True   # 10.0.0.0/8
        if a == 172 and 16 <= b <= 31:       return True   # 172.16.0.0/12
        if a == 192 and b == 168:            return True   # 192.168.0.0/16
        if a == 169 and b == 254:            return True   # 169.254.0.0/16 link-local
        if 224 <= a <= 239:                  return True   # multicast
        if a == 127:                         return True   # full loopback range
        if a == 0:                           return True   # 0.x.x.x unspecified
        if a == 255:                         return True   # broadcast range
    except (ValueError, AttributeError):
        return True   # malformed — exclude
    return False


# ─── URL Exclusion List ───────────────────────────────────────────────────────────
# These are XML namespace URIs and SDK reference strings present in virtually
# every Android APK — they are NOT network endpoints and must not be treated as IoCs.

EXCLUDED_URL_PREFIXES = (
    # Android / Google namespaces
    "http://schemas.android.com/",
    "https://schemas.android.com/",
    "http://schemas.google.com/",

    # W3C / XML standards
    "http://www.w3.org/",
    "https://www.w3.org/",
    "http://xmlns.jcp.org/",
    "http://xml.org/",

    # Java / JVM namespaces
    "http://java.sun.com/",
    "https://java.sun.com/",
    "http://www.oracle.com/",

    # Office Open XML / Adobe namespaces (appear in document-handling libs)
    "http://schemas.openxmlformats.org/",
    "http://ns.adobe.com/",
    "http://purl.org/",

    # Apache / Maven build artifacts (appear in bundled JARs)
    "http://maven.apache.org/",
    "http://ant.apache.org/",

    # Common SDK documentation URLs (not live endpoints)
    "http://www.apache.org/licenses/",
    "https://www.apache.org/licenses/",
    "http://www.gnu.org/licenses/",
    "https://www.gnu.org/licenses/",
    "http://opensource.org/licenses/",
    "https://opensource.org/licenses/",

    # Google developer docs / policies (present in Play-compliant apps)
    "http://www.google.com/policies/",
    "https://www.google.com/policies/",
    "http://www.google.com/intl/",
    "https://policies.google.com/",
    "https://support.google.com/",
    "https://developer.android.com/",
    "http://developer.android.com/",
    "https://firebase.google.com/",
    "https://play.google.com/",
    "https://www.googleapis.com/",
    "https://accounts.google.com/",

    # Common third-party SDKs included in most legitimate apps
    "https://www.facebook.com/",
    "https://graph.facebook.com/",
    "https://api.twitter.com/",
    "https://crashlytics.com/",
    "https://sentry.io/",
)


def _is_noise_url(url: str) -> bool:
    """Returns True if the URL is a known namespace/SDK reference, not a C2 endpoint."""
    return url.startswith(EXCLUDED_URL_PREFIXES)


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


# ─── Risk Level ───────────────────────────────────────────────────────────────────

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


# ─── File Hashing ─────────────────────────────────────────────────────────────────

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


# ─── Core APK Analysis ────────────────────────────────────────────────────────────

def analyse_apk(filepath):
    md5, sha1, sha256 = get_file_hashes(filepath)
    apk, dex, analysis = AnalyzeAPK(filepath)

    all_strings = [s.get_value() for s in analysis.get_strings()]
    urls, ips, telegrams, keywords = set(), set(), set(), set()

    for s in all_strings:
        # URLs — skip known Android/SDK namespace noise
        for match in URL_PATTERN.findall(s):
            if not _is_noise_url(match):
                urls.add(match)

        # IPs — skip private, loopback, multicast, and placeholder ranges
        for match in IP_PATTERN.findall(s):
            if not _is_private_or_excluded_ip(match):
                ips.add(match)

        telegrams.update(TELEGRAM_PATTERN.findall(s))
        keywords.update(KEYWORD_PATTERN.findall(s))

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