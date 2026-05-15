"""
campaign/store.py
Persists APK analysis results and auto-clusters by shared C2 indicators.

Flow on each save:
  1. Upsert apk_scans row (skip if SHA-256 already stored)
  2. Insert c2_indicators rows (telegram tokens and IPs only — URLs excluded as campaign pivots)
  3. For each indicator, check if a campaign already exists for that value
     - Yes → update last_seen + apk_count
     - No  → create new campaign row with auto-generated name
"""
import json
import datetime
from campaign.db import get_connection
from core.analyser import DANGEROUS_PERMISSIONS, get_risk_level


# ─── Campaign name generator ──────────────────────────────────────────────────────

def _make_campaign_name(ioc_type: str, ioc_value: str, apk_count: int = 1) -> str:
    """
    Auto-generates a human-readable campaign name from the pivot indicator.
    Examples:
      telegram  t.me/mybotgroup        → "TG-Campaign: mybotgroup"
      ip        103.44.120.5           → "IP-Campaign: 103.44.120.x"
      url       https://evil.com/gate  → "URL-Campaign: evil.com"
    """
    if ioc_type == "telegram":
        label = ioc_value.replace("t.me/", "").split("?")[0][:30]
        return f"TG-Campaign: {label}"
    elif ioc_type == "ip":
        parts = ioc_value.split(".")
        masked = ".".join(parts[:3]) + ".x"
        return f"IP-Campaign: {masked}"
    elif ioc_type == "url":
        try:
            from urllib.parse import urlparse
            domain = urlparse(ioc_value).netloc or ioc_value[:30]
        except Exception:
            domain = ioc_value[:30]
        return f"URL-Campaign: {domain}"
    return f"Campaign: {ioc_value[:30]}"


# ─── Save APK scan to DB ──────────────────────────────────────────────────────────

def save_scan(result: dict, analyst_name: str = "", analyst_org: str = "",
              case_number: str = "", gti: dict = None, ai_summary: str = None) -> int | None:
    """
    Persists one APK scan result to the database.
    Returns the scan row ID, or None if this SHA-256 was already saved.

    Automatically clusters the APK into campaigns based on shared C2 indicators.
    """
    conn = get_connection()
    now  = datetime.datetime.utcnow().isoformat() + "Z"

    risk_level, _ = get_risk_level(result["score"])

    # ── GTI fields ───────────────────────────────────────────────────────────────
    gti_malicious = 0
    gti_total     = 0
    gti_threat    = None
    if gti and gti.get("file") and not gti["file"].get("not_found"):
        gti_malicious = gti["file"].get("malicious", 0)
        gti_total     = gti["file"].get("total", 0)
        gti_threat    = gti["file"].get("threat_name")

    # ── Dangerous permissions (names only) ────────────────────────────────────────
    danger_perms = [p.split(".")[-1] for p in result.get("permissions", [])
                    if p in DANGEROUS_PERMISSIONS]

    # ── Upsert apk_scans ─────────────────────────────────────────────────────────
    try:
        cur = conn.execute("""
            INSERT INTO apk_scans
                (package, version, sha256, md5, sha1, risk_score, risk_level,
                 min_sdk, target_sdk, analyst_name, analyst_org, case_number,
                 gti_malicious, gti_total, gti_threat, ai_verdict,
                 scanned_at, keywords, permissions)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            result["package"],
            result.get("version", ""),
            result["sha256"],
            result.get("md5", ""),
            result.get("sha1", ""),
            result["score"],
            risk_level,
            result.get("min_sdk", ""),
            result.get("target_sdk", ""),
            analyst_name or "",
            analyst_org  or "",
            case_number  or "",
            gti_malicious,
            gti_total,
            gti_threat or "",
            ai_summary or "",
            now,
            json.dumps(list(result.get("keywords", []))),
            json.dumps(danger_perms),
        ))
        scan_id = cur.lastrowid
        conn.commit()
    except Exception:
        # SHA-256 UNIQUE constraint — already saved, skip silently
        conn.close()
        return None

    # ── Insert c2_indicators ─────────────────────────────────────────────────────
    indicators = []
    for token in result.get("telegrams", []):
        indicators.append(("telegram", token))
    for ip in result.get("ips", []):
        indicators.append(("ip", ip))

    for ioc_type, ioc_value in indicators:
        try:
            conn.execute("""
                INSERT OR IGNORE INTO c2_indicators (scan_id, ioc_type, ioc_value)
                VALUES (?, ?, ?)
            """, (scan_id, ioc_type, ioc_value))
        except Exception:
            pass

    conn.commit()

    # ── Auto-cluster into campaigns ───────────────────────────────────────────────
    for ioc_type, ioc_value in indicators:
        existing = conn.execute("""
            SELECT id, apk_count FROM campaigns
            WHERE pivot_type = ? AND pivot_value = ?
        """, (ioc_type, ioc_value)).fetchone()

        if existing:
            conn.execute("""
                UPDATE campaigns
                SET last_seen = ?, apk_count = apk_count + 1
                WHERE id = ?
            """, (now, existing["id"]))
        else:
            name = _make_campaign_name(ioc_type, ioc_value)
            conn.execute("""
                INSERT INTO campaigns
                    (name, pivot_type, pivot_value, first_seen, last_seen, apk_count)
                VALUES (?, ?, ?, ?, ?, 1)
            """, (name, ioc_type, ioc_value, now, now))

    conn.commit()
    conn.close()
    return scan_id