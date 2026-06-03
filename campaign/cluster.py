"""
campaign/cluster.py
Query helpers that power the Campaign Clustering UI (Feature 2).

Functions:
  get_all_campaigns()        — all campaign rows, sorted by APK count desc
  get_campaign_members()     — all APKs linked to a specific campaign pivot
  get_apk_timeline()         — all scans ordered by date for timeline view
  get_scan_details()         — full scan record + C2 indicators for detail panel
  save_ai_verdict()          — persist a generated AI verdict back to the DB
  get_stats()                — summary counts for the dashboard header
  get_network_graph_data()   — nodes + edges for the visual network graph
  rename_campaign()          — analyst can override the auto-generated name
  delete_scan()              — remove a scan and cascade-delete its indicators
"""
from campaign.db import get_connection


# ─── Summary stats ────────────────────────────────────────────────────────────────

def get_stats() -> dict:
    conn = get_connection()
    total_apks      = conn.execute("SELECT COUNT(*) FROM apk_scans").fetchone()[0]
    total_campaigns = conn.execute("SELECT COUNT(*) FROM campaigns").fetchone()[0]
    critical_apks   = conn.execute(
        "SELECT COUNT(*) FROM apk_scans WHERE risk_level = 'CRITICAL'"
    ).fetchone()[0]
    telegram_c2     = conn.execute(
        "SELECT COUNT(DISTINCT ioc_value) FROM c2_indicators WHERE ioc_type = 'telegram'"
    ).fetchone()[0]
    ip_c2           = conn.execute(
        "SELECT COUNT(DISTINCT ioc_value) FROM c2_indicators WHERE ioc_type = 'ip'"
    ).fetchone()[0]
    conn.close()
    return {
        "total_apks":      total_apks,
        "total_campaigns": total_campaigns,
        "critical_apks":   critical_apks,
        "telegram_c2":     telegram_c2,
        "ip_c2":           ip_c2,
    }


# ─── Campaign list ────────────────────────────────────────────────────────────────

def get_all_campaigns(filter_type: str = "all") -> list[dict]:
    conn = get_connection()
    if filter_type == "all":
        rows = conn.execute(
            "SELECT * FROM campaigns ORDER BY apk_count DESC, last_seen DESC"
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM campaigns WHERE pivot_type = ? ORDER BY apk_count DESC, last_seen DESC",
            (filter_type,)
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ─── Campaign members ─────────────────────────────────────────────────────────────

def get_campaign_members(pivot_type: str, pivot_value: str) -> list[dict]:
    conn = get_connection()
    rows = conn.execute("""
        SELECT s.*
        FROM apk_scans s
        JOIN c2_indicators c ON c.scan_id = s.id
        WHERE c.ioc_type = ? AND c.ioc_value = ?
        ORDER BY s.risk_score DESC, s.scanned_at DESC
    """, (pivot_type, pivot_value)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ─── APK timeline ─────────────────────────────────────────────────────────────────

def get_apk_timeline() -> list[dict]:
    conn = get_connection()
    rows = conn.execute("""
        SELECT id, package, risk_score, risk_level, scanned_at,
               analyst_name, gti_malicious, gti_total, gti_threat
        FROM apk_scans
        ORDER BY scanned_at DESC
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ─── Full scan details ────────────────────────────────────────────────────────────

def get_scan_details(scan_id: int) -> dict | None:
    """
    Returns the full scan record for a given scan ID, plus all its C2 indicators.
    Returns None if scan_id does not exist.
    """
    conn = get_connection()
    row = conn.execute("SELECT * FROM apk_scans WHERE id = ?", (scan_id,)).fetchone()
    if row is None:
        conn.close()
        return None
    scan = dict(row)
    indicators = conn.execute(
        "SELECT ioc_type, ioc_value FROM c2_indicators WHERE scan_id = ? ORDER BY ioc_type",
        (scan_id,)
    ).fetchall()
    conn.close()
    scan["indicators"] = [dict(i) for i in indicators]
    return scan


# ─── Persist AI verdict ───────────────────────────────────────────────────────────

def save_ai_verdict(scan_id: int, verdict: str) -> None:
    """
    Writes a newly generated AI verdict back to the apk_scans row.
    Called from the Campaigns page after on-demand Gemini generation.
    """
    conn = get_connection()
    conn.execute(
        "UPDATE apk_scans SET ai_verdict = ? WHERE id = ?",
        (verdict, scan_id)
    )
    conn.commit()
    conn.close()


# ─── Network graph data ───────────────────────────────────────────────────────────

def get_network_graph_data() -> dict:
    conn = get_connection()
    apk_rows  = conn.execute("""
        SELECT id, package, sha256, risk_score, risk_level, scanned_at, analyst_name
        FROM apk_scans
    """).fetchall()
    edge_rows = conn.execute("""
        SELECT s.id as scan_id, c.ioc_type, c.ioc_value
        FROM c2_indicators c
        JOIN apk_scans s ON s.id = c.scan_id
    """).fetchall()
    conn.close()

    RISK_COLORS = {
        "CRITICAL": "#e74c3c", "HIGH": "#e67e22", "MEDIUM": "#f39c12",
        "LOW": "#27ae60",      "CLEAN": "#2ecc71", "UNKNOWN": "#95a5a6",
    }
    C2_COLORS = {"telegram": "#2980b9", "ip": "#8e44ad", "url": "#16a085"}

    nodes, edges, seen_c2 = [], [], set()

    for row in apk_rows:
        nodes.append({
            "id":         f"apk_{row['id']}",
            "label":      row["package"].split(".")[-1],
            "full_label": row["package"],
            "type":       "apk",
            "risk_level": row["risk_level"],
            "color":      RISK_COLORS.get(row["risk_level"], "#95a5a6"),
            "size":       25,
            "title": (
                f"<b>{row['package']}</b><br>"
                f"Risk: {row['risk_level']} ({row['risk_score']})<br>"
                f"SHA-256: {row['sha256'][:16]}…<br>"
                f"Scanned: {row['scanned_at'][:10]}<br>"
                f"Analyst: {row['analyst_name'] or 'Unknown'}"
            ),
        })

    for row in edge_rows:
        c2_id = f"c2_{row['ioc_type']}_{row['ioc_value']}"
        if c2_id not in seen_c2:
            seen_c2.add(c2_id)
            short = row["ioc_value"]
            if row["ioc_type"] == "telegram":
                short = row["ioc_value"].replace("t.me/", "")[:20]
            elif row["ioc_type"] == "url":
                try:
                    from urllib.parse import urlparse
                    short = urlparse(row["ioc_value"]).netloc[:20]
                except Exception:
                    short = row["ioc_value"][:20]
            nodes.append({
                "id":         c2_id,
                "label":      short,
                "full_label": row["ioc_value"],
                "type":       "c2",
                "ioc_type":   row["ioc_type"],
                "color":      C2_COLORS.get(row["ioc_type"], "#7f8c8d"),
                "size":       18,
                "title": (
                    f"<b>C2: {row['ioc_type'].upper()}</b><br>{row['ioc_value']}"
                ),
            })
        edges.append({
            "source":   f"apk_{row['scan_id']}",
            "target":   c2_id,
            "ioc_type": row["ioc_type"],
        })

    return {"nodes": nodes, "edges": edges}


# ─── Analyst actions ──────────────────────────────────────────────────────────────

def rename_campaign(campaign_id: int, new_name: str) -> None:
    conn = get_connection()
    conn.execute("UPDATE campaigns SET name = ? WHERE id = ?", (new_name, campaign_id))
    conn.commit()
    conn.close()


def delete_scan(scan_id: int) -> None:
    conn = get_connection()
    conn.execute("DELETE FROM apk_scans WHERE id = ?", (scan_id,))
    conn.commit()
    campaigns = conn.execute("SELECT id, pivot_type, pivot_value FROM campaigns").fetchall()
    for camp in campaigns:
        count = conn.execute("""
            SELECT COUNT(DISTINCT s.id)
            FROM apk_scans s
            JOIN c2_indicators c ON c.scan_id = s.id
            WHERE c.ioc_type = ? AND c.ioc_value = ?
        """, (camp["pivot_type"], camp["pivot_value"])).fetchone()[0]
        if count == 0:
            conn.execute("DELETE FROM campaigns WHERE id = ?", (camp["id"],))
        else:
            conn.execute("UPDATE campaigns SET apk_count = ? WHERE id = ?",
                         (count, camp["id"]))
    conn.commit()
    conn.close()