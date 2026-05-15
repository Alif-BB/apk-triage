"""
campaign/cluster.py
Query helpers that power the Campaign Clustering UI (Feature 2).

Functions:
  get_all_campaigns()        — all campaign rows, sorted by APK count desc
  get_campaign_members()     — all APKs linked to a specific campaign pivot
  get_apk_timeline()         — all scans ordered by date for timeline view
  get_stats()                — summary counts for the dashboard header
  get_network_graph_data()   — nodes + edges for the visual network graph
  rename_campaign()          — analyst can override the auto-generated name
  delete_scan()              — remove a scan and cascade-delete its indicators
"""
from campaign.db import get_connection


# ─── Summary stats ────────────────────────────────────────────────────────────────

def get_stats() -> dict:
    """Returns high-level counts for the campaign dashboard header."""
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
    """
    Returns all campaigns as a list of dicts, ordered by apk_count desc.
    filter_type: 'all' | 'telegram' | 'ip' | 'url'
    """
    conn = get_connection()
    if filter_type == "all":
        rows = conn.execute("""
            SELECT * FROM campaigns ORDER BY apk_count DESC, last_seen DESC
        """).fetchall()
    else:
        rows = conn.execute("""
            SELECT * FROM campaigns
            WHERE pivot_type = ?
            ORDER BY apk_count DESC, last_seen DESC
        """, (filter_type,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ─── Campaign members ─────────────────────────────────────────────────────────────

def get_campaign_members(pivot_type: str, pivot_value: str) -> list[dict]:
    """
    Returns all APK scans that share a specific C2 indicator.
    Used to drill into a campaign and see all linked APKs.
    """
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
    """Returns all scans ordered by scan date, newest first."""
    conn = get_connection()
    rows = conn.execute("""
        SELECT id, package, risk_score, risk_level, scanned_at,
               analyst_name, gti_malicious, gti_total, gti_threat
        FROM apk_scans
        ORDER BY scanned_at DESC
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ─── Network graph data ───────────────────────────────────────────────────────────

def get_network_graph_data() -> dict:
    """
    Builds nodes + edges for the pyvis/networkx visual graph.

    Node types:
      - APK node   : labelled by package name, coloured by risk level
      - C2 node    : labelled by IoC value, shaped differently per type

    Edges connect each APK node to its C2 nodes.

    Returns:
      {
        "nodes": [ {id, label, type, risk_level, color, size, title} ],
        "edges": [ {source, target, ioc_type} ]
      }
    """
    conn = get_connection()

    apk_rows = conn.execute("""
        SELECT id, package, sha256, risk_score, risk_level, scanned_at, analyst_name
        FROM apk_scans
    """).fetchall()

    c2_rows = conn.execute("""
        SELECT DISTINCT ioc_type, ioc_value FROM c2_indicators
    """).fetchall()

    edge_rows = conn.execute("""
        SELECT s.id as scan_id, c.ioc_type, c.ioc_value
        FROM c2_indicators c
        JOIN apk_scans s ON s.id = c.scan_id
    """).fetchall()

    conn.close()

    RISK_COLORS = {
        "CRITICAL": "#e74c3c",
        "HIGH":     "#e67e22",
        "MEDIUM":   "#f39c12",
        "LOW":      "#27ae60",
        "CLEAN":    "#2ecc71",
        "UNKNOWN":  "#95a5a6",
    }

    C2_COLORS = {
        "telegram": "#2980b9",
        "ip":       "#8e44ad",
        "url":      "#16a085",
    }

    nodes = []
    edges = []
    seen_c2 = set()

    # APK nodes
    for row in apk_rows:
        nodes.append({
            "id":         f"apk_{row['id']}",
            "label":      row["package"].split(".")[-1],   # short label
            "full_label": row["package"],
            "type":       "apk",
            "risk_level": row["risk_level"],
            "color":      RISK_COLORS.get(row["risk_level"], "#95a5a6"),
            "size":       25,
            "title":      (
                f"<b>{row['package']}</b><br>"
                f"Risk: {row['risk_level']} ({row['risk_score']})<br>"
                f"SHA-256: {row['sha256'][:16]}…<br>"
                f"Scanned: {row['scanned_at'][:10]}<br>"
                f"Analyst: {row['analyst_name'] or 'Unknown'}"
            ),
        })

    # C2 nodes + edges
    for row in edge_rows:
        c2_id = f"c2_{row['ioc_type']}_{row['ioc_value']}"

        if c2_id not in seen_c2:
            seen_c2.add(c2_id)
            short = row["ioc_value"]
            if row["ioc_type"] == "telegram":
                short = row["ioc_value"].replace("t.me/", "")[:20]
            elif row["ioc_type"] == "ip":
                short = row["ioc_value"]
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
                "title":      (
                    f"<b>C2: {row['ioc_type'].upper()}</b><br>"
                    f"{row['ioc_value']}"
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
    """Lets the analyst override the auto-generated campaign name."""
    conn = get_connection()
    conn.execute("UPDATE campaigns SET name = ? WHERE id = ?", (new_name, campaign_id))
    conn.commit()
    conn.close()


def delete_scan(scan_id: int) -> None:
    """Removes a scan and cascades to c2_indicators. Does NOT remove campaigns."""
    conn = get_connection()
    conn.execute("DELETE FROM apk_scans WHERE id = ?", (scan_id,))
    conn.commit()
    # Recount campaigns after deletion
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