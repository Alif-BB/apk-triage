"""
campaign/db.py
SQLite schema and connection helpers for Campaign Clustering (Feature 2).

Tables:
  apk_scans      — one row per analysed APK (hashes, score, analyst, timestamp)
  c2_indicators  — normalised C2 IoCs extracted from each APK (IPs, Telegram tokens)
  campaigns      — named campaign groups; APKs are linked via shared c2_indicators
"""
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "campaign.db")


def get_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # safe for concurrent Streamlit reruns
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """
    Creates all tables if they don't exist.
    Safe to call on every app startup — uses IF NOT EXISTS.
    """
    conn = get_connection()
    conn.executescript("""
        -- ── APK scan results ──────────────────────────────────────────────────────
        CREATE TABLE IF NOT EXISTS apk_scans (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            package       TEXT    NOT NULL,
            version       TEXT,
            sha256        TEXT    NOT NULL UNIQUE,
            md5           TEXT,
            sha1          TEXT,
            risk_score    INTEGER NOT NULL DEFAULT 0,
            risk_level    TEXT    NOT NULL DEFAULT 'UNKNOWN',
            min_sdk       TEXT,
            target_sdk    TEXT,
            analyst_name  TEXT,
            analyst_org   TEXT,
            case_number   TEXT,
            gti_malicious INTEGER DEFAULT 0,
            gti_total     INTEGER DEFAULT 0,
            gti_threat    TEXT,
            ai_verdict    TEXT,
            scanned_at    TEXT    NOT NULL,
            keywords      TEXT,   -- JSON array
            permissions   TEXT    -- JSON array (dangerous only)
        );

        -- ── Normalised C2 indicators ───────────────────────────────────────────────
        CREATE TABLE IF NOT EXISTS c2_indicators (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id    INTEGER NOT NULL REFERENCES apk_scans(id) ON DELETE CASCADE,
            ioc_type   TEXT    NOT NULL,   -- 'telegram', 'ip', 'url'
            ioc_value  TEXT    NOT NULL,
            UNIQUE(scan_id, ioc_type, ioc_value)
        );

        -- ── Campaign groups ────────────────────────────────────────────────────────
        CREATE TABLE IF NOT EXISTS campaigns (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            name            TEXT    NOT NULL,   -- auto-generated or analyst-named
            pivot_type      TEXT    NOT NULL,   -- 'telegram' | 'ip' | 'url'
            pivot_value     TEXT    NOT NULL,   -- the shared C2 value that defines this campaign
            first_seen      TEXT    NOT NULL,
            last_seen       TEXT    NOT NULL,
            apk_count       INTEGER NOT NULL DEFAULT 1,
            UNIQUE(pivot_type, pivot_value)
        );

        -- ── Indexes for fast lookups ───────────────────────────────────────────────
        CREATE INDEX IF NOT EXISTS idx_c2_value   ON c2_indicators(ioc_value);
        CREATE INDEX IF NOT EXISTS idx_c2_type    ON c2_indicators(ioc_type);
        CREATE INDEX IF NOT EXISTS idx_scan_score ON apk_scans(risk_score DESC);
        CREATE INDEX IF NOT EXISTS idx_scan_sha   ON apk_scans(sha256);
    """)
    conn.commit()
    conn.close()