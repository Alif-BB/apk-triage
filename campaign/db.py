"""
campaign/db.py
Dynamic SQLite & Supabase PostgreSQL connection helpers for Campaign Clustering.

This module automatically connects to a Supabase PostgreSQL instance if the
SUPABASE_DB_URL secret or environment variable is set. Otherwise, it transparently
falls back to local SQLite, providing seamless offline developer testing.
"""
import os
import sqlite3
import streamlit as st

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "campaign.db")


# ─── SQLite-to-PostgreSQL Compatibility Wrappers ───────────────────────────────

class PostgresCursorWrapper:
    """
    Wraps a psycopg2 cursor to mimic the sqlite3 Cursor API.
    Handles '?' -> '%s' placeholder translation and INSERT OR IGNORE translation.
    """
    def __init__(self, cur, conn_wrapper):
        self._cur = cur
        self._conn = conn_wrapper

    def execute(self, sql, params=None):
        # 1. Translate '?' placeholders to '%s'
        sql_pg = sql.replace('?', '%s')
        
        # 2. Translate SQLite-specific 'INSERT OR IGNORE' to Postgres-native 'ON CONFLICT DO NOTHING'
        if "INSERT OR IGNORE" in sql_pg:
            sql_pg = sql_pg.replace("INSERT OR IGNORE INTO", "INSERT INTO")
            if "ON CONFLICT DO NOTHING" not in sql_pg:
                sql_pg += " ON CONFLICT DO NOTHING"

        # 3. Execute query
        if params is not None:
            self._cur.execute(sql_pg, params)
        else:
            self._cur.execute(sql_pg)
        return self

    @property
    def lastrowid(self):
        """
        Retrieves the last auto-generated sequence/identity ID in the current session.
        This provides a drop-in replacement for SQLite's cursor.lastrowid.
        """
        temp_cur = self._conn._conn.cursor()
        temp_cur.execute("SELECT LASTVAL()")
        val = temp_cur.fetchone()[0]
        temp_cur.close()
        return val

    def fetchone(self):
        return self._cur.fetchone()

    def fetchall(self):
        return self._cur.fetchall()

    def close(self):
        self._cur.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class PostgresConnectionWrapper:
    """
    Wraps a psycopg2 connection to mimic the sqlite3 Connection API.
    """
    def __init__(self, conn):
        self._conn = conn

    def cursor(self):
        import psycopg2.extras
        # Use DictCursor so columns can be accessed by both integer index and string key
        cur = self._conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        return PostgresCursorWrapper(cur, self)

    def execute(self, sql, params=None):
        cur = self.cursor()
        cur.execute(sql, params)
        return cur

    def executescript(self, sql_script):
        """
        Executes a series of semicolon-separated SQL commands.
        PostgreSQL's cursor.execute() natively supports multi-statement strings.
        """
        cur = self._conn.cursor()
        cur.execute(sql_script)
        cur.close()

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


# ─── Connection Resolution ─────────────────────────────────────────────────────

def sanitize_db_url(url: str) -> str:
    """
    Automatically URL-encodes special characters (such as '#', '@', ':') in the
    password or username part of a database URL. This prevents driver parsing errors
    when passwords contain special characters.
    """
    if not url or "://" not in url:
        return url
    
    scheme, rest = url.split("://", 1)
    if "@" not in rest:
        return url
        
    # Split on the last '@' to isolate credentials from hostname/port/path
    creds, host_part = rest.rsplit("@", 1)
    
    if ":" in creds:
        from urllib.parse import quote, unquote
        user, password = creds.split(":", 1)
        # Decode first (in case it is partially encoded) then safely encode standard characters
        user_enc = quote(unquote(user), safe='')
        password_enc = quote(unquote(password), safe='')
        return f"{scheme}://{user_enc}:{password_enc}@{host_part}"
        
    return url


def get_connection_url() -> str | None:
    """
    Checks Streamlit secrets first, then falls back to environment variables.
    Returns the Supabase PostgreSQL connection URL if found, else None.
    """
    try:
        # Check Streamlit secrets (local secrets.toml or cloud dashboard secrets)
        if "SUPABASE_DB_URL" in st.secrets:
            return st.secrets["SUPABASE_DB_URL"]
    except Exception:
        pass
    
    # Fallback to local environment variables
    return os.environ.get("SUPABASE_DB_URL")


def get_connection():
    """
    Resolves and returns a database connection.
    Connects to Supabase PostgreSQL if configured, otherwise falls back to SQLite.
    """
    db_url = get_connection_url()
    
    if db_url:
        import psycopg2
        # Sanitize connection URL to safely encode any special characters in passwords
        db_url = sanitize_db_url(db_url)
        # heroku/supabase sometimes expose 'postgres://' which psycopg2 requires as 'postgresql://'
        if db_url.startswith("postgres://"):
            db_url = db_url.replace("postgres://", "postgresql://", 1)
        conn = psycopg2.connect(db_url)
        return PostgresConnectionWrapper(conn)
    else:
        # Local SQLite Fallback
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")   # Concurrent safe for Streamlit
        conn.execute("PRAGMA foreign_keys=ON")
        return conn


# ─── Database Initialization ───────────────────────────────────────────────────

def init_db():
    """
    Creates all tables and indexes if they don't exist yet.
    Automatically handles engine-specific DDL (e.g. SERIAL vs AUTOINCREMENT).
    """
    db_url = get_connection_url()
    conn = get_connection()
    
    if db_url:
        # PostgreSQL DDL
        conn.executescript("""
            -- ── APK scan results ──────────────────────────────────────────────────────
            CREATE TABLE IF NOT EXISTS apk_scans (
                id            SERIAL PRIMARY KEY,
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
                keywords      TEXT,   -- JSON array (stored as JSON text for compatibility)
                permissions   TEXT    -- JSON array (stored as JSON text for compatibility)
            );

            -- ── Normalised C2 indicators ───────────────────────────────────────────────
            CREATE TABLE IF NOT EXISTS c2_indicators (
                id         SERIAL PRIMARY KEY,
                scan_id    INTEGER NOT NULL REFERENCES apk_scans(id) ON DELETE CASCADE,
                ioc_type   TEXT    NOT NULL,   -- 'telegram', 'ip', 'url'
                ioc_value  TEXT    NOT NULL,
                UNIQUE(scan_id, ioc_type, ioc_value)
            );

            -- ── Campaign groups ────────────────────────────────────────────────────────
            CREATE TABLE IF NOT EXISTS campaigns (
                id              SERIAL PRIMARY KEY,
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
    else:
        # SQLite DDL
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