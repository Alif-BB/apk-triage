#!/usr/bin/env python3
"""
scripts/migrate_data.py
Database Migration Script for APK Triage.

This script reads from the local SQLite database (data/campaign.db) and migrates all
records to Supabase PostgreSQL, preserving original IDs, linkages, and updating serial sequences.
"""
import os
import sys
import sqlite3
import psycopg2

# Setup workspace paths
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(ROOT_DIR)

DB_PATH = os.path.join(ROOT_DIR, "data", "campaign.db")
SECRETS_PATH = os.path.join(ROOT_DIR, ".streamlit", "secrets.toml")


def get_supabase_url() -> str | None:
    """Gets the Supabase DB connection URL from env vars or secrets.toml."""
    # Check env vars
    url = os.environ.get("SUPABASE_DB_URL")
    if url:
        return url

    # Parse secrets.toml manually to avoid adding extra dependency requirements
    if os.path.exists(SECRETS_PATH):
        try:
            with open(SECRETS_PATH, "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("SUPABASE_DB_URL") and "=" in line:
                        parts = line.split("=", 1)
                        val = parts[1].strip().strip('"').strip("'")
                        return val
        except Exception as e:
            print(f"[-] Error reading secrets.toml: {e}")
    
    return None


def migrate():
    print("[*] Starting database migration to Supabase...")

    # 1. Check SQLite DB presence
    if not os.path.exists(DB_PATH):
        print(f"[-] Local SQLite database not found at '{DB_PATH}'. Nothing to migrate.")
        return 1

    # 2. Get Supabase Connection String
    supabase_url = get_supabase_url()
    if not supabase_url:
        print("[-] Error: 'SUPABASE_DB_URL' not found in environment or .streamlit/secrets.toml.")
        print("    Please configure it first. Example:")
        print("    SUPABASE_DB_URL = \"postgresql://postgres:password@db.ref.supabase.co:5432/postgres\"")
        return 1

    # Safely URL-encode special characters in the password
    from campaign.db import sanitize_db_url
    supabase_url = sanitize_db_url(supabase_url)

    if supabase_url.startswith("postgres://"):
        supabase_url = supabase_url.replace("postgres://", "postgresql://", 1)

    # 3. Connect to Databases
    try:
        print("[*] Connecting to local SQLite database...")
        sqlite_conn = sqlite3.connect(DB_PATH)
        sqlite_conn.row_factory = sqlite3.Row
        sqlite_cur = sqlite_conn.cursor()
    except Exception as e:
        print(f"[-] Failed to connect to SQLite: {e}")
        return 1

    try:
        print("[*] Connecting to Supabase PostgreSQL database...")
        pg_conn = psycopg2.connect(supabase_url)
        pg_cur = pg_conn.cursor()
    except Exception as e:
        print(f"[-] Failed to connect to Supabase: {e}")
        sqlite_conn.close()
        return 1

    try:
        # Initialize tables on Postgres first
        from campaign.db import init_db
        # We temporarily set environmental variable so init_db connects to Postgres
        os.environ["SUPABASE_DB_URL"] = supabase_url
        print("[*] Initializing remote PostgreSQL schema tables if not present...")
        init_db()

        # 4. Migrate Table: apk_scans
        print("[*] Fetching records from 'apk_scans'...")
        sqlite_cur.execute("SELECT * FROM apk_scans")
        scans = sqlite_cur.fetchall()
        print(f"[+] Found {len(scans)} local scans.")

        inserted_scans = 0
        for scan in scans:
            cols = dict(scan)
            try:
                pg_cur.execute("""
                    INSERT INTO apk_scans (
                        id, package, version, sha256, md5, sha1, risk_score, risk_level,
                        min_sdk, target_sdk, analyst_name, analyst_org, case_number,
                        gti_malicious, gti_total, gti_threat, ai_verdict, scanned_at,
                        keywords, permissions
                    ) VALUES (
                        %(id)s, %(package)s, %(version)s, %(sha256)s, %(md5)s, %(sha1)s,
                        %(risk_score)s, %(risk_level)s, %(min_sdk)s, %(target_sdk)s,
                        %(analyst_name)s, %(analyst_org)s, %(case_number)s, %(gti_malicious)s,
                        %(gti_total)s, %(gti_threat)s, %(ai_verdict)s, %(scanned_at)s,
                        %(keywords)s, %(permissions)s
                    ) ON CONFLICT (sha256) DO NOTHING
                """, cols)
                inserted_scans += pg_cur.rowcount
            except Exception as e:
                print(f"[-] Error migrating scan ID {cols['id']} ({cols['package']}): {e}")
                pg_conn.rollback()
                sqlite_conn.close()
                pg_conn.close()
                return 1

        print(f"[+] Successfully migrated {inserted_scans} unique records to 'apk_scans'.")

        # 5. Migrate Table: c2_indicators
        print("[*] Fetching records from 'c2_indicators'...")
        sqlite_cur.execute("SELECT * FROM c2_indicators")
        indicators = sqlite_cur.fetchall()
        print(f"[+] Found {len(indicators)} local C2 indicators.")

        inserted_indicators = 0
        for ioc in indicators:
            cols = dict(ioc)
            try:
                pg_cur.execute("""
                    INSERT INTO c2_indicators (id, scan_id, ioc_type, ioc_value)
                    VALUES (%(id)s, %(scan_id)s, %(ioc_type)s, %(ioc_value)s)
                    ON CONFLICT (scan_id, ioc_type, ioc_value) DO NOTHING
                """, cols)
                inserted_indicators += pg_cur.rowcount
            except Exception as e:
                print(f"[-] Error migrating indicator ID {cols['id']}: {e}")
                pg_conn.rollback()
                sqlite_conn.close()
                pg_conn.close()
                return 1

        print(f"[+] Successfully migrated {inserted_indicators} unique records to 'c2_indicators'.")

        # 6. Migrate Table: campaigns
        print("[*] Fetching records from 'campaigns'...")
        sqlite_cur.execute("SELECT * FROM campaigns")
        campaigns = sqlite_cur.fetchall()
        print(f"[+] Found {len(campaigns)} local campaign clusters.")

        inserted_campaigns = 0
        for camp in campaigns:
            cols = dict(camp)
            try:
                pg_cur.execute("""
                    INSERT INTO campaigns (
                        id, name, pivot_type, pivot_value, first_seen, last_seen, apk_count
                    ) VALUES (
                        %(id)s, %(name)s, %(pivot_type)s, %(pivot_value)s,
                        %(first_seen)s, %(last_seen)s, %(apk_count)s
                    ) ON CONFLICT (pivot_type, pivot_value) DO NOTHING
                """, cols)
                inserted_campaigns += pg_cur.rowcount
            except Exception as e:
                print(f"[-] Error migrating campaign ID {cols['id']}: {e}")
                pg_conn.rollback()
                sqlite_conn.close()
                pg_conn.close()
                return 1

        print(f"[+] Successfully migrated {inserted_campaigns} unique records to 'campaigns'.")

        # 7. Reset PostgreSQL Primary Key Sequences
        # (Needed because we manually inserted explicit ID primary key numbers)
        print("[*] Aligning PostgreSQL key sequences...")
        tables = ["apk_scans", "c2_indicators", "campaigns"]
        for table in tables:
            pg_cur.execute(f"""
                SELECT setval(
                    pg_get_serial_sequence('{table}', 'id'),
                    COALESCE(MAX(id), 1),
                    MAX(id) IS NOT NULL
                ) FROM {table}
            """)
            new_val = pg_cur.fetchone()[0]
            print(f"[+] Key sequence for '{table}' aligned to {new_val}.")

        # Commit everything
        pg_conn.commit()
        print("\n[+] MIGRATION COMPLETED SUCCESSFULLY!")
        print("[+] Your Supabase database is fully synced and ready for cloud deployment.")

    except Exception as e:
        print(f"[-] Critical migration error: {e}")
        pg_conn.rollback()
    finally:
        sqlite_conn.close()
        pg_conn.close()


if __name__ == "__main__":
    sys.exit(migrate())
