"""
campaign/db.py
SQLite initialisation for Campaign Clustering (Feature 2).
Schema and connection helpers will be implemented here.
"""
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "campaign.db")


def get_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Creates tables if they don't exist. Call once at app startup."""
    conn = get_connection()
    # Tables will be added in Feature 2
    conn.close()