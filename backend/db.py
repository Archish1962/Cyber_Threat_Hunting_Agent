"""
Centralised database helpers for the Cyber Threat Hunting Agent backend.

* DB_PATH  – single source of truth for the SQLite file location
* init_db  – execute schema.sql to create / reset tables and indices
* get_connection – return an open sqlite3.Connection
"""

import os
import sqlite3

# Resolve paths relative to the project root (one level up from backend/)
_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(_BASE_DIR, "data", "logs.sqlite")
SCHEMA_PATH = os.path.join(_BASE_DIR, "data", "schema.sql")


def get_connection() -> sqlite3.Connection:
    """Return an open connection to the shared SQLite database."""
    return sqlite3.connect(DB_PATH)


def init_db() -> None:
    """Read data/schema.sql and execute it to create tables + indices.

    Safe to call on every startup – the schema uses
    CREATE TABLE IF NOT EXISTS / DROP TABLE IF EXISTS.
    """
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        schema_sql = f.read()

    conn = get_connection()
    try:
        conn.executescript(schema_sql)
        conn.commit()
        print(f"[db] Schema initialised -> {DB_PATH}")
    finally:
        conn.close()
