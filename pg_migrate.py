#!/usr/bin/env python3
"""
One-time migration script: copies all data from mailer.db (SQLite) into PostgreSQL.

Usage:
    python pg_migrate.py

Environment:
    DATABASE_URL  - PostgreSQL connection string
                    (default: postgresql://postgres:postgres@localhost/mailer)

Prerequisites:
    1. PostgreSQL database must exist (createdb mailer)
    2. psycopg2-binary must be installed (pip install psycopg2-binary)
    3. mailer.db must be present in the same directory
"""

import os
import sys
import sqlite3
import psycopg2
from psycopg2.extras import RealDictCursor

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SQLITE_PATH = os.path.join(BASE_DIR, 'mailer.db')
DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://postgres:postgres@localhost/mailer')

# PostgreSQL schema (matches app.py SCHEMA_STATEMENTS)
SCHEMA_STATEMENTS = [
    """CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    last_active TEXT DEFAULT '',
    totp_secret TEXT DEFAULT ''
)""",
    """CREATE TABLE IF NOT EXISTS credentials (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    encrypted_email TEXT NOT NULL,
    encrypted_app_password TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)""",
    """CREATE TABLE IF NOT EXISTS sent_logs (
    id SERIAL PRIMARY KEY,
    timestamp TEXT NOT NULL,
    username TEXT NOT NULL,
    encrypted_domain TEXT NOT NULL,
    encrypted_email TEXT NOT NULL,
    sender_email TEXT NOT NULL
)""",
    """CREATE TABLE IF NOT EXISTS profiles (
    id SERIAL PRIMARY KEY,
    user_id INTEGER UNIQUE NOT NULL,
    name TEXT DEFAULT '',
    email TEXT DEFAULT '',
    phone TEXT DEFAULT '',
    discord_webhook_url TEXT DEFAULT '',
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)""",
    """CREATE TABLE IF NOT EXISTS inbox_cache (
    id SERIAL PRIMARY KEY,
    credential_id INTEGER NOT NULL,
    message_id TEXT UNIQUE NOT NULL,
    sender TEXT NOT NULL,
    subject TEXT NOT NULL,
    body_preview TEXT NOT NULL,
    full_body TEXT DEFAULT '',
    received_at TEXT NOT NULL,
    is_read INTEGER DEFAULT 0,
    fetched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (credential_id) REFERENCES credentials(id) ON DELETE CASCADE
)""",
    """CREATE TABLE IF NOT EXISTS email_templates (
    id SERIAL PRIMARY KEY,
    user_id INTEGER,
    name TEXT NOT NULL,
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    sender_name TEXT NOT NULL DEFAULT 'Whitehat',
    is_default INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)""",
    """CREATE TABLE IF NOT EXISTS responses (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    inbox_cache_id INTEGER NOT NULL,
    sent_log_id INTEGER NOT NULL,
    credential_id INTEGER NOT NULL,
    matched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (inbox_cache_id) REFERENCES inbox_cache(id) ON DELETE CASCADE,
    FOREIGN KEY (sent_log_id) REFERENCES sent_logs(id) ON DELETE CASCADE
)""",
    """CREATE TABLE IF NOT EXISTS email_opens (
    id SERIAL PRIMARY KEY,
    tracking_token TEXT UNIQUE NOT NULL,
    sent_log_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    recipient_email TEXT NOT NULL,
    opened_at TEXT,
    open_count INTEGER DEFAULT 0,
    user_agent TEXT DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sent_log_id) REFERENCES sent_logs(id) ON DELETE CASCADE
)""",
]

def migrate_table(sqlite_conn, pg_cur, table, columns, conflict_action=None):
    """Copy all rows from a SQLite table into PostgreSQL."""
    sqlite_cur = sqlite_conn.cursor()
    sqlite_cur.execute(f"SELECT {', '.join(columns)} FROM {table}")
    rows = sqlite_cur.fetchall()
    if not rows:
        print(f"  [SKIP] {table}: no rows")
        return 0

    placeholders = ', '.join(['%s'] * len(columns))
    col_list = ', '.join(columns)
    if conflict_action:
        sql = f"INSERT INTO {table} ({col_list}) VALUES ({placeholders}) {conflict_action}"
    else:
        sql = f"INSERT INTO {table} ({col_list}) VALUES ({placeholders})"

    count = 0
    for row in rows:
        try:
            pg_cur.execute(sql, row)
            count += 1
        except Exception as e:
            print(f"  [WARN] {table} row skipped: {e}")
    return count

def reset_sequence(pg_cur, table, id_col='id'):
    """Reset the PostgreSQL SERIAL sequence to continue from the max existing id."""
    pg_cur.execute(f"SELECT MAX({id_col}) FROM {table}")
    result = pg_cur.fetchone()
    max_id = result[0] if result and result[0] is not None else 0
    seq_name = f"{table}_{id_col}_seq"
    pg_cur.execute(f"SELECT setval(%s, %s, true)", (seq_name, max(max_id, 1)))

def main():
    if not os.path.exists(SQLITE_PATH):
        print(f"[ERROR] SQLite database not found: {SQLITE_PATH}")
        sys.exit(1)

    print(f"[INFO] Source: {SQLITE_PATH}")
    print(f"[INFO] Target: {DATABASE_URL}")
    print()

    # Connect to both databases
    sqlite_conn = sqlite3.connect(SQLITE_PATH)
    sqlite_conn.row_factory = sqlite3.Row

    try:
        pg_conn = psycopg2.connect(DATABASE_URL)
    except Exception as e:
        print(f"[ERROR] Cannot connect to PostgreSQL: {e}")
        print(f"  Make sure PostgreSQL is running and DATABASE_URL is correct.")
        print(f"  Create the database with: createdb mailer")
        sys.exit(1)

    pg_cur = pg_conn.cursor()

    # Create schema
    print("[INFO] Creating PostgreSQL schema...")
    for stmt in SCHEMA_STATEMENTS:
        pg_cur.execute(stmt)
    pg_conn.commit()
    print("[OK] Schema ready.")
    print()

    # Migration order matters due to foreign keys
    tables = [
        # (table_name, [columns], conflict_action)
        ('users', ['id', 'username', 'password', 'salt', 'role', 'last_active', 'totp_secret'], 'ON CONFLICT (username) DO NOTHING'),
        ('credentials', ['id', 'user_id', 'encrypted_email', 'encrypted_app_password', 'created_at'], None),
        ('profiles', ['id', 'user_id', 'name', 'email', 'phone', 'discord_webhook_url'], 'ON CONFLICT (user_id) DO NOTHING'),
        ('email_templates', ['id', 'user_id', 'name', 'subject', 'body', 'sender_name', 'is_default', 'created_at'], None),
        ('sent_logs', ['id', 'timestamp', 'username', 'encrypted_domain', 'encrypted_email', 'sender_email'], None),
        ('inbox_cache', ['id', 'credential_id', 'message_id', 'sender', 'subject', 'body_preview', 'full_body', 'received_at', 'is_read', 'fetched_at'], 'ON CONFLICT (message_id) DO NOTHING'),
        ('responses', ['id', 'user_id', 'inbox_cache_id', 'sent_log_id', 'credential_id', 'matched_at'], None),
        ('email_opens', ['id', 'tracking_token', 'sent_log_id', 'username', 'recipient_email', 'opened_at', 'open_count', 'user_agent', 'created_at'], 'ON CONFLICT (tracking_token) DO NOTHING'),
    ]

    # Check which tables exist in SQLite
    sqlite_cur = sqlite_conn.cursor()
    sqlite_cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    existing_sqlite_tables = {row[0] for row in sqlite_cur.fetchall()}

    for table, columns, conflict_action in tables:
        if table not in existing_sqlite_tables:
            print(f"  [SKIP] {table}: not in SQLite (will be created empty)")
            continue

        # Check which columns exist in this SQLite table
        sqlite_cur.execute(f"PRAGMA table_info({table})")
        sqlite_cols = {row[1] for row in sqlite_cur.fetchall()}
        # Only migrate columns that exist in both SQLite and our target list
        available_cols = [c for c in columns if c in sqlite_cols]

        print(f"[INFO] Migrating {table}...")
        count = migrate_table(sqlite_conn, pg_cur, table, available_cols, conflict_action)
        pg_conn.commit()
        print(f"[OK]   {table}: {count} rows copied")

    # Reset sequences so auto-increment continues from correct value
    print()
    print("[INFO] Resetting PostgreSQL sequences...")
    for table, _, _ in tables:
        try:
            reset_sequence(pg_cur, table)
        except Exception as e:
            print(f"  [WARN] Could not reset sequence for {table}: {e}")
    pg_conn.commit()
    print("[OK] Sequences reset.")

    sqlite_conn.close()
    pg_conn.close()

    print()
    print("[DONE] Migration complete. You can now start the app with PostgreSQL.")
    print(f"       Make sure DATABASE_URL is set: export DATABASE_URL={DATABASE_URL}")

if __name__ == '__main__':
    main()
