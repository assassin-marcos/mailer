#!/usr/bin/env python3
"""
Migration script for Mailer App: CSV -> PostgreSQL
Usage:
    python migrate.py --fresh      # Fresh database with default admin
    python migrate.py --migrate    # Migrate existing CSV data to PostgreSQL
    python migrate.py --migrate --backup  # Migrate + rename CSVs to .bak
"""

import sys
import os
import csv
import json
import base64
import hashlib
import psycopg2
from psycopg2.extras import RealDictCursor
from werkzeug.security import generate_password_hash
from cryptography.fernet import Fernet

DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://postgres:postgres@localhost/mailer')
USER_CSV = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'users.csv')
LOG_CSV = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs', 'sent_log.csv')

# ---------- Encryption Utilities (same as app.py) ----------
def derive_key(password, salt):
    return base64.urlsafe_b64encode(
        hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000, dklen=32)
    )

def encrypt(value, key):
    from cryptography.fernet import Fernet
    return Fernet(key).encrypt(value.encode()).decode()

# ---------- Schema ----------
SCHEMA_STATEMENTS = [
    """CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user'
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
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)""",
    """CREATE TABLE IF NOT EXISTS inbox_cache (
    id SERIAL PRIMARY KEY,
    credential_id INTEGER NOT NULL,
    message_id TEXT UNIQUE NOT NULL,
    sender TEXT NOT NULL,
    subject TEXT NOT NULL,
    body_preview TEXT NOT NULL,
    received_at TEXT NOT NULL,
    fetched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (credential_id) REFERENCES credentials(id) ON DELETE CASCADE
)""",
]

def create_tables(cursor):
    for stmt in SCHEMA_STATEMENTS:
        cursor.execute(stmt)
    print("[OK] Tables created.")

def fresh(conn):
    """Create fresh database with default admin user."""
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    create_tables(cursor)
    conn.commit()

    cursor.execute("SELECT id FROM users WHERE username=%s", ('aditya',))
    existing = cursor.fetchone()
    if existing:
        print("[SKIP] Admin user 'aditya' already exists.")
        return

    salt = base64.urlsafe_b64encode(os.urandom(16)).decode()
    password_hash = generate_password_hash('Aditya@819409557')
    cursor.execute(
        "INSERT INTO users (username, password, salt, role) VALUES (%s,%s,%s,%s)",
        ('aditya', password_hash, salt, 'admin')
    )
    conn.commit()
    cursor.execute("SELECT id FROM users WHERE username=%s", ('aditya',))
    user_id = cursor.fetchone()['id']

    key = derive_key('decryption-key' + 'aditya', salt)
    default_creds = [
        ('itsecresearcher007@gmail.com', 'vqakudjcxhaeomgp'),
        ('researcher.whitehat@gmail.com', 'yjfwtcehvweadfui'),
        ('whitehatsaviour007@gmail.com', 'aifserzbcmrpislx'),
        ('secureit1337@gmail.com', 'ikwetyinnghqsgog')
    ]
    for email_addr, app_pass in default_creds:
        cursor.execute(
            "INSERT INTO credentials (user_id, encrypted_email, encrypted_app_password) VALUES (%s,%s,%s)",
            (user_id, encrypt(email_addr, key), encrypt(app_pass, key))
        )
    conn.commit()
    print(f"[OK] Admin user 'aditya' created with {len(default_creds)} credentials.")

def migrate(conn, backup=False):
    """Migrate existing CSV data to PostgreSQL."""
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    create_tables(cursor)
    conn.commit()

    # --- Migrate users.csv ---
    user_count = 0
    cred_count = 0
    if os.path.exists(USER_CSV):
        with open(USER_CSV, newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                username = row['username']
                cursor.execute("SELECT id FROM users WHERE username=%s", (username,))
                existing = cursor.fetchone()
                if existing:
                    print(f"  [SKIP] User '{username}' already exists in DB.")
                    continue

                cursor.execute(
                    "INSERT INTO users (username, password, salt, role) VALUES (%s,%s,%s,%s)",
                    (username, row['password'], row['salt'], row.get('role', 'user'))
                )
                conn.commit()
                cursor.execute("SELECT id FROM users WHERE username=%s", (username,))
                user_id = cursor.fetchone()['id']

                creds = json.loads(row.get('credentials', '[]'))
                for enc_email, enc_pass in creds:
                    cursor.execute(
                        "INSERT INTO credentials (user_id, encrypted_email, encrypted_app_password) VALUES (%s,%s,%s)",
                        (user_id, enc_email, enc_pass)
                    )
                    cred_count += 1
                conn.commit()
                user_count += 1
        print(f"[OK] Migrated {user_count} users with {cred_count} credentials from users.csv")
    else:
        print("[WARN] users.csv not found. Skipping user migration.")

    # --- Migrate sent_log.csv ---
    log_count = 0
    if os.path.exists(LOG_CSV):
        with open(LOG_CSV, 'r') as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) >= 5:
                    cursor.execute(
                        "INSERT INTO sent_logs (timestamp, username, encrypted_domain, encrypted_email, sender_email) VALUES (%s,%s,%s,%s,%s)",
                        (row[0], row[1], row[2], row[3], row[4])
                    )
                    log_count += 1
        conn.commit()
        print(f"[OK] Migrated {log_count} log entries from sent_log.csv")
    else:
        print("[WARN] logs/sent_log.csv not found. Skipping log migration.")

    # --- Backup CSV files ---
    if backup:
        if os.path.exists(USER_CSV):
            os.rename(USER_CSV, USER_CSV + '.bak')
            print(f"[OK] Renamed users.csv -> users.csv.bak")
        if os.path.exists(LOG_CSV):
            os.rename(LOG_CSV, LOG_CSV + '.bak')
            print(f"[OK] Renamed sent_log.csv -> sent_log.csv.bak")

def main():
    args = sys.argv[1:]

    if not args or '--help' in args:
        print(__doc__)
        return

    mode = args[0]
    backup = '--backup' in args

    conn = psycopg2.connect(DATABASE_URL)

    try:
        if mode == '--fresh':
            fresh(conn)
            print(f"\n[DONE] Fresh database setup complete.")
        elif mode == '--migrate':
            migrate(conn, backup=backup)
            print(f"\n[DONE] Migration complete.")
        else:
            print(f"Unknown mode: {mode}")
            print(__doc__)
    finally:
        conn.close()

if __name__ == '__main__':
    main()
